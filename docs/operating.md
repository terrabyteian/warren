# Operating the control plane

What an operator sets up and should know when running `warren
control-plane`. The configuration itself is described, with every setting,
in [examples/control-plane.yaml](examples/control-plane.yaml).

## TLS certificates

The control plane listens on one HTTPS port for two kinds of peer: browsers
and clients at the organization URL (link D: sign-in, enrollment,
certificates), and relays and connectors (link E). It has two certificates
for them.

- **Its own certificate**, issued by the deployment's private infrastructure
  CA for `publicUrl`'s host and every name in `dnsNames`, and renewed
  automatically. Relays and connectors always verify the control plane with
  it, against the deployment trust bundle.
- **The operator's certificate**, from `tls.certFile` and `tls.keyFile`: a
  PEM chain, leaf first, and its unencrypted PEM key (`PRIVATE KEY`,
  `EC PRIVATE KEY` or `RSA PRIVATE KEY`), from a public CA or the
  organization's own CA. It must name `publicUrl`'s host.

With `tls` set, the control plane chooses by the name the peer asks for
(TLS SNI): the names in `dnsNames` get its own certificate, and every other
name, `publicUrl`'s host included, gets the operator's. So `tls` needs at
least one name in `dnsNames` besides `publicUrl`'s host, resolving to the same
address; give relays and connectors that name when they join. Clients and
browsers keep using the organization URL.

```yaml
publicUrl: https://warren.example.com
dnsNames: [nodes.warren.example.com]
tls:
  certFile: /etc/warren/tls/tls.crt
  keyFile: /etc/warren/tls/tls.key
```

The control plane checks the files every 30 seconds, and on SIGHUP, and
presents a new certificate as soon as they change, so a certificate manager
can rotate them in place. If new files do not load (unreadable, no
certificate, or a key that does not match), it logs an error and keeps
presenting the last good certificate. At startup, files that do not load are
a configuration error.

Without `tls`, the organization URL presents the control plane's own
certificate. Warren clients that pin the trust bundle (from an MDM profile,
for example) work, but browsers do not trust it, so browser sign-in shows a
certificate error; the control plane logs a warning saying so at startup.

## Connection limits

The HTTPS listener bounds what any peer can hold before it authenticates.

| Limit | Value |
| --- | --- |
| Connections in total | 4096 |
| Connections from one source (an IPv4 address or an IPv6 /64) | 64 |
| Concurrent requests on one HTTP/2 connection | 32 |
| TLS handshake | 10 seconds |
| Request headers (HTTP/1.1) | 10 seconds |
| Request body | 30 seconds |
| A connection with no request in progress | closed after 60 seconds |

A connection beyond a limit is closed at once. Clients, relays and connectors
each need one connection, and an event stream counts as a request in
progress for as long as it is open. The per-source limit binds only when
many peers share one address, such as an office behind NAT: the 65th
concurrent connection from that address is refused.

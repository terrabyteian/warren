# Operating the control plane

What an operator sets up and should know when running `warren
control-plane`. The configuration itself is described, with every setting,
in [examples/control-plane.yaml](examples/control-plane.yaml).

## TLS certificates

The control plane listens on one HTTPS port for browsers and clients
(link D: sign-in, enrollment, then certificates and entitlements) and for
relays and connectors (link E). It has two certificates for them.

- **Its own certificate**, issued by the deployment's private infrastructure
  CA for `publicUrl`'s host and every name in `dnsNames`, and renewed
  automatically. Enrolled clients, relays and connectors always verify the
  control plane with it, against the deployment trust bundle.
- **The operator's certificate**, from `tls.certFile` and `tls.keyFile`: a
  PEM chain, leaf first, and its unencrypted PEM key (`PRIVATE KEY`,
  `EC PRIVATE KEY` or `RSA PRIVATE KEY`), from a public CA or the
  organization's own CA. It must name `publicUrl`'s host.

With `tls` set, the control plane chooses by the name the peer asks for
(TLS SNI): the names in `dnsNames` get its own certificate, and every other
name, `publicUrl`'s host included, gets the operator's. The operator's
certificate serves browser sign-in and enrollment only (discovery,
`/v1/auth/*` and `/v1/devices`); every other call made at `publicUrl`'s host
is refused with `421 misdirected_request`. So `tls` needs at least one name
in `dnsNames` besides `publicUrl`'s host, resolving to the same address from
everywhere clients and nodes run; the first such name is the internal name.

- Clients sign in and enroll at the organization URL. The enrollment answer
  gives them `api_base`, a URL under the internal name, and from then on they
  make every call there and verify the control plane against the trust
  bundle, so a certificate their system trusts (a misissued public one, or a
  TLS-inspection root) can never stand in for the control plane.
- Relays and connectors join and run at the internal name: the
  `control_plane` URL a new join token comes with.

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

**Turning `tls` on in a deployment that already has relays and
connectors:** nodes that joined at `publicUrl` cannot verify the operator's
certificate, so they lose bundles and revocation events until they are
moved. First add the internal name to `dnsNames` (a restart), point every
relay and connector at it, and only then set `tls`. With `tls` set, the
control plane warns at startup, naming every enabled relay and connector,
that any still using `publicUrl` must be moved. Enrolled clients pick up the
new `api_base` from `GET /v1/devices/current` when a call is refused with
`421`.

Without `tls`, the organization URL presents the control plane's own
certificate. Warren clients that pin the trust bundle (from an MDM profile,
for example) work, but browsers do not trust it, so browser sign-in shows a
certificate error; the control plane logs a warning saying so at startup.

## Connection limits

The HTTPS listener bounds what any peer can hold before it authenticates.

| Limit | Value |
| --- | --- |
| Connections in total | 4096 |
| Unauthenticated connections from one source (an IPv4 address or an IPv6 /64) | `connections.maxPerSource`, 64 by default |
| Concurrent requests on one HTTP/2 connection | 32 |
| TLS handshake (and a trusted proxy's PROXY header) | 10 seconds |
| Request headers (HTTP/1.1) | 10 seconds |
| Request body | 30 seconds; 16 KiB before the caller is known |
| A connection with no request in progress | closed after 60 seconds |

A connection beyond a limit is closed at once. An event stream counts as a
request in progress for as long as it is open.

The per-source limit counts a connection only until it authenticates: one
that presents a client certificate the control plane verifies (every relay
and connector, and clients that present their user+device certificate)
stops counting after the TLS handshake. It binds on connections that have
not, such as browsers signing in and clients calling with only their session
token, so it matters when many of those share an address: an office behind
NAT, or a load balancer that hides client addresses. Raise
`connections.maxPerSource` for a large office behind one address, or set it
to 0 to turn the limit off.

```yaml
connections:
  maxPerSource: 64           # 0: no limit
  trustedProxies: [10.0.0.0/8]
```

### Behind a load balancer

A TCP load balancer that does not keep client addresses makes every peer
look like the balancer, so the per-source limit, and the addresses in audit
records, would see only it. Either keep client addresses or have the
balancer send them:

- **PROXY protocol version 2.** List the balancer's addresses (or the range
  they come from) in `connections.trustedProxies`. Every connection from
  those addresses must then start with a PROXY protocol version 2 header,
  and the control plane uses the source it names; a `LOCAL` header (a
  health check) counts as the balancer itself. A trusted address that sends
  anything else is disconnected, and no other peer's connection is read for
  a header. The balancer must terminate nothing: TLS goes through to the
  control plane, since relays, connectors and enrolled clients authenticate
  with certificates.
- **Kubernetes.** Give the control plane's `LoadBalancer` Service
  `externalTrafficPolicy: Local`, so pods see client addresses, or enable
  PROXY protocol version 2 on the cloud load balancer (usually with an
  annotation on the Service) and list the node or load-balancer range in
  `trustedProxies`. With the default `externalTrafficPolicy: Cluster` and
  no PROXY protocol, every peer appears as a node address: set
  `maxPerSource` to 0 rather than let the limit refuse legitimate peers.

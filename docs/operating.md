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
in `dnsNames` besides `publicUrl`'s host that reaches the control plane from
everywhere clients and nodes run. The first such name in the list is the
internal name: it is the `api_base` enrolled clients are given, the
`control_plane` URL join tokens come with, and where `421` refusals send
callers. Every name in `dnsNames` gets the control plane's own certificate,
so peers in the control plane's own cluster can use a ClusterIP Service name
listed after the internal name (see
[Behind a load balancer](#behind-a-load-balancer)); listed first, it would
become the name every client is given, which clients outside the cluster
cannot resolve.

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
| A trusted proxy's PROXY header and the TLS handshake, together | 10 seconds |
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
  trustedProxies: [192.0.2.10, 192.0.2.11]   # the load balancer's own addresses
```

### Behind a load balancer

The control plane applies one rule: it reads a PROXY protocol version 2
header only from connections whose TCP source address is in
`connections.trustedProxies`, and it requires one from them. Every other
connection must start with TLS. A trusted address that sends anything but a
valid header is disconnected; an untrusted address whose connection starts
with a PROXY header is disconnected too, with a warning in the log naming
that address.

So the setting follows from the source address the control plane sees for
a client outside the deployment. Find it before configuring anything:
with PROXY protocol off and `trustedProxies` empty, the `source` recorded in
the audit log for a refused relay or connector is the address the control
plane sees; or turn PROXY protocol on at the balancer with `trustedProxies`
still empty, and the warning the control plane logs for each connection
names the address the balancer connects from.

- **It sees the client's real address.** The balancer keeps client
  addresses (on Kubernetes, for example, `externalTrafficPolicy: Local` with
  a balancer that preserves client IPs). PROXY protocol is not needed: leave
  it off at the balancer and leave `trustedProxies` empty.
- **It sees the balancer's own addresses.** The balancer connects from its
  own addresses, with client IP preservation off. Turn PROXY protocol
  version 2 on at the balancer and list exactly those addresses in
  `trustedProxies`. The control plane then uses the source each header
  names; a `LOCAL` header (a health check) counts as the balancer itself.
- **It sees some other address**, such as a node's, because something
  between the balancer and the control plane rewrites the source. Neither
  of the above holds: do not turn PROXY protocol on. Without it the
  per-source limit would see every peer as that address, so set
  `connections.maxPerSource` to 0.

Never turn PROXY protocol on at a balancer whose connections arrive from
client or node addresses, and never list node, pod or office ranges in
`trustedProxies`: a peer connecting from such an address without passing
through the balancer sends no header and is disconnected. The balancer must
terminate nothing: TLS goes through to the control plane, since relays,
connectors and enrolled clients authenticate with certificates.

On Kubernetes, relays and connectors in the control plane's own cluster
should not go through the load balancer at all; traffic for a load
balancer's address from inside the cluster may be sent straight to the pod
from a node or pod address. Give them a ClusterIP Service name that is also
in `dnsNames`, listed after the internal name, since the first name other
than `publicUrl`'s host is the one clients and nodes are given (for example
`dnsNames: [nodes.warren.example.com, warren.warren-system.svc.cluster.local]`),
and point them at it. Where the provider supports it, `ipMode: Proxy`,
requested through the provider's Service annotation, sends in-cluster
traffic through the balancer instead.

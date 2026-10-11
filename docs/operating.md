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

A TCP load balancer that does not keep client addresses makes every peer
look like the balancer, so the per-source limit, and the addresses in audit
records, would see only it. Either keep client addresses or have the
balancer send them:

- **PROXY protocol version 2.** List only the balancer's own addresses in
  `connections.trustedProxies`. Every connection from those addresses must
  then start with a PROXY protocol version 2 header, and the control plane
  uses the source it names; a `LOCAL` header (a health check) counts as the
  balancer itself. A trusted address that sends anything else is
  disconnected, and no other peer's connection is read for a header. So
  never list a range that peers also connect from directly, such as node,
  pod or office ranges: a relay, connector or client connecting from such
  an address without passing through the balancer sends no header and is
  disconnected. The balancer must terminate nothing: TLS goes through to the
  control plane, since relays, connectors and enrolled clients authenticate
  with certificates.
- **Kubernetes.** Give the control plane's `LoadBalancer` Service
  `externalTrafficPolicy: Local`, so pods see client addresses, or enable
  PROXY protocol version 2 on the cloud load balancer (usually with an
  annotation on the Service) and list only the load balancer's own
  addresses in `trustedProxies`. PROXY protocol needs connections to reach
  the pod from the balancer's own addresses, so use it with
  `externalTrafficPolicy: Local` or a load balancer that targets pod IPs
  directly: under the default `externalTrafficPolicy: Cluster`, kube-proxy
  rewrites each connection's source to a node address, which is not
  trusted, so the header is never read and every TLS handshake fails. With
  `externalTrafficPolicy: Cluster` and no PROXY protocol, every peer
  appears as a node address: set `maxPerSource` to 0 rather than let the
  limit refuse legitimate peers.
- **Relays and connectors in the same cluster.** kube-proxy sends in-cluster
  traffic for a `LoadBalancer` IP straight to the pod, bypassing the load
  balancer, so it carries no PROXY header; if it arrives from a trusted
  address it is disconnected. Give in-cluster relays and connectors a
  ClusterIP Service name that is also in `dnsNames`, after the internal
  name (for example
  `dnsNames: [nodes.warren.example.com, warren.warren-system.svc.cluster.local]`),
  so they reach the control plane directly under its own certificate. Or,
  where the cloud provider supports it, request `ipMode: Proxy` through the
  provider's annotation on the `LoadBalancer` Service; the cloud controller
  then reports it in the Service's status and kube-proxy sends in-cluster
  traffic through the load balancer too.

# warren wire protocol profile

Status: profile for M1, recorded at M0 and refined by the M1 data-path
implementation (the bound-UDP revision, capsule codepoints and formats, the
identity extension encoding, the outer-layer delivery rule in
[section 9](#9-mtu-budget), and the join exchange). It fixes the
requirements and invariants an implementation must meet. Tunable values are named parameters
(`UPPER_SNAKE_CASE`) collected in [section 14](#14-named-parameters); their
initial defaults are starting points that M1 benchmarks may change. Bounds
that are part of a guarantee in [design.md](design.md#4-guarantees) are marked
as fixed.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.

## 1. Scope

This document covers:

- the outer layer: QUIC and HTTP/3 from clients and connectors to relays, and
  how relays join them with CONNECT-UDP;
- the inner layer: the end-to-end, mutually authenticated QUIC session from
  client to connector carrying CONNECT-IP;
- the warren capsules for name binding, deny reasons, posture and certificate
  refresh;
- the HTTP/2 over TCP fallback;
- the MTU budget;
- the certificate profile;
- the control channels and the revocation push channel.

Out of scope until later milestones: clientless HTTP(S) proxying (M3), direct
peer-to-peer paths, and Windows and Linux client specifics.

Standards this profile builds on:

| Standard | Used for |
| --- | --- |
| RFC 9000, RFC 9001, RFC 9002 | QUIC version 1, its TLS mapping, loss recovery |
| RFC 9369 | QUIC version 2 (optional) |
| RFC 9221 | QUIC DATAGRAM frames |
| RFC 8899 | Datagram packetization layer path MTU discovery |
| RFC 9114 | HTTP/3 |
| RFC 9113 | HTTP/2 (fallback) |
| RFC 8441, RFC 9220 | Extended CONNECT over HTTP/2 and HTTP/3 |
| RFC 9297 | HTTP Datagrams and the Capsule Protocol |
| RFC 9298 | CONNECT-UDP |
| RFC 9484 | CONNECT-IP |
| draft-ietf-masque-connect-udp-listen | Bound UDP in CONNECT-UDP (connector attachment) |
| RFC 9209 | Proxy-Status header (failure reasons) |
| RFC 8446 | TLS 1.3 |
| RFC 5280 | X.509 certificates |
| RFC 8252, RFC 7636 | OAuth 2.0 for native apps; PKCE |

## 2. Connections at a glance

```
client ──(A) outer QUIC, mTLS, CONNECT-UDP──► relay ◄──(B) outer QUIC, mTLS, CONNECT-UDP bind── connector
   │                                                                                              │
   └────────────(C) inner QUIC, mTLS, CONNECT-IP, carried as datagrams over (A)+(B)───────────────┘

client ──(D) HTTPS──► control plane ◄──(E) HTTPS, mTLS, event stream── relay, connector
```

| Link | Initiator | Authenticates | Carries |
| --- | --- | --- | --- |
| A | client | client: user+device certificate; relay: infrastructure certificate | CONNECT-UDP toward a connector group |
| B | connector | connector and relay: infrastructure certificates | CONNECT-UDP in bind mode: datagrams from many clients |
| C | client | client: user+device certificate; connector: infrastructure certificate | CONNECT-IP: the client's IP packets |
| D | client | before enrollment: control plane via WebPKI or an MDM pin; after: both sides | enrollment, sign-in, certificates, posture, entitlements, notices |
| E | relay, connector | both sides: infrastructure certificates | policy bundles, revocation events, health, audit |

Every link is initiated outbound by the party on the left of the arrow. Relays
and the control plane are the only listeners.

## 3. Common TLS and QUIC profile

Applies to links A to E.

- TLS 1.3 only (RFC 8446). Implementations MUST use rustls with the aws-lc-rs
  provider and MUST NOT negotiate TLS 1.2 or earlier.
- Cipher suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
  TLS_CHACHA20_POLY1305_SHA256.
- Key exchange: the hybrid post-quantum group X25519MLKEM768 SHOULD be
  offered first; X25519 and secp256r1 are the fallbacks.
- Signature schemes: ecdsa_secp256r1_sha256 MUST be supported (the device key
  profile); ecdsa_secp384r1_sha384 and ed25519 MAY be used by infrastructure
  keys.
- Certificates are verified against the deployment trust bundle
  ([section 10](#10-certificate-profile)), not the system or WebPKI roots,
  except where link D explicitly allows WebPKI
  ([section 10.1](#101-trust-hierarchy)).
- 0-RTT MUST NOT be used on any link (replay risk on CONNECT requests and
  control calls). Session resumption MAY be used; a resumption ticket MUST NOT
  outlive the certificate that authenticated the original handshake, and the
  server MUST re-check revocation state on resumption.
- QUIC version 1 MUST be supported; version 2 MAY be negotiated with
  compatible version negotiation.
- Endpoints MUST run DPLPMTUD (RFC 8899, as profiled in RFC 9000 section 14.3)
  on every QUIC connection.
- The ALPN is `h3` for QUIC links and `h2` for the TCP fallback. The warren
  protocol version travels in requests ([section 13](#13-versioning-and-extensibility)).
- HTTP/3 is the subset MASQUE needs: SETTINGS, request streams with one
  HEADERS exchange followed by DATA frames, HTTP Datagrams and GOAWAY; no
  server push. Endpoints advertise `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`
  and `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, so field sections never refer to
  a dynamic table. Clients wait for the peer's SETTINGS before sending an
  extended CONNECT (RFC 9220).

## 4. Outer layer

### 4.1 Client to relay (link A)

- Transport: QUIC on UDP 443, HTTP/3. Both sides MUST send
  SETTINGS_H3_DATAGRAM=1 (RFC 9297) and SETTINGS_ENABLE_CONNECT_PROTOCOL=1
  (RFC 9220), and MUST advertise a non-zero `max_datagram_frame_size`
  (RFC 9221).
- Client authentication: the client presents its user+device certificate in
  the TLS handshake; the Secure Enclave key signs the CertificateVerify. TLS 1.3
  encrypts the client certificate, so the identity is not visible on the path.
  The relay MUST verify the chain to the deployment's client CA, the validity
  window, and its pushed revocation state (user, device, session, serial)
  before accepting any request.
- Request: an extended CONNECT with `:protocol` = `connect-udp` (RFC 9298),
  `Capsule-Protocol: ?1`, and a target that names a connector group:
  `/.well-known/masque/udp/{group}.connectors.warren.invalid/443/`. The
  `.invalid` suffix (RFC 6761) guarantees the target never resolves in DNS, so a
  request that reaches a generic proxy fails closed. `{group}` is the connector
  group identifier from the client's entitlement data.
- Response: 2xx once the relay has spliced the request to an attached connector
  replica ([section 4.3](#43-relay-splicing)); otherwise a 4xx or 5xx response
  with a `Proxy-Status` header (RFC 9209) whose error type the client maps to a
  human-readable reason (for example `destination_unavailable` when no replica
  of the group is attached).
- Payload: HTTP Datagrams with context ID 0 carry inner-session QUIC packets as
  UDP payloads. The client MUST NOT send any other context ID on this stream.

### 4.2 Connector attachment (link B)

- Same transport profile as link A. The connector authenticates with its
  infrastructure certificate; the relay MUST check that the connector and its
  group are enabled in its pushed state.
- Request: CONNECT-UDP in bind mode, as specified by the IETF MASQUE
  working group's bound-UDP extension (draft-ietf-masque-connect-udp-listen).
  warren pins one draft revision (`BIND_DRAFT_REVISION`, revision 16) until
  an RFC exists. The request targets `/.well-known/masque/udp/%2A/%2A/` with
  `Connect-UDP-Bind: ?1`; the relay answers `Connect-UDP-Bind: ?1` and a
  `Proxy-Public-Address` naming its virtual peer prefix.
  Bind mode lets one request stream carry datagrams from many peers; the relay
  assigns each peer its own compressed context ID and announces the peer's
  address with the extension's capsules. Context IDs on a bind stream stay
  within the MTU budget's bound ([section 9](#9-mtu-budget)), and the
  extension's uncompressed context, which carries the peer address in every
  datagram, MUST NOT be used.
- Contexts in this profile: only the relay registers contexts on a bind
  stream, one odd context ID per spliced client, with COMPRESSION_ASSIGN
  naming the client's virtual peer address; the connector answers
  COMPRESSION_ACK, and either side ends a context with COMPRESSION_CLOSE.
  Context IDs are never reused on a stream. The draft lets a proxy open
  compressed contexts only while the client keeps an uncompressed one; warren
  replaces that rule with the splice itself (the relay opens a context only
  for a client it splices to this replica), and `Warren-Protocol` on the
  request says this profile applies. A connector rejects any other
  registration with COMPRESSION_CLOSE, and MAY hold a few datagrams for a
  context whose COMPRESSION_ASSIGN it has not processed yet.
- Peers are virtual: each spliced client stream appears to the connector as a
  distinct peer address that the relay allocates from a private range
  (`RELAY_PEER_PREFIX`). The connector's inner QUIC endpoint uses these
  addresses only to tell sessions apart.
- Each connector replica keeps one attachment per relay in its relay set
  (default: every relay in the deployment) and re-attaches immediately when an
  attachment drops. An attachment is one outer connection carrying one or
  more bind streams.
- Rollover: so a bind stream never runs out of context IDs, a relay sends a
  `WARREN_NOTICE` capsule with reason `bind_rollover` on a stream each time
  it assigns that stream context ID `BIND_ROLLOVER` or above. The connector
  then opens a fresh bind stream on the same outer connection, alongside the
  old one, retrying with backoff until it is open. Until then the old stream
  keeps taking clients from its reserve of IDs above `BIND_ROLLOVER`. When
  the fresh stream attaches, the relay rolls every stream of that connector
  past `BIND_ROLLOVER` over: a rolled-over stream takes no new contexts, and
  the relay closes it once its last context ends; the connector's other
  streams carry on. Within a replica, the relay assigns new clients to its
  streams before `BIND_ROLLOVER` first, then by load.
- Draining: a connector that is shutting down sends a `WARREN_NOTICE` capsule
  with reason `draining` on each bind stream, over either carrier, and HTTP/3
  GOAWAY on an HTTP/3 outer connection; it keeps serving its existing peers.
  The relay MUST stop assigning new client streams to it, except re-dials
  naming it in `Warren-Connector` ([section 4.3](#43-relay-splicing)), and MAY
  keep existing ones until they close or `DRAIN_TIMEOUT` passes.
- If the semantics change incompatibly before the draft is final, warren keeps
  the same semantics behind warren-specific capsules. The semantics, not the
  codepoints, are the contract.

### 4.3 Relay splicing

When a client's CONNECT-UDP names group G, the relay:

1. selects a healthy replica of G attached to it (`REPLICA_SELECTION`, default
   least-loaded, counting the open contexts over all of the replica's bind
   streams) and pins the client stream to that replica for its lifetime.
   A request carrying `Warren-Connector: {node ID}` goes to one of that
   connector's bind streams, draining or not, whenever it has one attached
   to this relay; the relay never picks another replica for it then, and
   refuses it with 503 if none of those streams has a free context ID. Only
   when the connector has no bind stream here does the request get the
   `REPLICA_SELECTION` choice;
2. allocates a virtual peer address and announces it on the replica's bind
   stream;
3. forwards datagram payloads between the two streams byte for byte.

Invariants:

- A relay MUST NOT forward to any target other than a connector group of its
  own deployment that currently has an attached replica. There is no other
  egress: relays are never open proxies (G8).
- A relay MUST NOT originate, modify, reorder deliberately, or inspect inner
  datagrams beyond their length. It cannot decrypt them (G5).
- A relay MAY enforce per-client and per-connector rate and concurrency limits
  (`RELAY_LIMITS`).
- The relay MAY tell the connector the client's public source address, as it
  observed it, in a `WARREN_PEER_INFO` capsule on the bind stream. Policy uses
  this only for network conditions and labels it *relay-observed*.
- On a revocation event that covers the client's certificate, user, device or
  session, the relay closes the client's outer connection
  ([section 12](#12-revocation-push-channel)).
- A relay closes an outer connection when the certificate that authenticated it
  expires. Clients open a new outer connection with their renewed certificate
  before then and migrate the inner session onto it.
- The inner session lives on one connector replica, so a client re-dialling
  for a renewed certificate or after losing its outer path sends
  `Warren-Connector` with the node ID from the connector certificate its inner
  session verified. The header is a routing hint only: a relay never forwards
  anywhere it would not otherwise, and the inner session still authenticates
  the connector end to end.

## 5. Inner session (link C)

- Transport: QUIC over the CONNECT-UDP datagram path of links A and B, with
  HTTP/3. Settings as in [section 4.1](#41-client-to-relay-link-a).
- Mutual authentication:
  - The client presents its user+device certificate (Secure Enclave key).
  - The connector presents its infrastructure certificate. The client MUST
    verify the chain to the deployment's infrastructure CA and that the
    certificate names a connector in group G. A relay therefore cannot
    substitute itself or another connector.
  - The connector MUST verify the client certificate exactly as the relay does
    and MUST NOT rely on any relay check.
- Request: one extended CONNECT with `:protocol` = `connect-ip` (RFC 9484) and
  `Capsule-Protocol: ?1` to `/.well-known/masque/ip/*/*/`. The request is not
  scoped by target in the URI; scope comes from policy, per flow.
- Addresses: the client sends ADDRESS_REQUEST for its device tunnel addresses
  (one IPv4 /32 and one IPv6 /128, carried in its certificate). The connector
  MUST confirm exactly those addresses with ADDRESS_ASSIGN and MUST drop any
  packet whose source address is not assigned (RFC 9484).
- Routes: the connector sends ROUTE_ADVERTISEMENT for the ranges this client
  may use through it (CIDR apps and the synthetic ranges of name apps). Routes
  are hints for the client's routing table and never an authorization; every
  flow is admitted on its own ([section 7](#7-flow-admission-and-deny-signalling)).
- Payload: HTTP Datagrams with context ID 0 carry full IP packets
  (RFC 9484). No other context IDs are defined.
- Certificate refresh: a session never outlives the certificate that
  authenticated it. Before `notAfter` the client sends its renewed certificate
  in a `WARREN_CERT_REFRESH` capsule with a signature by the device key over a
  TLS exporter value of the inner session (RFC 8446 section 7.5; label
  `EXPORTER-warren-cert-refresh`, empty context, 32 bytes; ECDSA P-256 with
  SHA-256, DER), which binds the new certificate to this session and this
  key. The client also opens a new outer connection with the renewed
  certificate and migrates the inner session onto it (section 4.3). The connector MUST verify
  the new certificate exactly as at the handshake and MUST check that it names
  the same user and device and carries the same public key; it then extends the
  session. Otherwise it closes the session at `notAfter`.
- Migration: when the outer path changes (new network, new relay, fallback to
  or from HTTP/2) the inner session migrates with QUIC path validation; it is
  not re-established.

## 6. Names, addresses and routes

- The control plane gives each device stable tunnel addresses from
  `DEVICE_POOL_V4` and `DEVICE_POOL_V6`, unique within the deployment.
- Every client-facing name has exactly one owning app: the app whose exact
  host matches it, otherwise the app with the most specific matching wildcard
  ([policy.md](policy.md#3-apps)).
- For FQDN and wildcard apps the client answers DNS queries for entitled names
  with synthetic addresses from its local pools `SYNTHETIC_POOL_V4` and
  `SYNTHETIC_POOL_V6`. Synthetic addresses are meaningful only inside one
  client's sessions. The client knows only the user's own apps (those the user
  may reach or request) and binds each name to the most specific of them that
  matches it.
- Before releasing packets to a synthetic address, the client binds it on the
  inner session with a `WARREN_NAME_BIND` capsule {synthetic address, name,
  app}. The connector MUST check, against its verified bundle, that the named
  app is the name's owning app and that the app is served by its group. A bind
  that names any other app, such as a broader wildcard app for a name a more
  specific app owns, MUST be rejected with reason `name_not_in_app`; the
  rejection is an access decision with its own audit record (G13), and its
  reason never names the owning app. The connector then answers
  `WARREN_NAME_BOUND` {synthetic address, result, reason}. Binding happens when
  the name resolves, so it usually completes before the application's first
  packet; until it does, the client holds that destination's packets
  (`FIRST_PACKET_HOLD`, bounded by `FIRST_PACKET_QUEUE`). When a bind fails the
  client fails those packets fast and shows the reason (G12).
- The connector resolves the name's target (the name itself unless the app
  sets a separate target, [policy.md](policy.md#3-apps)) with its own resolver
  when a flow starts, MUST check that every address used is inside its group's
  destination scope,
  and translates the synthetic destination to the resolved one. A flow keeps
  its resolved address for its lifetime; new flows resolve afresh within the
  record's TTL.
- CIDR and IP apps use real addresses end to end; the connector translates only
  the source.
- macOS split DNS claims exactly the internal suffixes in the user's
  entitlement data, never warren's reserved names
  ([policy.md](policy.md#3-apps)). The client answers the browser
  DNS-over-HTTPS canary domain so that browsers which honor it fall back to
  system DNS, and it reports bypass it detects for internal names to the user
  (G12).

## 7. Flow admission and deny signalling

- A flow is identified by its protocol and source and destination address and
  port (ICMP: echo identifier). TCP flows start with a SYN; UDP and ICMP flows
  start with their first packet and end after `FLOW_IDLE_TIMEOUT`.
- On the first packet of a flow the connector evaluates policy
  ([policy.md](policy.md)) with the client's identity, device, latest verified
  posture statement, and the app and destination. It caches the decision for
  the flow and re-evaluates live flows whenever policy, entities, posture,
  grants or revocations change. A flow that is no longer allowed is torn down
  (TCP reset toward both ends, UDP and ICMP state removed).
- Invariants checked before policy, which no rule can override: valid
  certificate, approved device, not revoked, destination inside the app's
  declared destinations and the connector group's scope, and client-initiated
  direction unless the app opts in to server-initiated flows.
- Every decision emits an audit record ([design.md](design.md#77-audit)).
- On a deny the connector MUST:
  1. answer the first packet so the application fails fast: TCP reset for TCP,
     ICMP or ICMPv6 destination unreachable, administratively prohibited, for
     everything else; and
  2. send a `WARREN_FLOW_DENIED` capsule {flow, decision ID, reason code,
     human-readable message, remediation} on the CONNECT-IP stream.
- Reason codes include `no_rule`, `request_access`, `posture_failed`,
  `reauth_required`, `mfa_required`, `outside_schedule`, `network_not_allowed`,
  `device_not_approved`, `revoked`, `grant_expired`, `out_of_scope`,
  `name_not_in_app`, and `server_initiated_blocked`. Clients map unknown codes
  to the message text. The client rate-limits notifications per app so a
  retrying application produces one clear message, not a stream of them.
- Before closing a session for revocation, draining or policy reasons, the
  connector SHOULD send a `WARREN_NOTICE` capsule with the reason.

### 7.1 warren capsule formats

warren's capsules use provisional codepoints from the unregistered space
(`WARREN_CAPSULE_*`, [section 14](#14-named-parameters)). Fields use the
notation of RFC 9000: `(i)` is a variable-length integer, an address is an
IP Version byte (4 or 6) followed by 4 or 16 bytes, and text is a length
`(i)` followed by that many bytes of UTF-8. Receivers ignore bytes after the
fields they know, so later versions can append fields.

| Capsule | Fields |
| --- | --- |
| `WARREN_NAME_BIND` | synthetic address, name (text), app (text) |
| `WARREN_NAME_BOUND` | synthetic address, result (8: 0 bound, 1 rejected), reason code (text), message (text) |
| `WARREN_FLOW_DENIED` | IP protocol (8), source address, source port (16), destination address, destination port (16), decision ID (text), reason code (text), message (text), remediation (text) |
| `WARREN_POSTURE` | the signed posture statement, opaque |
| `WARREN_CERT_REFRESH` | certificate count (i), each certificate as length (i) and DER, leaf first; signature as length (i) and DER |
| `WARREN_NOTICE` | reason code (text), message (text) |
| `WARREN_PEER_INFO` | context ID (i), the client's address and port (16) as the relay observed them |

For ICMP flows both ports carry the echo identifier.

## 8. HTTP/2 fallback

- When UDP 443 is blocked or degraded, the outer layer runs over TLS 1.3 on
  TCP 443 with HTTP/2 (RFC 9113): extended CONNECT (RFC 8441) with
  `:protocol` = `connect-udp`, SETTINGS_ENABLE_CONNECT_PROTOCOL=1, and every
  datagram carried in a DATAGRAM capsule (RFC 9297, capsule type 0x00) on the
  request stream. Authentication and targets are identical to links A and B.
- Connectors use the same fallback for link B where their egress blocks UDP.
- The inner session is unchanged: same QUIC, same mutual authentication, same
  CONNECT-IP. The fallback changes only the outer hop, so it cannot weaken
  end-to-end confidentiality or authentication (G5).
- Selection: the client starts QUIC first and starts HTTP/2 in parallel if no
  QUIC handshake completes within `FALLBACK_DELAY`, using whichever completes
  first and preferring QUIC. It remembers the outcome per network for
  `FALLBACK_MEMORY` and re-probes QUIC every `QUIC_REPROBE_INTERVAL` while on
  the fallback, migrating the inner session back when QUIC works.
- Relays splice between carriers transparently: a client on HTTP/2 can reach a
  connector attached over QUIC and vice versa.
- A TLS-intercepting middlebox fails certificate verification (the client pins
  the deployment trust bundle); the client reports that the network is
  intercepting TLS rather than retrying silently.

## 9. MTU budget

Terms:

- *Outer PMTU*: the path MTU between an endpoint and the relay, discovered by
  DPLPMTUD on the outer QUIC connection.
- *Per-layer overhead*: QUIC short header (1 byte + destination connection ID +
  packet number), AEAD tag (16), DATAGRAM frame type (1; a full-size datagram
  is the packet's last frame and carries no length), Quarter Stream ID
  (varint), Context ID (varint).
  - Outer layer (links A and B): connection IDs of at most 4 bytes, 2-byte
    packet numbers and 2-byte quarter stream IDs. The context ID is 1 byte on
    link A (always 0) and at most 2 bytes on link B (one per virtual peer), so
    the outer overhead is at most 27 bytes on link A and 28 bytes on link B.
  - Inner layer (link C): with 8-byte connection IDs, 2-byte packet numbers,
    2-byte quarter stream IDs and context ID 0, about 31 bytes.
- *Tunnel MTU*: the largest IP packet the client's tunnel interface accepts.

Budget for one direction, both hops on the same PMTU, using the larger link B
overhead:

| Outer path | Outer PMTU | IP + UDP | Outer QUIC | Inner QUIC | Largest inner IP packet |
| --- | --- | --- | --- | --- | --- |
| IPv4 Ethernet | 1500 | 28 | 28 | ~31 | ~1413 |
| IPv6 Ethernet | 1500 | 48 | 28 | ~31 | ~1393 |
| IPv6 minimum | 1280 | 48 | 28 | ~31 | ~1173: below the floor |

Requirements:

- **The floor (fixed).** The tunnel MTU is never below 1280 bytes, the IPv6
  minimum that RFC 9484 requires CONNECT-IP to carry.
- **Inner QUIC must run on any IPv6-capable path.** On a 1280-byte outer path
  the outer layer carries 1232 bytes of UDP payload, less at most 28 bytes of
  outer overhead: at least 1204 bytes, 4 bytes above the inner session's
  1200-byte minimum on link B and 5 bytes above it on link A. Implementations
  MUST keep outer overhead within that budget: on links A and B, connection
  IDs of at most 4 bytes in both directions and quarter stream IDs below
  16,384 (an endpoint opens a new outer connection rather than exceed them);
  on link B, compressed context IDs below 16,384 (2-byte varints). A relay
  that has no free context ID on a replica's bind stream refuses new splices
  to that replica as it does at `RELAY_LIMITS`.
- **No silent drops of conforming packets.** When an IP packet that fits the
  tunnel MTU does not fit an inner DATAGRAM frame on the current path, the
  sender MUST carry it in a DATAGRAM capsule on the CONNECT-IP stream instead
  of dropping it. This keeps the 1280 floor on constrained paths at the cost of
  reliable delivery for those packets, and the client reports the constrained
  path in diagnostics.
- **Inner QUIC packets always cross the outer hops.** QUIC implementations
  size DATAGRAM frames conservatively: quinn, which warren uses, reserves a
  4-byte packet number and a frame length, 10 bytes beyond the minimal
  encoding counted above, so a 1200-byte inner packet does not fit an outer
  DATAGRAM frame on a 1280-byte path even though the wire format allows it.
  On links A and B, a sender that cannot fit an inner QUIC packet of at most
  1200 bytes (the QUIC minimum) into a DATAGRAM frame MUST carry it in a
  DATAGRAM capsule on the CONNECT-UDP stream instead; relays apply the same
  rule toward the next hop. Larger inner packets that do not fit a frame are
  dropped, as a path that is too small drops them, which is what the inner
  session's DPLPMTUD expects. Together with the rule above, every packet up to
  the tunnel MTU is delivered on any path QUIC itself can run on.
- **Refusing below the floor.** A client MUST refuse to set up a tunnel
  whose MTU would be below 1280 bytes, and MUST refuse a relay or connector
  that does not support HTTP Datagrams, rather than run a tunnel that cannot
  meet the floor.
- **Tunnel MTU choice.** The client sets the tunnel MTU at session setup to
  `TUNNEL_MTU` (default 1280, always deliverable). It MAY use a larger value,
  up to `TUNNEL_MTU_MAX`, only when the inner session's own DPLPMTUD, which
  measures both hops end to end, has proven it.
- **Oversized packets.** A packet larger than the tunnel MTU is answered at its
  ingress (the client for outbound packets, the connector for return traffic)
  with ICMP fragmentation-needed or ICMPv6 packet-too-big, never dropped
  silently. Both ingress points clamp TCP MSS to fit the tunnel MTU.
- Relays never fragment or reassemble.

## 10. Certificate profile

### 10.1 Trust hierarchy

- Each deployment has a root CA and two issuing CAs under it: the **client CA**
  (user+device certificates) and the **infrastructure CA** (control plane,
  relays, connectors). A certificate from one issuing CA is never accepted
  where the other is required.
- The deployment trust bundle (the root and both issuing CA certificates) is
  given to clients at enrollment over HTTPS to the organization URL, verified
  with WebPKI or with a fingerprint preset by MDM. After enrollment clients
  verify relays, connectors and the control plane's client API against the
  bundle only, and require the certificate to name the role they expect
  (`warren://{td}/control-plane/{id}` for the control plane), so no relay or
  connector certificate can stand in for the control plane. When the operator
  gives the organization URL's host a certificate of its own (WebPKI or the
  operator's CA), the control plane presents that one there for browser
  sign-in and enrollment only: discovery, `/v1/auth/*` and `/v1/devices`,
  which browsers and not-yet-enrolled clients verify against the system
  trust store (or the CA their MDM profile installs). Every other call,
  from enrolled clients and from relays and connectors, goes to an internal
  name, where the control plane always presents its infrastructure
  certificate; the enrollment answer gives clients that `api_base`, and the
  control plane refuses those calls at the organization URL's host with
  `421 misdirected_request`. A certificate the system trusts can therefore
  never stand in for the control plane to an enrolled client. The control
  plane never issues a node a certificate for its own or the IdP's host
  names.
- The trust domain `{td}` is the deployment's identifier, used in URI SANs.

### 10.2 User+device certificate

| Field | Requirement |
| --- | --- |
| Version | X.509 v3 (RFC 5280) |
| Issuer | the deployment client CA |
| Serial | at least 64 bits from a CSPRNG |
| Subject | empty; identity is in the SAN |
| Subject public key | ECDSA P-256, generated in the device's hardware key store (Secure Enclave on macOS) and never exported |
| Validity | `notAfter` at most `CLIENT_CERT_LIFETIME` after issuance (fixed bound: 4 hours); `notBefore` at most `CLOCK_SKEW_ALLOWANCE` before issuance |
| Subject Alternative Name | critical; exactly one URI `warren://{td}/user/{user-id}` and one URI `warren://{td}/device/{device-id}` |
| Key Usage | critical; digitalSignature |
| Extended Key Usage | id-kp-clientAuth only |
| Basic Constraints | CA:FALSE |
| Key identifiers | Authority and Subject Key Identifier present |
| warren identity extension | non-critical, OID `WARREN_OID_ARC.1`: session ID, IdP authentication time, MFA performed (from the IdP's `amr`/`acr`), device enrollment trust class, device tunnel addresses (encoding below) |
| Revocation pointers | none (no CRL distribution points, no OCSP); revocation is pushed |

- The identity extension's value is DER:

  ```asn1
  WarrenIdentity ::= SEQUENCE {
    version          INTEGER (1),
    sessionId        UTF8String,     -- 1 to 128 bytes
    authTime         INTEGER,        -- IdP authentication, Unix seconds
    mfa              BOOLEAN,
    trustClass       ENUMERATED { deviceReported(1), serverVerified(2),
                                  hardwareAttested(3) },
    tunnelAddresses  SEQUENCE OF OCTET STRING  -- one of 4 and one of 16 octets
  }
  ```

  Verifiers ignore fields appended after `tunnelAddresses`.
- Group membership is deliberately absent: it changes faster than certificates
  and reaches connectors in signed policy bundles instead.
- `notAfter` never passes the end of the sign-in session the certificate
  belongs to (`SESSION_MAX_LIFETIME`).
- Issuance needs a signed PKCS#10 request from the device key, a live session,
  an enabled user, an approved and unrevoked device, and passing baseline
  posture. Renewal starts at half-life (`CLIENT_CERT_RENEW_AT`, fixed at 0.5),
  counted from issuance rather than from `notBefore`, which is backdated by
  `CLOCK_SKEW_ALLOWANCE`, over the existing mTLS channel.
- No certificate is issued valid past its issuing CA's own `notAfter`; the
  control plane warns 90 days before a CA expires.

### 10.3 Infrastructure certificates

- Issued by the infrastructure CA to the control plane, relays and connectors.
  Keys are generated on the node and never leave it (`INFRA_KEY_ALG`: ECDSA
  P-256; Ed25519 may be added later).
- SAN: DNS names where the node listens (control plane, relays) and a URI
  `warren://{td}/{role}/{id}`; connectors use
  `warren://{td}/connector/{group}/{id}`.
- Extended Key Usage: serverAuth for listeners, clientAuth for outbound
  connections; connectors need both (they are the TLS server of link C and the
  TLS client of links B and E).
- Lifetime `INFRA_CERT_LIFETIME`, renewed at half-life over link E.
- Subject: empty, as for client certificates; the SAN carries the identity.
  Relays get both serverAuth and clientAuth as well: they listen on links A
  and B and dial out on link E.
- Bootstrap: a single-use join token, valid for `JOIN_TOKEN_LIFETIME` and scoped
  to one role (and one connector group), is exchanged with a signed request for
  the first certificate, as the join exchange below describes. An
  administrator mints it for one node, naming the node and, for a relay, the
  DNS names it listens on (`warren admin join-token create --role relay
  --name relay-1 --dns-name relay1.example.com`); those are fixed in the
  token's record and are what the certificate names. The control plane
  stores only a hash of the token's secret.

#### Join exchange

- The token is `warren-join-v1.` followed by the base64url (no padding)
  encoding of a JSON object: `td` (trust domain), `cp` (the join endpoint,
  `host:port`), `role` (`relay` or `connector`), `group` (connectors only),
  `root` (lowercase hex SHA-256 of the root CA certificate, DER), `id`,
  `secret` (base64url, at least 16 bytes) and `exp` (Unix seconds).
- The node generates its key, builds a PKCS#10 request (RFC 2986) with an
  empty subject signed by that key (ECDSA P-256 with SHA-256), and sends
  `POST /v1/join` over HTTPS (TLS 1.3, HTTP/2) to `cp` with the JSON body
  `{"token": ..., "csr": <base64 DER>}`. Without a trust bundle yet, it
  verifies the endpoint's certificate against the root the token pins: the
  control plane presents the root in its chain, and its certificate must
  name the control-plane role in the token's trust domain.
- The control plane checks the token (for its trust domain and root, known by
  its secret's hash, unused, unexpired, ID, role and group as minted) and the
  request's signature, spends the token, assigns the node ID and the names
  the token was minted for, and answers `{"chain": [<base64 DER>, ...], "trustBundle":
  {"root": ..., "clientCas": [...], "infraCas": [...]}}`. Refusals are 4xx
  with an RFC 9457 problem body.
- The node accepts the result only if the bundle's root is the pinned one,
  the certificate chains to it through an infrastructure CA, names the role
  and group the token was for, and carries the node's own key.

### 10.4 Encodings

- **Object identifiers.** `WARREN_OID_ARC` is a UUID-based arc (ITU-T
  X.667, section 14), so it needs no registration. The identity extension is
  `WARREN_OID_ARC.1`, encoded as in [section 10.2](#102-userdevice-certificate).
  Until a hardware attestation path exists the enrollment trust class is
  device-reported (1).
- **`authTime`** in the identity extension comes only from the ID token's
  `auth_time` claim, never from when the token was issued (a silent single
  sign-on issues a fresh token without authenticating anyone). When the IdP
  leaves `auth_time` out, `authTime` is 0: freshness is unknown, and every
  `auth.maxAge` condition fails, asking the user to sign in again. For a
  built-in account it is the time the control plane verified the
  authenticator or recovery code, and MFA is always set.
- **Key identifiers** (Subject and Authority Key Identifier) are the leftmost
  160 bits of the SHA-256 digest of the subject public key (RFC 7093,
  method 1).
- **Times** are UTCTime through 2049 and GeneralizedTime from 2050, in UTC
  with seconds (RFC 5280 section 4.1.2.5).
- **Signatures** on certificates and PKCS#10 requests are ECDSA P-256 with
  SHA-256, with no algorithm parameters (RFC 5758).

## 11. Control channels

### 11.1 Client to control plane (link D)

HTTPS (HTTP/2 or HTTP/3), JSON, under a versioned path. Requirements:

1. **Discovery.** `GET https://{org}/.well-known/warren` returns the
   deployment identifier, trust bundle, API base and sign-in endpoint. The
   discovery API base is for sign-in and enrollment only; once enrolled, the
   client makes every later call at the `api_base` the enrollment answer
   gives ([section 10.1](#101-trust-hierarchy)).
2. **Sign-in.** OAuth 2.0 for native apps (RFC 8252) in the system browser
   with authorization code and PKCE (RFC 7636). The user signs in with a
   built-in account on the control plane's own pages (a password, then an
   authenticator or recovery code), or through the IdP, toward which the
   control plane is the OIDC relying party. Either way the client receives a
   one-time code bound to its PKCE verifier and exchanges it, together with a
   request signed by the device key, for a session bound to that key; the
   client cannot tell the two apart and needs nothing more.
3. **Enrollment.** The client registers the device public key, platform
   attributes, and a hardware attestation where the platform offers one. The
   device is pending until approved.
4. **Certificates.** Issuance and renewal as in
   [section 10.2](#102-userdevice-certificate).
5. **Posture.** The client reports signals at least every
   `POSTURE_RECHECK_INTERVAL` (fixed bound: 5 minutes) and on change. The
   control plane returns a posture statement: a compact object signed by the
   posture-signing key naming the device, each signal with its trust class and
   observation time, and an expiry at most `POSTURE_STATEMENT_LIFETIME`
   (fixed bound: 5 minutes) after the oldest observation it carries, on the
   control plane's clock. The client forwards each new statement to its
   connectors in a `WARREN_POSTURE` capsule and reports early enough that a
   fresh statement arrives before the current one expires. Connectors accept a
   statement until its expiry plus at most `CLOCK_SKEW_ALLOWANCE` (fixed
   bound: 2 minutes) on their own
   clock and then drop it, so stale posture fails closed at the connector even
   if the client stops reporting (G11).
6. **Entitlements.** Apps the user may reach or request, with names, ranges,
   ports, connector groups and the relay list. It never names apps the user
   may neither reach nor request. Nothing in it is secret.
7. **Notices.** A server-to-client stream of user-facing events (re-auth
   needed, device revoked, posture failing, entitlements changed). It drives the
   UI only; clients are never part of enforcement.

The endpoints, all JSON unless noted, are described in
[api/openapi.yaml](api/openapi.yaml):

| Step | Request |
| --- | --- |
| Discovery | `GET /.well-known/warren`: trust domain, API base, sign-in endpoints, trust bundle (root, client CA, infrastructure CA, PEM), protocol versions. Its `api_base` is for sign-in and enrollment only; later calls use the enrollment answer's `api_base`. |
| Sign-in | `GET /v1/auth/authorize` with `redirect_uri`, `code_challenge`, `code_challenge_method=S256` and `state`, and `prompt=login` when the user asked to sign in again (after a `reauth_required` or `mfa_required` refusal), in the system browser. The redirect URI is an `http` loopback URI on `127.0.0.1` or `[::1]` with any port (RFC 8252 section 7.3), or one the deployment configures exactly; anything else gets an error page, never a redirect. The control plane runs its own authorization-code flow with PKCE and a nonce toward the IdP, sending `max_age` set to the shortest `auth.maxAge` in policy when policy has one, and `prompt=login` when the client sent it, so the IdP authenticates the user afresh rather than reuse its own session; either one obliges the IdP to report `auth_time` (OpenID Connect Core section 3.1.2.1), and an ID token without it leaves the sign-in time unknown ([section 10.4](#104-encodings)). It then redirects to the client with a one-time `code` (valid 2 minutes) and the client's `state`, or with `error` and a human-readable `error_description`. When built-in accounts are on and either no IdP is configured or built-in accounts exist, `authorize` answers with the sign-in page instead (below), which offers the IdP as a button (`GET /v1/auth/idp`) when there is one. With the Google preset, `prompt=login` becomes `prompt=select_account` and no `max_age` is sent, since Google supports neither; its ID tokens carry no `auth_time`, so the sign-in time is unknown. |
| Built-in account | The sign-in page sets a `__Host-warren-signin` cookie (Secure, HttpOnly, SameSite=Strict) and carries the sign-in's `flow` token; each form post must present both, come from the control plane's origin, and moves the sign-in on exactly once. `POST /v1/auth/password` checks the username and password (PBKDF2-HMAC-SHA256); the same page, with the same status, answers an unknown username, a locked account and a wrong password ([threat-model.md T18](threat-model.md#t18-attacks-on-built-in-accounts)). It leads to `POST /v1/auth/code` with a six-digit TOTP code (RFC 6238: SHA-1, 30 s, one step either side, each step accepted once per account) or a single-use recovery code. An account without an authenticator is shown a new secret as a QR code and key instead, and its first code enrolls it; the ten recovery codes are then shown once and `POST /v1/auth/continue` finishes. Finishing redirects (303) to the client exactly as an IdP sign-in does, with `auth_time` the time the code was verified and `mfa` true. `ACCOUNT_LOCKOUT` failed passwords or codes in a row lock the account; `SOURCE_FAILURE_LIMIT` applies per source address (per /64 for IPv6). Pages carry a CSP of `default-src 'none'` with the stylesheet allowed by hash, `form-action` limited to the control plane and the client's redirect URI, and no framing. |
| Setup link | `GET /v1/auth/setup?token=...` and `POST /v1/auth/setup`: an admin's one-time link, valid `SETUP_LINK_LIFETIME`, sets a built-in account's password (at least 12 characters, not the username). |
| Session | `POST /v1/auth/token` with a compact JWS (ES256, `typ` `warren-session-request+jws`, the device's public key as the header's `jwk`) whose payload is `{code, code_verifier, redirect_uri, iat}`. The control plane checks the signature, the PKCE verifier, the redirect URI and that `iat` is within `CLOCK_SKEW_ALLOWANCE`, and returns a session bound to that key with a bearer token. |
| Enrollment | `POST /v1/devices` with a PKCS#10 request signed by the session's device key, platform facts, and where the key lives. The answer, and `GET /v1/devices/current`, carry `api_base`: where every later call goes, verified against the trust bundle with the control-plane URI SAN ([section 10.1](#101-trust-hierarchy)). |
| Certificates | `POST {api_base}/certificates` with a PKCS#10 request signed by the session's device key. Renewal is the same call. |
| Entitlements | `GET {api_base}/entitlements`. |

After sign-in the client authenticates link D calls with its session token,
and every call that yields a credential also proves possession of the device
key with a request signed by it, so a token alone yields nothing beyond the
user's entitlement data. Errors are RFC 9457 problem details with a stable
`reason` code and a `detail` written for people, so the client can always say
why something failed (G12). Posture reports and notices arrive with
posture evaluation in M2.

### 11.2 Relays and connectors to control plane (link E)

- mTLS with infrastructure certificates. When the organization URL's host has
  an operator-supplied certificate ([section 10.1](#101-trust-hierarchy)),
  nodes reach the control plane under one of its other names, where it still
  presents its infrastructure certificate, and verify it against the bundle.
- **Policy bundles.** (Until the control plane publishes them, M1 relays and
  connectors load the same content, unsigned, from a static file, reloaded
  on `SIGHUP` and subject to the same version rule.) The control plane
  publishes a signed, versioned bundle:
  the compiled Cedar policy set and schema, the entity snapshot (users, groups,
  devices, apps, connector scopes, active JIT grants with expiries), the current
  revocation state, and the posture-signing and session-assertion-signing
  public keys. Bundle versions only increase; a node MUST reject a bundle older
  than its current one, MUST verify the signature before use, and MUST persist
  the last verified bundle so it can restart during an outage (G10).
- **Event stream:** [section 12](#12-revocation-push-channel).
- **Health and audit.** Nodes report health and metrics and export audit
  records to the control plane and any configured sinks.

Encodings and endpoints ([api/openapi.yaml](api/openapi.yaml)):

- **Joining.** The join exchange of [section 10.3](#103-infrastructure-certificates).
  A joined node then fetches the policy-signing public key (a JWK) with
  `GET /v1/node/policy-key` on this link, where it has verified the control
  plane against the trust bundle its join pinned, and keeps it. Renewal at
  half-life is `POST /v1/node/certificate` with a request signed by the same
  key.
- **Bundles.** `GET /v1/node/bundle` returns the latest bundle as a JWS in
  compact serialization (RFC 7515), ES256, `typ` `warren-bundle+jws`, `kid`
  the RFC 7638 thumbprint of the policy-signing key. The payload is JSON with
  `format` `warren.bundle.v1`, `trust_domain`, `version`, `issued_at`,
  `view`, the compiled `policy` (Cedar schema and policies, a `sha256:`
  digest, and per rule the conditions the explainer evaluates one by one),
  the Cedar `entities`, `apps`, `connector_groups`, approved `devices` with
  their users and tunnel addresses, enabled `nodes`, `revocations`, and the
  posture and session-assertion public `keys`. Each Cedar policy carries its
  rule path in `@id`; enforcement points use it as the policy ID. The policy
  also maps each `context.time` field schedules use to its time zone
  (`timezones`). Nodes reject a bundle for another trust domain or view. The
  control plane reads the state a bundle carries in the same transaction
  that commits the bundle's `bundle_updated` event, so a bundle never lacks a
  revocation whose event came before it.
- **Views.** Each version is published twice: the connector view with
  everything above, and the relay view with only what admission needs
  (nodes, connector groups and revocations), so relays never hold the
  policy, users, devices or apps.
- **Audit.** `POST /v1/node/audit` takes OCSF-shaped records as JSON lines.
  The control plane stamps `metadata.log_provider` with the reporting node's
  identity, `metadata.log_name` with its role and `metadata.logged_time`, so
  a node can pass its records off neither as another node's nor as the
  control plane's, and writes them to its audit sinks.
- **Node revocation.** Revoking a relay or connector also revokes every
  certificate issued to it, so they stay in the revocation state by serial
  until they expire, and a revoked node stays revoked even if a new node
  later joins under its name.

## 12. Revocation push channel

Requirements, which together implement G9 and G10:

1. **One long-lived stream per node.** Each relay and connector holds an event
   stream to the control plane on link E (a long-lived HTTP response). On loss
   it reconnects with jittered backoff to any control-plane replica.
2. **Ordered and resumable.** Events carry a deployment-wide, strictly
   increasing sequence number. Nodes apply events in order and resume from the
   last applied number; when the gap is no longer retained, the control plane
   sends a full revocation snapshot and the current bundle version.
3. **Liveness.** The control plane sends a heartbeat at least every
   `EVENT_HEARTBEAT_INTERVAL`. A node that has heard nothing for
   `EVENT_STALE_AFTER` treats the stream as broken and reconnects at once.
4. **Event types.** User disabled; device disabled or revoked; session revoked;
   certificate revoked (serial, kept until its `notAfter`); JIT grant revoked or
   expired; posture failed (device, check); infrastructure node revoked;
   re-authentication required; policy bundle updated (version and digest).
5. **Only the bundle grants access.** Events that reduce access take effect
   directly. Anything that adds access (re-enabling a user, a new grant, a
   looser rule) arrives only in a signed bundle, which the
   "policy bundle updated" event tells nodes to fetch.
6. **Apply budget.** A node MUST finish applying an access-reducing event,
   closing every affected session and flow, within `REVOCATION_APPLY_BUDGET`.
   The end-to-end bound from commit at the control plane to the last cut
   connection is `REVOCATION_DEADLINE` (fixed: 10 seconds).
7. **Measured.** Each event carries its commit time. Nodes acknowledge each
   event with the time it took effect and the number of connections it cut; the
   control plane exports the commit-to-cut latency as a metric, and an
   integration test asserts the deadline (the control plane's side from M1,
   end to end through real connectors in M2).
8. **Unknown events** are logged and trigger a bundle refresh; they are never
   silently ignored.
9. **Partition.** While a node's stream is broken it keeps enforcing its last
   verified bundle and revocation state (G10).
10. **Who acts.** Relays act on events about identities (user, device, session,
    certificate) and infrastructure nodes, closing outer connections. Connectors
    act on all events, closing inner sessions and tearing down flows, and send
    `WARREN_NOTICE` to the client first where they can.
11. **Defense in depth.** JIT grant expiry and certificate expiry are enforced
    on the node's own clock as well, so they hold even if the event never
    arrives.

Wire format:

- The stream is `GET /v1/node/events`, optionally with `?after=<seq>`, and
  its body is `application/x-ndjson`: one JSON object per line, each with a
  `type`.
- Events: `{"type", "seq", "committed_at_ms", ...}` with these types and
  fields: `user_disabled` (`user_id`), `device_disabled` (`device_id`,
  `revoked`), `session_revoked` (`session_id`), `certificate_revoked`
  (`serial`, `not_after`), `node_revoked` (`node_id`), `reauth_required`
  (`user_id`) and `bundle_updated` (`version`, `digest`). Grant and posture
  events arrive with just-in-time access and posture evaluation.
- Heartbeats: `{"type": "heartbeat", "seq", "time_ms"}`, where `seq` is the
  latest sequence number sent.
- Snapshots: `{"type": "snapshot", "seq", "revocations", "bundle_version",
  "bundle_digest"}`. A stream without `after`, or with an `after` the control
  plane no longer retains (`EVENT_RETENTION`), starts with one.
- Pruning drops only the oldest events, by sequence number, so the events
  retained never have a gap. If events the node needs were pruned while it
  resumed, the control plane sends a snapshot instead of skipping them.
- The control plane closes the stream when the node is revoked, or when the
  certificate it connected with is revoked or expires.
- Acknowledgements: `POST /v1/node/events/ack` with
  `{"acks": [{"seq", "applied_at_ms", "connections_cut"}]}`.

## 13. Versioning and extensibility

- Every CONNECT request and control call carries `Warren-Protocol: {n}`.
  A peer that does not support `{n}` refuses with a 4xx response and a
  `Proxy-Status` or problem detail naming the supported range. Each role
  supports the current and the previous protocol version (`VERSION_SKEW`).
- Unknown capsule types MUST be ignored (RFC 9297). warren's capsule types are
  provisional codepoints from the unregistered space until registered
  (`WARREN_CAPSULE_*`). Endpoints SHOULD send reserved (GREASE) capsule types
  and settings occasionally to keep the extension points working.
- New behavior arrives as new capsules, settings or request headers that old
  peers ignore safely; the meaning of an existing codepoint never changes.

## 14. Named parameters

Fixed values are bounds promised in [design.md](design.md#4-guarantees). Other
defaults are initial and may change with measurement.

| Parameter | Value | Meaning |
| --- | --- | --- |
| `CLIENT_CERT_LIFETIME` | at most 4 h (fixed bound) | User+device certificate lifetime |
| `CLIENT_CERT_RENEW_AT` | 0.5 (fixed) | Fraction of lifetime, from issuance, at which renewal starts |
| `REVOCATION_DEADLINE` | 10 s (fixed) | Commit to last connection cut |
| `POSTURE_RECHECK_INTERVAL` | at most 5 min (fixed bound) | Maximum time between posture reports |
| `POSTURE_STATEMENT_LIFETIME` | at most 5 min (fixed bound) | Validity of a signed posture statement, from its oldest observation |
| `CLOCK_SKEW_ALLOWANCE` | at most 2 min (fixed bound; deployments may only lower it) | `notBefore` backdating and validity slack, including posture statements |
| `TUNNEL_MTU` floor | 1280 (fixed) | RFC 9484 minimum |
| `REVOCATION_APPLY_BUDGET` | 1 s | Node-side time to apply a revocation |
| `EVENT_HEARTBEAT_INTERVAL` | 2 s | Event-stream heartbeat |
| `EVENT_STALE_AFTER` | 3 heartbeats | Silence before a node reconnects |
| `CLIENTLESS_ASSERTION_LIFETIME` | 5 min | Validity of a control-plane-signed clientless session assertion (user, app, sign-in session, IdP authentication time, MFA) |
| `INFRA_CERT_LIFETIME` | 24 h | Relay, connector and control-plane certificates |
| `INFRA_KEY_ALG` | ECDSA P-256 | Infrastructure key algorithm |
| `JOIN_TOKEN_LIFETIME` | 1 h, single use | Node bootstrap token |
| `EVENT_RETENTION` | 7 days | How far back a node can resume the event stream |
| `SESSION_MAX_LIFETIME` | deployment setting | Maximum time between browser sign-ins |
| `PASSWORD_KDF` | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte salt | Built-in account password hashes; each records its iteration count and is rehashed at sign-in when it falls behind |
| `ACCOUNT_LOCKOUT` | 5 failures in a row, 15 min | Lockout of a built-in account after failed passwords or codes |
| `SOURCE_FAILURE_LIMIT` | 20 failures per 15 min | Failed built-in account sign-ins per source address |
| `SETUP_LINK_LIFETIME` | 72 h, single use | One-time link that sets a built-in account's password |
| `RECOVERY_CODES` | 10, 50 bits each, single use | Issued when an authenticator is enrolled |
| `TUNNEL_MTU` | 1280 | Initial tunnel MTU |
| `TUNNEL_MTU_MAX` | 1380 | Largest tunnel MTU used when proven |
| `FALLBACK_DELAY` | 300 ms | QUIC head start before racing HTTP/2 |
| `FALLBACK_MEMORY` | 24 h | How long a network's transport outcome is remembered |
| `QUIC_REPROBE_INTERVAL` | 5 min | QUIC re-probe period while on HTTP/2 |
| `FIRST_PACKET_HOLD` | 2 s | Longest a first packet waits for session setup or name binding |
| `FIRST_PACKET_QUEUE` | 64 KiB per destination | Bound on held packets |
| `FLOW_IDLE_TIMEOUT` | UDP 60 s, ICMP 10 s | Idle time that ends a UDP or ICMP flow |
| `DRAIN_TIMEOUT` | 5 min | Longest a draining connector keeps existing streams |
| `REPLICA_SELECTION` | least loaded | Relay's choice of connector replica |
| `BIND_ROLLOVER` | context ID 12287 | Context ID at which a relay asks the connector for a fresh bind stream (three quarters of the 2-byte bound) |
| `RELAY_LIMITS` | deployment setting | Per-client and per-connector relay limits |
| `RELAY_PEER_PREFIX` | an IPv6 ULA /64 per relay | Virtual peer addresses on bind streams |
| `DEVICE_POOL_V4`, `DEVICE_POOL_V6` | deployment setting (defaults `100.96.0.0/16`, `fd00:7761:7272:6e00::/64`) | Device tunnel addresses |
| `SYNTHETIC_POOL_V4`, `SYNTHETIC_POOL_V6` | deployment setting with local fallbacks (defaults `100.80.0.0/16`, `fd00:7761:7272:6e01::/64`) | Synthetic addresses for name apps |
| `VERSION_SKEW` | current and previous | Protocol versions each role accepts |
| `BIND_DRAFT_REVISION` | 16 | Pinned revision of the bound-UDP draft |
| `WARREN_OID_ARC` | `2.25.97285697713720826090513308506181383429` | OID arc for the warren identity extension: a UUID-based arc (ITU-T X.667), which needs no registration |
| `WARREN_CAPSULE_*` | `NAME_BIND` 0x3a726e10, `NAME_BOUND` 0x3a726e11, `FLOW_DENIED` 0x3a726e12, `POSTURE` 0x3a726e13, `CERT_REFRESH` 0x3a726e14, `NOTICE` 0x3a726e15, `PEER_INFO` 0x3a726e16 | Provisional capsule types (none is a GREASE value) |

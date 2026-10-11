# warren wire protocol profile

Status: profile for M1, recorded at M0. It fixes the requirements and
invariants an implementation must meet. Tunable values are named parameters
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
  except where link D explicitly allows WebPKI before enrollment.
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
  warren pins one draft revision (`BIND_DRAFT_REVISION`) until an RFC exists.
  Bind mode lets one request stream carry datagrams from many peers; the relay
  assigns each peer its own compressed context ID and announces the peer's
  address with the extension's capsules. Context IDs on a bind stream stay
  within the MTU budget's bound ([section 9](#9-mtu-budget)), and the
  extension's uncompressed context, which carries the peer address in every
  datagram, MUST NOT be used.
- Peers are virtual: each spliced client stream appears to the connector as a
  distinct peer address that the relay allocates from a private range
  (`RELAY_PEER_PREFIX`). The connector's inner QUIC endpoint uses these
  addresses only to tell sessions apart.
- Each connector replica keeps one attachment per relay in its relay set
  (default: every relay in the deployment) and re-attaches immediately when an
  attachment drops.
- Draining: a connector that is shutting down sends HTTP/3 GOAWAY on the outer
  connection; the relay MUST stop assigning new client streams to it and MAY
  keep existing ones until they close or `DRAIN_TIMEOUT` passes.
- If the semantics change incompatibly before the draft is final, warren keeps
  the same semantics behind warren-specific capsules. The semantics, not the
  codepoints, are the contract.

### 4.3 Relay splicing

When a client's CONNECT-UDP names group G, the relay:

1. selects a healthy replica of G attached to it (`REPLICA_SELECTION`, default
   least-loaded) and pins the client stream to that replica for its lifetime;
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
  TLS exporter value of the inner session (RFC 8446 section 7.5), which binds
  the new certificate to this session and this key. The connector MUST verify
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
  bundle only.
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
| warren identity extension | non-critical, OID under `WARREN_OID_ARC`: session ID, IdP authentication time, MFA performed (from the IdP's `amr`/`acr`), device enrollment trust class, device tunnel addresses |
| Revocation pointers | none (no CRL distribution points, no OCSP); revocation is pushed |

- Group membership is deliberately absent: it changes faster than certificates
  and reaches connectors in signed policy bundles instead.
- Issuance needs a signed PKCS#10 request from the device key, a live session,
  an enabled user, an approved and unrevoked device, and passing baseline
  posture. Renewal starts at half-life (`CLIENT_CERT_RENEW_AT`, fixed at 0.5)
  over the existing mTLS channel.

### 10.3 Infrastructure certificates

- Issued by the infrastructure CA to the control plane, relays and connectors.
  Keys are generated on the node and never leave it (P-256 ECDSA or Ed25519,
  `INFRA_KEY_ALG`).
- SAN: DNS names where the node listens (control plane, relays) and a URI
  `warren://{td}/{role}/{id}`; connectors use
  `warren://{td}/connector/{group}/{id}`.
- Extended Key Usage: serverAuth for listeners, clientAuth for outbound
  connections; connectors need both (they are the TLS server of link C and the
  TLS client of links B and E).
- Lifetime `INFRA_CERT_LIFETIME`, renewed at half-life over link E.
- Bootstrap: a single-use join token, valid for `JOIN_TOKEN_LIFETIME` and scoped
  to one role (and one connector group), is exchanged with a signed request for
  the first certificate.

## 11. Control channels

### 11.1 Client to control plane (link D)

HTTPS (HTTP/2 or HTTP/3), JSON, under a versioned path. Requirements:

1. **Discovery.** `GET https://{org}/.well-known/warren` returns the
   deployment identifier, trust bundle, API base and sign-in endpoint.
2. **Sign-in.** OAuth 2.0 for native apps (RFC 8252) in the system browser
   with authorization code and PKCE (RFC 7636). The control plane is the OIDC
   relying party toward the IdP; the client receives a one-time code bound to
   its PKCE verifier and exchanges it, together with a request signed by the
   device key, for a session bound to that key.
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

### 11.2 Relays and connectors to control plane (link E)

- mTLS with infrastructure certificates.
- **Policy bundles.** The control plane publishes a signed, versioned bundle:
  the compiled Cedar policy set and schema, the entity snapshot (users, groups,
  devices, apps, connector scopes, active JIT grants with expiries), the current
  revocation state, and the posture-signing and session-assertion-signing
  public keys. Bundle versions only increase; a node MUST reject a bundle older
  than its current one, MUST verify the signature before use, and MUST persist
  the last verified bundle so it can restart during an outage (G10).
- **Event stream:** [section 12](#12-revocation-push-channel).
- **Health and audit.** Nodes report health and metrics and export audit
  records to the control plane and any configured sinks.

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
   integration test asserts the deadline (M2).
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
| `CLIENT_CERT_RENEW_AT` | 0.5 (fixed) | Fraction of lifetime at which renewal starts |
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
| `SESSION_MAX_LIFETIME` | deployment setting | Maximum time between browser sign-ins |
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
| `RELAY_LIMITS` | deployment setting | Per-client and per-connector relay limits |
| `RELAY_PEER_PREFIX` | an IPv6 ULA /64 per relay | Virtual peer addresses on bind streams |
| `DEVICE_POOL_V4`, `DEVICE_POOL_V6` | deployment setting | Device tunnel addresses |
| `SYNTHETIC_POOL_V4`, `SYNTHETIC_POOL_V6` | deployment setting with local fallbacks | Synthetic addresses for name apps |
| `VERSION_SKEW` | current and previous | Protocol versions each role accepts |
| `BIND_DRAFT_REVISION` | chosen in M1 | Pinned revision of the bound-UDP draft |
| `WARREN_OID_ARC` | to be assigned | OID arc for the warren identity extension |
| `WARREN_CAPSULE_*` | to be assigned in M1 | `NAME_BIND`, `NAME_BOUND`, `FLOW_DENIED`, `POSTURE`, `CERT_REFRESH`, `NOTICE`, `PEER_INFO` |

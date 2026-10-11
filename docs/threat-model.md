# warren threat model

Status: v1 threat model, recorded at M0. It is revisited at every milestone
and is the starting brief for the external security audit in M4.

Every mitigation here points at a guarantee in
[design.md](design.md#4-guarantees) (G1 to G19). A threat whose mitigation
cannot be tied to a guarantee is a gap in the design and is listed in
[section 7](#7-open-items).

## 1. Scope

In scope: the v1 design, meaning the control plane, relays, connectors, the
macOS client, the Kubernetes operator, the clientless HTTP(S) tier, and the
build and dependency pipeline.

Out of scope: the security of the applications warren protects (warren limits
who can reach them, not what they do once reached), the IdP's own security, and
the security of the operating systems warren runs on beyond the platform
features it relies on.

## 2. Assets

| Asset | Why it matters |
| --- | --- |
| Private applications and their data | What warren exists to protect. |
| Deployment root and issuing CA keys | Mint any identity; full compromise if stolen. |
| Policy-signing, posture-signing and session-assertion-signing keys | Forge policy bundles, posture statements or clientless identities. |
| Device private keys | Act as a device; bound to hardware (G3). |
| Client certificates and sessions | Act as a user on a device, for at most 4 hours (G4). |
| Policy, entity data, grants | Decide who reaches what. |
| Audit records | Detection, investigation, compliance. |
| Kubernetes broker service-account credentials | Can impersonate any user or group toward the API server, potentially a cluster administrator; RBAC cannot limit impersonation to a name prefix (G15, T13). |
| Join tokens | Enroll a relay or connector. |
| Control-plane database | Users, devices, sessions, grants, configuration, audit. |
| Availability of relays and connectors | Access to everything depends on it. |

## 3. Actors

| Actor | Capabilities assumed |
| --- | --- |
| Internet attacker | Reaches relays and the control plane's public endpoints; no credentials. |
| On-path attacker near a client | Observes, drops, delays, injects and intercepts traffic on the client's network, including TLS-intercepting middleboxes. |
| Malicious insider | A legitimate user with valid credentials and an approved device, trying to exceed their entitlements. |
| Thief of a device | Physical possession of an enrolled Mac, locked or unlocked. |
| Malware on an enrolled device | Runs as the user, possibly with elevated privileges. |
| Compromised relay | Full control of a relay host and its keys. |
| Hostile connector network | Controls the network around a connector: DNS, routing, other hosts, possibly the apps themselves. |
| Compromised connector | Full control of a connector host and its keys. |
| Compromised control plane | Full control of the control plane, its keys and database. |
| Compromised or lagging IdP | Asserts false identities, or reports changes late. |
| Cluster insider | Can create or edit warren CRDs and Service annotations in some namespaces of a cluster. |
| Supply-chain attacker | Publishes or compromises a crate, a build tool, or a CI action. |

## 4. Trust boundaries

| ID | Boundary | Crossing |
| --- | --- | --- |
| TB1 | Device: user processes, the system extension, the Secure Enclave | Apps send packets into the tunnel; the extension asks the enclave to sign. |
| TB2 | Client to relay (the internet) | Outer QUIC or HTTP/2, mutual TLS. |
| TB3 | Relay | Splices sessions; trusted for availability and admission only. |
| TB4 | Relay to connector | Outer QUIC or HTTP/2, mutual TLS. |
| TB5 | Client to connector | Inner QUIC, mutual TLS, end to end through the relay. |
| TB6 | Connector to private network | Plain traffic to destinations in scope. |
| TB7 | Nodes and clients to the control plane | HTTPS, mutual TLS after enrollment; signed bundles. |
| TB8 | Control plane to the IdP | OIDC, SCIM, shared signals. |
| TB9 | Admins to the control plane | Console, API, CLI, Git, CRDs. |
| TB10 | Kubernetes broker to the API server | Impersonation with the broker's service account. |
| TB11 | Source and dependencies to binaries | Build and CI pipeline. |

## 5. Threats and mitigations

### T1. Compromised relay

A relay operator, or an attacker who owns a relay host, tries to read or alter
traffic, impersonate a party, or reach private networks.

- **Cannot read or alter tunneled application traffic.** The inner session is
  end-to-end QUIC between client and connector; the relay forwards ciphertext
  (G5, G16).
- **Can read and alter clientless HTTP(S) traffic** it proxies, because it
  terminates TLS for those apps; that is the cost of the lower-assurance
  clientless tier (T14). It cannot mint or extend a clientless identity: the
  connector admits a clientless request only with a control-plane-signed
  session assertion naming the user, the app, the sign-in session, the IdP
  authentication time, whether MFA was used, and an expiry, and it takes the
  authentication facts policy checks only from that assertion, so the relay
  cannot pass off a stale or non-MFA sign-in as fresh. Within a live
  clientless session it carries, it can send requests as that user to that app
  until the assertion expires or the session is revoked.
- **Cannot impersonate a connector or a tunnel client.** The client verifies
  that the inner session's certificate names a connector in the expected group,
  issued by the infrastructure CA; the connector verifies the client's
  certificate itself. Neither relies on the relay's checks. The relay holds no client or
  connector keys (G2, G3, G5).
- **Cannot reach private networks.** A relay can only forward to attached
  connectors, and connectors admit only authenticated inner sessions or
  clientless requests with a valid session assertion; there is no relay egress
  (G6, G8).
- **Can see metadata:** which user and device talk to which connector group,
  when, and how much; the client's public address. **Can deny service** by
  dropping or delaying traffic. Mitigations: clients move to another relay;
  relays are stateless and replaceable; relay certificates are short-lived and
  revocable (G9, G18).
- **Can lie about the client's public address**, which matters only to rules
  with `network` conditions. Policy labels that signal relay-observed and the
  docs advise never using it alone ([policy.md](policy.md#5-access-policies)).

Residual risk: metadata exposure to relay operators, loss of availability, and
exposure of clientless content and live clientless sessions. Run relays you
control.

### T2. Stolen device

- **Locked or powered off.** Disk encryption (a posture check) protects data at
  rest. The device key lives in the Secure Enclave and cannot be extracted
  (G3). An admin or the user disables the device, cutting access within
  10 seconds (G9); otherwise access ends within one certificate lifetime when
  renewal fails (G4).
- **Unlocked, with a live session.** The thief can use whatever the user can
  reach until the device is disabled. Mitigations: screen-lock posture checks
  (G11); rules that require recent authentication or MFA for sensitive apps,
  which force an IdP sign-in the thief cannot complete; revocation within
  10 seconds once reported (G9).

Residual risk: the window between theft and report on an unlocked device.

### T3. Stolen certificate

A certificate is public data; it is useless without its private key. Client
keys are non-exportable Secure Enclave keys, so a copied certificate cannot
complete a TLS handshake (G3). Even if a key were usable remotely through a
compromised device (see T10), the certificate lasts at most 4 hours (G4) and
revoking its session, device or serial cuts it within 10 seconds (G9). TLS 1.3
encrypts client certificates in the handshake, so passive observers do not
learn identities. Resumption tickets never outlive their certificate and
revocation is re-checked on resumption ([protocol.md](protocol.md#3-common-tls-and-quic-profile)).

### T4. Malicious connector network and compromised connector

**Hostile network around a connector.**

- **DNS poisoning** could point an app's name at an attacker's host. Every
  resolved address must fall inside the connector group's declared scope, so a
  poisoned answer cannot send users outside it (G8). Inside the scope, the app's
  own TLS remains the defense; warren does not replace it.
- **Server-initiated attacks on clients** are blocked: flows toward clients are
  off unless an app opts in (G7, G8).
- **Scanning from the connector** by an insider is bounded by policy per flow,
  destination scopes, deny audit and rate limits (G1, G8, G13).

**Compromised connector.** It sees plaintext for the apps it serves, which is
inherent: it is where traffic leaves the tunnel. It cannot mint identities,
cannot reach other connector groups' apps through warren, and cannot forge
policy (bundles are signed by the control plane). It could under-enforce its
own apps or lie in its own audit. It holds no Kubernetes impersonation rights;
only the Kubernetes broker does (T13). Mitigations: small connector groups with
tight scopes (blast radius), short-lived infrastructure certificates and node
revocation (G9), audit cross-checks between relay-side and connector-side
records, and connectors as hardened, minimal data-path builds (G17).

Residual risk: full access to the apps behind one compromised connector.

### T5. Control-plane compromise

The control plane is the root of trust; an attacker who owns it can mint
identities and rewrite policy. warren cannot make this harmless, so it aims to
make it hard, visible and recoverable.

- **Hard.** Minimal exposed surface; admin actions require an authenticated,
  recently MFA'd admin identity from the IdP; CA and signing keys are encrypted
  at rest, with an offline root possible (G16, G18). Policy from Git or CRDs is
  reviewed outside warren before it applies (G19).
- **Visible.** Every change and every decision is audited and can be streamed
  off-box as it happens to sinks the control plane cannot rewrite (G13).
- **Limited.** The control plane never sees application traffic (G5), and the
  infrastructure and client CAs are separate, so a stolen client CA cannot
  impersonate relays or connectors.
- **Recoverable.** Rotate the root and issuing CAs, re-join nodes and re-enroll
  devices; short lifetimes make old credentials expire within hours (G4).

Residual risk: full compromise grants full access until detected. This is the
reason the control plane is small, separately deployable and audited.

### T6. IdP lag and IdP compromise

**Lag.** A user disabled in the IdP keeps access until warren learns of it.

- IdPs that send shared signals (CAEP/RISC) or SCIM deprovisioning reach the
  10-second revocation path directly (G9).
- Certificate renewal re-checks the session with the IdP where the IdP allows
  it, so a disabled account stops renewing within one certificate lifetime
  (G4). IdP status polling arrives in v1.x.
- Rules on sensitive apps can require recent authentication, forcing a fresh
  IdP sign-in that a disabled account fails.
- The latency from an IdP-side change to warren is documented per IdP, so
  operators know their real exposure.

**Compromise.** A compromised IdP can assert any identity. warren still
requires an approved device whose key is in hardware (G2, G3), so an IdP
compromise alone does not grant access from an unknown device; device approval
rules that need a server-verified signal (for example MDM enrollment) make that
step independent of the IdP.

### T7. DNS bypass and DNS manipulation on the client

- **Bypass.** Applications with their own encrypted DNS send internal names to
  public resolvers, which leaks internal hostnames and fails. The client answers
  the browser DNS-over-HTTPS canary so compliant browsers fall back to system
  DNS, detects bypass for internal names, and tells the user what to change
  rather than failing silently (G12, G14). Internal names reveal nothing beyond
  the name itself; no traffic reaches an app without the tunnel.
- **Local DNS spoofing** cannot redirect internal names, because the client
  answers them itself from entitlement data. Public names are outside warren's
  scope (G14).
- **Synthetic address misuse.** A synthetic address means something only after
  the connector accepts its name binding, which it accepts only for the name's
  single owning app (an exact host first, otherwise the most specific matching
  wildcard) and within its own scope (G8). Binding a name to a broader wildcard
  app to dodge a more specific app's rules is rejected.

### T8. Hostile client network

- **Blocking UDP** triggers the HTTP/2 over TCP 443 fallback with identical
  end-to-end guarantees (G5).
- **TLS interception** fails: clients verify relays against the deployment
  trust bundle, not system roots, and report that the network intercepts TLS
  (G12).
- **Downgrade** is not possible: TLS 1.3 only, no 0-RTT, no protocol or cipher
  negotiation that weakens the inner session (G16).
- **Traffic analysis** of the outer layer reveals that warren is in use and
  traffic volume, not destinations or identities.

### T9. Malicious insider with valid credentials

- **Reaching apps they are not entitled to:** every flow is admitted at the
  connector, never by the client (G1, G7).
- **Spoofing source addresses** inside the tunnel: the connector drops packets
  not from the assigned device addresses (G2, RFC 9484).
- **Abusing JIT:** requesters never approve their own requests; reasons,
  approvals and grants are audited; grants expire on the connector's own clock
  (G9, G13).
- **Escalating in Kubernetes** through impersonation: see T13.
- **Granting themselves access through config:** delegation scopes limit
  which connector groups each source may publish through, which client-facing
  names it may claim, and which apps its policies may grant; a name already
  used by another app or reserved for warren itself cannot be claimed; and
  every change is audited (G19).

### T10. Malware on an enrolled device

Malware running as the user can use the tunnel exactly as the user can; that is
the inherent scope of device-level access. It cannot extract the device key
(G3). Mitigations: posture checks, including a named security agent with a
server-verified signal (G11); short certificates and fast revocation (G4, G9);
sensitive apps that require fresh MFA; and full audit of what the device
reached (G13). The system extension's access to the enclave key is restricted
to warren's signed code.

Residual risk: a fully compromised device acts as its user until detected.

### T11. Supply-chain compromise

- Direct dependencies come only from the allowlist, pinned exactly, vendored,
  and vetted with cargo-vet; cargo-deny blocks known advisories, unapproved
  licenses and sources; the per-binary closure gate fails CI on any growth
  (G17). See [dependencies.md](dependencies.md).
- Builds use only vendored sources, offline, with a pinned toolchain.
- CI actions are pinned by commit; CI-only tools are pinned binaries verified
  against recorded digests and never ship in products.
- Data-path builds exclude console, operator and Kubernetes crates, so the
  largest dependency trees cannot reach the data path (G17).
- Release signing and reproducible-build checks are added before v1.0 (M4).

### T12. Rogue relay or connector through a stolen join token

Join tokens are single-use, short-lived and scoped to one role and one
connector group. A node's identity is an infrastructure certificate the admin
can see and revoke (G9). A rogue relay gains only what T1 describes. A rogue
connector in a group could receive that group's sessions until it is noticed
and revoked; every attachment is audited (G13). Admin approval of new
connectors is a possible later option if join tokens alone prove
insufficient.

### T13. Abuse of Kubernetes impersonation

Kubernetes RBAC can limit `impersonate` only to exact names, never to a
prefix, so a component that impersonates arbitrary IdP users and prefixed
groups needs unrestricted impersonation, which includes `system:masters`.
warren therefore confines that power to one component, the Kubernetes broker.

- Only the broker's service account holds impersonation rights. Connector
  pods, including in-cluster connectors, hold none, so compromising a
  connector (T4) does not yield impersonation.
- The broker verifies the user's short-lived, session-bound credential itself,
  impersonates only that user and their prefixed IdP groups, and refuses any
  `system:` user or group (G15). That refusal is a software check in the
  broker, not a limit the API server enforces.
- **A compromised broker is equivalent to its impersonation power**, which is
  potentially cluster-admin. Mitigations: the broker is small, runs as its own
  Deployment in the operator's namespace with its service account mounted
  nowhere else, its RBAC allows impersonation and nothing more, and where the
  cluster supports constrained impersonation its grant uses it to narrow what
  impersonated requests may do.
- A cluster insider who edits warren CRDs or Service annotations can only
  publish apps and write policies within that cluster's delegation scope
  ([policy.md](policy.md#7-ownership-and-delegation)). They cannot widen the
  connector group's destination or client-name scope, and cannot claim a
  client-facing name outside the cluster's grant, one another app already
  owns, or one reserved for warren's control plane, relays or IdP sign-in, so
  they cannot redirect other users' traffic for those names to their own
  Services.
- The API server's own audit log records the impersonated user and the
  broker's service account, alongside warren's decision record (G13).

### T14. Clientless tier

The relay terminates TLS for clientless apps, so it can read and alter that
traffic; there is no device identity; browser sessions can be stolen through
the browser. Identity does not depend on the relay: after browser sign-in the
control plane issues a short-lived session assertion (user, app, sign-in
session, IdP authentication time, MFA, expiry), and the connector verifies it
against the control plane's key before forwarding each request and takes the
authentication facts for `auth` conditions only from it, so a relay cannot
mint or extend an identity, and revoking the session cuts it (G9).
Mitigations: clientless is opt-in per app; rules must name `browser`
explicitly and can never satisfy posture conditions (G2); session cookies are
host-only, `Secure`, `HttpOnly`, short-lived and bound to the IdP session; the
connector strips any incoming identity header and passes the verified
assertion to the app as its identity header, which apps verify against the
control plane's published keys.

### T15. Denial of service

Relays and the control plane are the public surfaces. QUIC address validation
and retry, per-client limits on relays, unauthenticated requests rejected
before expensive work, horizontally scaled stateless relays, and a control
plane whose outage does not cut existing access (G10) limit the impact. Volume
attacks beyond a deployment's capacity are out of scope.

### T16. Audit evasion and tampering

Every decision and flow is recorded by the enforcing connector (G13), relays
record sessions independently, and records stream to external sinks as they
happen, so deleting them from one component does not erase them. Log fields
from users (names, reasons) are encoded as structured data, never interpolated
into log lines.

### T17. Clock manipulation

Certificate validity, grant expiry and posture freshness depend on clocks.
Nodes and clients must run time synchronization; validation allows only a small
skew (`CLOCK_SKEW_ALLOWANCE`, fixed bound: at most 2 minutes); expiry is
enforced by both the control plane and the connector, so one wrong clock cannot
extend access past the other's view (G4, G9).

## 6. Accepted risks

- Relays see connection metadata (T1).
- Clientless sessions are lower assurance by design: they carry no device
  identity, and a compromised relay can read and alter the clientless HTTP(S)
  traffic it proxies and act within the live clientless sessions it carries
  until their assertions expire (T1, T14).
- A compromised connector exposes the apps behind it (T4).
- A compromised Kubernetes broker can act as anyone its service account may
  impersonate, potentially a cluster administrator (T13).
- A compromised control plane is a full compromise until detected (T5).
- Device-level access means any process on an enrolled, unlocked device can
  use the user's access (T2, T10).
- An IdP without shared signals or SCIM leaves a lag bounded by the
  certificate lifetime until polling arrives in v1.x (T6).

## 7. Open items

| Item | Milestone |
| --- | --- |
| Choose the hardware attestation path for Mac device keys and its trust class | M1 |
| Specify posture-statement and policy-bundle encodings and their signature formats | M1 |
| Specify the clientless session-assertion format and its signature | M3 |
| Revocation-deadline integration test and published latency metric | M2 |
| Per-IdP revocation latency documentation | M2 |
| Off-box audit streaming verified end to end | M3 |
| Release signing, provenance and reproducible-build checks | M4 |
| External security audit of the design and implementation | M4 |

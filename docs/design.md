# warren design

Status: accepted design for v1, recorded at milestone M0. Nothing described
here is implemented yet beyond the project skeleton.

This document states what warren promises and why. It is written as
guarantees and decisions, not algorithms, so it stays stable while the code
changes underneath it. The details live elsewhere:

- [protocol.md](protocol.md): the wire profile (QUIC, MASQUE, certificates,
  MTU, revocation push).
- [threat-model.md](threat-model.md): assets, actors, trust boundaries, and
  threats mapped to the guarantees below.
- [policy.md](policy.md): the policy schema and how it compiles to Cedar.
- [dependencies.md](dependencies.md): the dependency policy and the measured
  dependency closure.

## 1. What warren is

warren replaces VPNs with zero-trust private access. People reach internal
applications because of who they are, which device they use, and the state of
that device, never because they happen to be on a network. It is open source
(Apache-2.0), self-hosted, and runs anywhere: on Kubernetes or as a single
binary on any machine, with no vendor cloud behind it.

warren is deliberately small. It does one job, private access, and does it
thoroughly: identity- and device-aware, default-deny, continuously
re-evaluated, explained, and audited.

Principles, in priority order when they conflict:

1. **Zero trust by construction.** Every connection is authenticated,
   authorized against policy, and recorded. No network location is trusted.
2. **Secure and fast by default.** Standard protocols (QUIC, MASQUE, TLS 1.3),
   a memory-safe implementation (Rust), one audited crypto stack (rustls on
   aws-lc-rs), and a short, audited dependency list. Performance is a feature,
   measured from the first milestone that moves packets.
3. **It should feel effortless.** Sign in once. The tunnel is invisible until
   something is blocked, and then it says exactly why.
4. **Small and solid over sprawling.** A short list of things done very well;
   see [section 3](#3-non-goals-and-the-leave-out-list).
5. **Deploy anywhere.** The same binary runs in a homelab, on a VM, or in a
   Kubernetes cluster.
6. **Everything as code.** Policy and configuration are declarative and
   reviewable. The UI explains; Git decides.

## 2. Goals for v1

- **Private access.** Identity- and device-aware access to internal
  applications through outbound-only connectors. Applications can be FQDNs,
  wildcard domains, IP addresses or CIDR ranges, each scoped by port and
  protocol. Internet traffic goes direct and never enters warren.
- **A client that feels native, macOS first.** A signed menu-bar app with a
  packet tunnel in a NetworkExtension system extension. Windows (Wintun and
  WFP) and Linux (TUN, tray and CLI) follow in v1.x; mobile after them.
- **Very good Kubernetes integration.** Connectors as an operator, apps and
  policies as CRDs, and identity-brokered `kubectl` that maps cluster RBAC to
  IdP groups.
- **Continuous zero-trust evaluation.** Default-deny policy over user, device,
  posture, authentication freshness, and optional network and time
  conditions; just-in-time access; revocation in seconds.
- **Scale targets.** 5,000 devices, 1,000 apps, 3 relay regions, and 1 Gbps
  per connector on 4 vCPUs.
- **Performance bar.** Faster than the commercial zero-trust tunnels warren
  replaces, measured by a benchmark suite that exists from M1 onward
  (throughput, added latency, connect time, CPU per Gbps).

## 3. Non-goals and the leave-out list

**Not in v1, planned later:** public internet access security (with any TLS
interception opt-in per destination, never a default); direct peer-to-peer
paths (a pure performance optimization over relays); clientless access beyond
HTTP(S) (browser-based SSH, RDP, VNC and more); live session viewing and
recording for `kubectl exec` and SSH; workload-to-app access with projected
service-account tokens (v1.x); IdP status polling (v1.x); a Terraform/OpenTofu
provider (v1.x); Windows, Linux (v1.x) and mobile clients (after Windows and
Linux).

**Never, by design.** These are the product creep warren exists to avoid. A
proposal that needs one of them belongs in another project.

- TLS interception by default, or any content inspection of private-app
  traffic.
- A vendor cloud, phone-home telemetry, or a license server.
- Being an identity provider (warren never stores passwords), an MDM (warren
  reads posture, it does not manage devices), or an endpoint security agent.
- Opaque risk scores. Every decision is explained by named rules and named
  conditions.
- DLP, CASB, browser isolation, email security, SD-WAN, firewall-as-a-service,
  or experience-monitoring suites.
- Proprietary protocols or hand-rolled cryptography.
- Scripting, plugins or a marketplace inside the data path.
- "Trusted networks" that bypass policy, or a full-tunnel mode that hauls all
  internet traffic through warren.
- A JavaScript build toolchain for the console.

A feature earns its place by strengthening one of the guarantees below or the
experience of one that exists. Anything else is creep.

## 4. Guarantees

These are warren's promises. Each has a stable identifier that
[threat-model.md](threat-model.md) cites; changing one is a design change.
Timing bounds written as numbers are part of the promise. Everything else
tunable is a named parameter in [protocol.md](protocol.md#14-named-parameters).

| ID | Guarantee |
| --- | --- |
| **G1** Default deny | Nothing is reachable unless a policy rule allows it. A small set of invariants (valid certificate, approved device, destination inside the app and connector scope) hold regardless of policy and cannot be overridden by a rule. |
| **G2** User and device | Every tunneled connection is bound to exactly one authenticated user and one approved device. Clientless sessions are bound to a user only and exist only for apps that opt in. |
| **G3** Hardware-bound device keys | A device's private key is generated in and never leaves its hardware key store (the Secure Enclave on macOS). A certificate is useless without the device that holds the key. |
| **G4** Short-lived credentials | Client certificates live at most 4 hours and renew at half-life. Renewal re-checks the user, the device, the session, and baseline posture. |
| **G5** End-to-end encryption | Tunneled application traffic is encrypted from client to connector inside a mutually authenticated session. Relays forward only its ciphertext and cannot impersonate either end. Clientless traffic is the stated exception: the relay sees it in clear, but cannot mint or extend a user's identity (section 6). |
| **G6** Outbound only | Clients and connectors only dial out. A connector needs no inbound port on the network it serves. |
| **G7** Enforcement at the connector | The connector admits every new flow against policy. The client is never trusted to enforce anything; its local checks exist only to explain blocks faster. |
| **G8** Scoped reach, no open proxy | A connector reaches only destinations declared for it, a relay forwards only to connectors attached to it, and neither will carry traffic anywhere else. |
| **G9** Revocation in 10 seconds | Disabling a user or device, revoking a session, expiring or revoking a JIT grant, and changing policy cut every live connection that is no longer allowed within 10 seconds while connectors and relays are connected to the control plane. This is a tested promise. |
| **G10** Fail closed | During a control-plane outage nobody gains access, connectors keep enforcing the last policy they verified, and all access decays to zero within one certificate lifetime. |
| **G11** Continuous posture | Device posture is re-checked at least every 5 minutes, and connectors enforce that bound themselves: a posture statement lasts at most 5 minutes, plus a clock-skew allowance of at most 2 minutes. A stale signal counts as failing. A failing check cuts only the apps whose rules require it. Every signal carries a trust class. |
| **G12** Explained blocks | Every denial produces a specific, human-readable reason for the user and the matching rule and condition for the admin. Nothing fails as a silent timeout. |
| **G13** Complete audit | Every access decision, allow or deny, and every flow produces a structured audit record. |
| **G14** Split tunnel, no interception | Only traffic for internal apps enters the tunnel. warren does not decrypt or inspect application content. |
| **G15** Kubernetes identity | Kubernetes API access impersonates the user and their IdP groups, never a built-in system identity, and leaves no long-lived secret in kubeconfig. Only a dedicated broker holds impersonation rights; connectors hold none. |
| **G16** Standard, audited crypto | TLS 1.3 only, through rustls on aws-lc-rs. No hand-rolled cryptography. |
| **G17** Small, audited supply chain | Direct dependencies come from an explicit allowlist; every crate is pinned, vendored, and vetted; data-path builds never link console, operator or Kubernetes crates. |
| **G18** Self-hosted | warren depends on no vendor-operated service and can run air-gapped. |
| **G19** Code is the source of truth | Objects managed from Git or CRDs are read-only in the UI, and every change, wherever it comes from, is audited. |

## 5. Architecture

### 5.1 Roles

| Component | What it does | Where it runs |
| --- | --- | --- |
| **Control plane** | Brokers sign-in with the IdP, registers and approves devices, issues certificates, evaluates posture reports, compiles and distributes policy, pushes revocations, serves the admin API, CLI endpoint and console, stores audit for search. The root of trust. | `warren control-plane`, on Kubernetes or any host. |
| **Relay** | Stateless rendezvous that clients and connectors both dial out to. Splices client sessions to connector sessions and forwards ciphertext. Also hosts clientless HTTP(S) access. | `warren relay`, anywhere reachable on 443. |
| **Connector** | Terminates end-to-end sessions from clients, admits each flow against policy, resolves internal names, and forwards traffic to private destinations. | `warren connector`, standalone or in-cluster via the operator. |
| **Client** | Native shell (Swift on macOS) around the shared Rust core: sign-in, device key, posture, DNS, and the packet tunnel. | macOS menu-bar app with a NetworkExtension system extension. |
| **Operator** | Kubernetes operator: runs connector replicas and the Kubernetes broker, publishes annotated Services and app CRDs, syncs policy CRDs to the control plane. | Its own binary, in each cluster. |

The control plane, relay and connector are one binary, `warren`, with one
role per subcommand. Each role is a build feature, so a data-path build (relay
and connector only) carries no control-plane or console code. The operator is
a separate binary so the Kubernetes client libraries never enter the data path
(G17).

### 5.2 Data path

```
                        ┌─────────────────────────────┐
                        │        control plane        │
                        │ IdP · CA · devices · policy │
                        │ revocation · audit · console│
                        └──▲───────────▲───────────▲──┘
          enroll, sign in, │   events  │   events  │
          certs, posture   │           │           │
┌───────────────┐          │     ┌─────┴─────┐     │          ┌───────────────┐
│  macOS client ├──────────┼────►│   relay   │◄────┼──────────┤   connector   ├──► private apps:
│ packet tunnel │ outer QUIC     │ ciphertext│        outer QUIC│ policy · NAT  │    FQDNs, wildcards,
└───────┬───────┘ CONNECT-UDP    │   only    │      CONNECT-UDP └───────▲───────┘    IPs, CIDRs,
        │                        └───────────┘          (bind)          │            k8s Services
        └═══════ inner QUIC: mutual TLS, CONNECT-IP, end to end ════════┘
```

- **Two layers.** The *outer* layer is a QUIC connection from the client to a
  relay and from the connector to the same relay. The *inner* layer is a
  second, mutually authenticated QUIC session from the client to the connector,
  carried inside the outer layer. The relay joins the two outer sessions and
  sees only inner-session ciphertext (G5).
- **Standard protocols.** Both layers speak HTTP/3. The client reaches the
  connector through the relay with CONNECT-UDP (RFC 9298); inside the inner
  session it tunnels IP packets with CONNECT-IP (RFC 9484). Both run on UDP
  443. When UDP is blocked the outer layer falls back automatically to HTTP/2
  over TCP 443; the inner session and its guarantees are unchanged.
- **Packet level.** The tunnel carries IP packets, so any TCP, UDP or ICMP
  application works without per-protocol proxies. Policy still scopes each app
  by port and protocol.
- **Outbound only.** Relays are the only data-path component that listens.
  Connectors attach to every relay in their relay set, so a client can use
  whichever relay is closest (G6).
- **Relay choice.** Clients measure relay latency and use the lowest. Losing a
  relay moves the client to another one; the inner session migrates and
  survives.
- **Later: direct paths.** Peer-to-peer paths between client and connector
  arrive later as a pure performance optimization. The inner session and its
  identity stay the same; only its path changes, and relays remain the
  fallback.

### 5.3 Trust boundaries

- **The device.** The system extension holds the tunnel and talks to the
  Secure Enclave; the device key never leaves the enclave. Other processes on
  the device can use the tunnel exactly as the signed-in user can, which is
  the inherent scope of device-level access.
- **Relays** are trusted for availability and for coarse admission (only valid
  certificates get through), never for confidentiality or integrity of
  tunneled application traffic. For clientless apps the relay terminates TLS,
  so it is trusted with that content, but never with identity (section 6).
- **Connectors** are trusted for the apps they serve. A connector is the
  policy enforcement point and the place where traffic leaves the tunnel, so it
  sees plaintext for its own apps and nothing else.
- **The control plane** is the root of trust: it issues every identity and
  signs every policy. It never sees application traffic.
- **The IdP** is trusted to authenticate users and assert group membership.
- **The Kubernetes API server** trusts warren's Kubernetes broker to
  impersonate users, within the limits in [section 9](#9-kubernetes).

[threat-model.md](threat-model.md) walks each boundary.

## 6. The client experience

The client is where warren is felt, so its behavior is part of the design.

- **Sign in once.** The user enters the organization URL and signs in through
  SSO in the system browser (OAuth 2.0 for native apps, RFC 8252). There are no
  configuration files, keys or certificates to handle. A managed deployment can
  preset the URL and pre-approve the system extension through an MDM profile.
- **Always on.** The tunnel survives sleep, wake and network changes without
  prompting. Sessions migrate across networks; renewal happens in the
  background.
- **Split tunnel.** Only traffic for internal apps the user may reach is
  routed into the tunnel (G14).
- **Names just work.** Internal names resolve automatically through split DNS;
  see [section 8](#8-internal-names-and-addressing).
- **Every block has a reason.** If policy, posture, authentication age,
  schedule or a broken path stops a connection, the app fails fast and the
  menu-bar app says what happened and what to do: "FileVault is off; turn it on
  to reach grafana", "sign in again to reach prod-db (last sign-in 13 h ago,
  policy requires 12 h)", "request access to billing". Never a silent timeout
  (G12).
- **Continuous, quiet re-checks.** Posture and session state are re-evaluated
  in the background. The user is asked to re-authenticate only when a policy
  requires fresher authentication than they have.
- **Instant connects.** The session to a connector is set up when a name
  resolves, before the app's first packet; that first packet is held, not
  dropped, while setup finishes.
- **Native and signed.** A signed, notarized menu-bar app with a packet tunnel
  provider in a NetworkExtension system extension.

**Clientless access** is a secondary, lower-assurance tier for HTTP(S) apps
that opt in: the relay is the HTTPS front end and proxies requests to the
connector. The user signs in through the control plane, which issues a
short-lived signed session assertion naming the user, the app, the sign-in
session, the IdP authentication time, whether MFA was used, and an expiry.
Before forwarding any request, the connector verifies that assertion against
the control plane's key, takes the authentication facts that policy checks
only from it, strips any identity
header the request carries, and passes the verified assertion to the app as
its identity header. A relay can neither mint nor extend an identity, and
revoking the session cuts it (G9). There is no device identity and the relay
sees the traffic in clear, which is why clientless is opt-in per app and why
device-posture conditions can never be satisfied by a clientless session.
Non-web clientless access (SSH, RDP, VNC in the browser) comes later.

## 7. Identity, devices and policy

### 7.1 Users

- Any OpenID Connect IdP. SAML IdPs connect through an OIDC bridge.
- Group membership comes from SCIM provisioning (or token claims where SCIM is
  unavailable) and changes apply through the revocation path (G9).
- IdPs that emit shared signals (the OpenID Shared Signals Framework: CAEP and
  RISC events) feed the same revocation path. IdP status polling arrives in
  v1.x for IdPs without them. The latency from an IdP-side change to warren is
  documented per IdP.
- warren never stores user passwords and never acts as an IdP.

### 7.2 Devices

- On enrollment the client creates a P-256 key in the Secure Enclave and
  registers its public key with the control plane (G3). Where the platform can
  attest that the key is hardware-bound, the device records that as its trust
  class.
- Device approval is automatic when an admin-defined rule matches (for
  example, MDM confirms the serial number) or manual by an admin.
- Access requires both a valid user and an approved device (G2). A device is
  bound to the users who enrolled it; disabling either cuts access.
- Each device gets stable tunnel addresses from the control plane, so flows
  are attributable even before audit enrichment.

### 7.3 Certificates

- After sign-in and a baseline posture check, the control plane issues a
  certificate that names both the user and the device and is bound to the
  device key. It lasts at most 4 hours and renews at half-life (G4).
- Renewal needs a live session, an enabled user, an approved and unrevoked
  device, and passing baseline posture. When the session reaches its maximum
  lifetime, or policy needs fresher authentication, the user signs in again in
  the browser.
- Relays, connectors and the control plane have their own short-lived
  certificates from a separate infrastructure CA, so a mis-issued client
  certificate can never impersonate infrastructure.

[protocol.md](protocol.md#10-certificate-profile) has the profile.

### 7.4 Posture

- macOS signals in v1: disk encryption (FileVault), firewall, minimum OS
  version, screen lock, and optionally MDM enrollment or a named security
  agent.
- Each signal carries a **trust class**: *device-reported* (observed by the
  client), *server-verified* (confirmed by an integration such as an MDM or
  security agent API), or *hardware-attested* (backed by a hardware attestation
  chain). Rules can require a minimum class per check.
- Posture is re-checked at least every 5 minutes and whenever the client sees
  a relevant change. The control plane turns each report into a signed posture
  statement that lasts at most 5 minutes; connectors verify it and treat every
  signal in an expired statement as failing (G11), so the bound holds at the
  connector even if the client stops reporting.
- A failing check cuts only the apps whose rules require it, and the user sees
  which check failed and how to fix it.

### 7.5 Policy

- **Default deny** (G1). A rule allows *who* (users, groups) to reach *what*
  (apps, or apps selected by label) under *conditions*: posture profiles,
  authentication and MFA freshness, and optionally source network or time
  windows. Deny rules exist for exceptions and always win.
- **Cedar is the engine.** The friendly YAML/CRD policy surface compiles to
  Cedar policies. Connectors evaluate the same compiled policy set that the
  console explains and simulates, so what the "why?" explorer shows is what
  enforcement does. Cedar's validation rejects malformed policy before it ships,
  and its analysis powers the simulator and change impact.
- **Policy as code** in a config directory or as CRDs, plus a console that
  shows which rule allowed or denied any decision and which condition failed.
- **Enforced per flow** at the connector (G7), and re-evaluated for live flows
  whenever policy, membership, posture, grants or revocations change.

[policy.md](policy.md) defines the schema and the Cedar mapping.

### 7.6 Just-in-time access

- Users request time-boxed access to an app with a reason. Approval is by a
  human approver or automatic under stated conditions; requesters never
  approve their own requests.
- A grant has a hard expiry that connectors enforce on their own clock, even
  without the control plane. Requests, approvals, denials, expiries and
  revocations are all audited with the stated reason.

### 7.7 Audit

- One OCSF-shaped JSON record per access decision, including denies, and one
  per flow (G13). Records carry the user, device, app, destination, decision,
  the rules that determined it, any failed condition, and the policy version.
- Sinks: stdout or file, OTLP, and syslog. The control plane keeps a
  searchable copy for the console's audit search and export.

## 8. Internal names and addressing

- **Synthetic addresses for names.** FQDN and wildcard apps resolve to
  synthetic IPs from a private pool. The client answers DNS for the names the
  user is entitled to and tells the connector which name each synthetic address
  stands for; the connector resolves that name's target (the name itself unless
  the app sets a separate one) inside the private network and translates
  addresses (NAT). No internal DNS data is exposed to the client
  beyond the user's own entitlements.
- **Names are claimed once.** Each connector group and each delegated source
  has a deployment-admin-owned scope of client-facing names. Every name has
  exactly one owning app across the deployment (an exact host first, otherwise
  the most specific matching wildcard), and the connector accepts a name only
  for that app, so a broader wildcard app never reaches a more specific app's
  name; a bind to the wrong app is rejected and audited. warren's own names
  (control plane, relays, IdP sign-in hosts) are reserved, so no app or cluster
  can take over a name another app or warren itself uses
  ([policy.md](policy.md#3-apps)).
- **CIDR and IP apps keep real addresses** and are routed as-is.
- **Split DNS.** On macOS the client claims only the internal DNS suffixes in
  use. Names outside them, and names under them that warren does not publish,
  resolve exactly as they would without warren.
- **Requestable apps.** Names of apps a user may request but cannot yet reach
  still resolve, so the connection fails with a "request access" reason instead
  of a lookup failure. Apps a user may neither reach nor request stay
  invisible: their names fail as a lookup failure, or, under a wildcard of an
  app the user can reach, with a reason from the connector that never names
  the other app.
- **Bypass detection.** Applications that use their own encrypted DNS (DNS over
  HTTPS or private DNS settings) bypass split DNS. The client detects such
  bypass for internal names and tells the user how to fix it instead of failing
  silently (G12).
- **Collision handling.** The synthetic pool is configurable; if it overlaps a
  local network the client picks a configured alternative and reports the
  conflict.

## 9. Kubernetes

- **Connectors as an operator.** A Helm chart installs the operator, which
  runs connector replicas as an outbound-only, highly available deployment.
  Nothing in the cluster needs to be exposed.
- **Publishing.** Annotate a Service, or create a small `App` CRD. Policies are
  CRDs too, so access is managed with GitOps like everything else in the
  cluster. The operator syncs them to the control plane and marks them as owned
  by the cluster (G19).
- **Identity-brokered `kubectl`.** A cluster can be published as a Kubernetes
  API app. The connector admits the user's API connection by policy like any
  other flow and forwards it to the **Kubernetes broker**, a separate component
  the operator runs as its own Deployment with its own service account. The
  broker terminates the connection, verifies the user's short-lived,
  session-bound credential, and forwards each request to the API server
  impersonating the user and their IdP groups, so cluster RBAC maps directly to
  IdP groups and the API server's audit log shows the real user. Only the
  broker's service account holds impersonation rights; connector pods hold
  none (G15). Impersonated groups carry a configurable prefix and the broker
  refuses any built-in system user or group. Kubernetes RBAC cannot restrict
  impersonation to a name prefix, so that refusal is a check in the broker, not
  in the cluster: the broker's service account can impersonate anyone,
  potentially a cluster administrator. Where the cluster supports constrained
  impersonation, the broker's grant uses it to narrow what impersonated
  requests may do. The generated kubeconfig contains no secret, only an exec
  credential plugin that obtains those credentials from the local client.
- **The control plane** runs on Kubernetes as a Deployment with PostgreSQL, or
  anywhere as one binary.
- **v1.x: workload access.** Pods reach warren apps elsewhere by presenting
  projected service-account tokens.
- **Later:** live session viewing and recording for `kubectl exec` and SSH.

## 10. Connectors

- **Anything reachable.** A connector, in-cluster or standalone, can expose
  FQDNs, wildcard domains, IPs and CIDR ranges, each scoped by port and
  protocol.
- **Declared scope.** Each connector group has a destination scope and a
  client-name scope; an app's targets must lie inside the first and its
  client-facing names inside the second, and resolved addresses for names must
  also fall inside the destination scope (G8).
- **Forwarding modes.** Kernel mode (TUN plus NAT, needing `NET_ADMIN`) comes
  first. A userspace TCP/IP mode for unprivileged pods follows, and becomes the
  Kubernetes default only after it passes a conformance and performance suite.
  Both modes sit behind one flow-admission layer; the forwarding backend never
  makes policy decisions.
- **One direction by default.** Flows start at the client. Server-initiated
  flows toward clients are off by default and opt-in per app.
- **High availability.** Connector groups run several replicas; relays spread
  new sessions across them and stop sending new sessions to a replica that is
  draining.

## 11. Revocation and failure behavior

**The revocation contract (G9).** When the control plane commits any of these
events, every live connection the event no longer permits is cut within
10 seconds at connectors and relays:

- a user disabled (by an admin, by SCIM, or by an IdP shared signal);
- a device disabled or revoked;
- a session or certificate revoked;
- a JIT grant expired or revoked;
- a policy or group-membership change that removes access.

The control plane pushes these events to every connector and relay over a
dedicated channel ([protocol.md](protocol.md#12-revocation-push-channel)).
Connectors and relays report when each event took effect, and the measured
commit-to-cut latency is a published metric and an integration test that gates
releases. The 10-second bound covers warren's side; the time an IdP takes to
tell warren is documented per IdP.

**Lifetimes.** Certificates last at most 4 hours and renew at half-life.
Posture is re-checked at least every 5 minutes. JIT grants carry their own
expiry.

**Control-plane outage (G10).**

- Connectors keep enforcing the last policy bundle they verified, including
  every revocation they have received.
- Nobody gains access: no certificate, device approval, grant or policy change
  can be issued without the control plane.
- Access decays: posture-gated access ends when posture statements expire
  (within 5 minutes plus a clock-skew allowance of at most 2 minutes), JIT
  grants end on time, and all access ends within one certificate lifetime
  (at most 4 hours).
- Clients show that the control plane is unreachable and when access will end.

**Other failures.** Losing a relay moves clients to another relay without
breaking inner sessions. Losing a connector replica resets the flows that ran
through it; clients re-establish sessions on another replica automatically.

## 12. Deployment

- **One binary, three roles** (control plane, relay, connector), on Kubernetes
  or anywhere, with an operator binary and Helm chart for clusters.
- **Storage.** SQLite embedded for small setups; PostgreSQL for high
  availability. One SQL layer and one migration set, tested against both.
- **Relays are stateless.** A new relay joins with one command and a
  single-use join token. Connectors join the same way.
- **No vendor dependency** (G18). Every component is self-hosted, and warren
  can run air-gapped.
- **Keys at rest.** CA and signing keys are encrypted at rest under a
  deployment key-encryption key; external KMS and HSM support can follow.
- **Upgrades.** Components negotiate protocol versions and support a stated
  version skew, so relays, connectors, control plane and clients can be
  upgraded independently.

## 13. Admin experience and configuration as code

- **One declarative schema**, exposed as CRDs and as a config directory. The
  CLI applies a directory with plan and diff, and the plan shows the access
  impact (who gains or loses access to what) before anything changes.
- **Ownership labels** record whether an object is managed from Git, a
  cluster, the console, the API or Terraform. Objects owned by Git or CRDs are
  read-only in the console (G19).
- **A stable, versioned admin API** with an OpenAPI specification, a full CLI,
  and in v1.x a Terraform/OpenTofu provider in its own repository.
- **The console:** a live overview; health of apps, connectors and relays;
  policies with the "why?" explorer and a simulator; devices; the JIT queue;
  audit search and export; and an end-user portal with clientless launch and
  JIT requests. Server-rendered Rust pages with hand-written JavaScript and
  CSS, and no npm toolchain.

## 14. Implementation decisions

- **Rust everywhere in the data path and control plane.** One shared core
  (tunnel engine, crypto configuration, policy enforcement, device identity)
  used by the client, relay and connector. The control plane and the kube-rs
  operator are Rust too. Native shells per OS stay thin: Swift on macOS first.
- **Crypto.** rustls on aws-lc-rs only; TLS 1.3 only; no hand-rolled
  cryptography (G16).
- **Transport stack.** quinn and rustls/aws-lc-rs, with warren's own
  CONNECT-UDP and CONNECT-IP layer over warren's own minimal HTTP/3 subset
  (no server push, no QPACK dynamic table): the published h3 crate cannot
  carry `:protocol = connect-ip`, which the inner session needs, so M1 took
  the option this decision left open. The HTTP/2 fallback uses the h2 crate.
  The MTU budget honors RFC 9484's 1280-byte floor.
- **Policy engine.** Cedar.
- **Dependencies.** A small allowlist of direct crates, every crate pinned and
  vendored, cargo-deny and cargo-vet in CI, and a per-binary closure report
  that fails CI on growth (G17). See [dependencies.md](dependencies.md).

### Workspace layout

| Crate | Role | Filled in |
| --- | --- | --- |
| `warren` | The single binary; one subcommand per role | M1 |
| `warren-core` | Shared data-path core | M1 |
| `warren-masque` | CONNECT-UDP, CONNECT-IP, capsules, HTTP/2 fallback | M1 |
| `warren-policy` | Policy schema and Cedar compilation | M1, M2 |
| `warren-client` | Client core linked by native shells (data path) | M1 |
| `warren-relay` | Relay role | M1 |
| `warren-connector` | Connector role | M1 |
| `warren-control` | Control plane role | M1 |
| `warren-console` | Web console (never in data-path builds) | M3 |
| `warren-operator` | Kubernetes operator, its own binary (never in data-path builds) | M2 |
| `warren-harness` | Test client, test PKI, stand-in apps and benchmarks; never shipped | M1 |

## 15. Roadmap

| Milestone | Scope | Done when |
| --- | --- | --- |
| **M0** Design and skeleton | These documents, the Rust workspace skeleton, the dependency policy in code, CI. | Merged; CI green. |
| **M1** Walking skeleton | In a homelab: control plane, relay, standalone connector, macOS app; one app reachable over CONNECT-IP inside the end-to-end inner QUIC session; policy evaluation with decision logs; HTTP/2 fallback; the benchmark suite. | A signed-in Mac reaches one internal app through a relay, every decision is logged, and benchmarks run in CI. |
| **M2** Kubernetes and the zero-trust core | Operator and Helm chart, CRDs and Service annotations, identity-brokered `kubectl`; device approval, posture with trust classes, continuous re-evaluation, the 10-second revocation contract and its test, outage behavior. | G2, G4, G7 to G11 and G15 hold under test. |
| **M3** Console, JIT, clientless | The console and end-user portal, the "why?" explorer and simulator, JIT access, clientless HTTP(S). | An admin can explain any decision; JIT and clientless work end to end. |
| **M4** v1.0 | Hardening, scale and performance against the v1 targets, documentation, and an external security audit. | Audit findings resolved; v1 targets met. |

After v1.0: Windows and Linux clients, IdP status polling, workload access,
and the Terraform/OpenTofu provider (v1.x); then mobile clients, direct
peer-to-peer paths, session recording, non-web clientless access, and opt-in
internet access security.

# warren policy

Status: the v1 policy surface, recorded at M0. The schema is `v1alpha1` until
v1.0 and may change before then; the principles below will not.

warren policy answers one question for every new connection: may this user,
on this device, in this state, reach this destination now? The answer is
**no** unless a rule says yes (G1 in [design.md](design.md#4-guarantees)).

People write policy in a small declarative schema, as files in a config
directory or as Kubernetes custom resources. warren compiles it to
[Cedar](https://www.cedarpolicy.com/), validates it, and ships the compiled
policy set to connectors, which enforce it per flow. The console's "why?"
explorer and simulator evaluate that same compiled set, so the explanation and
the enforcement can never disagree.

## 1. Objects

| Kind | Purpose | Usually written by |
| --- | --- | --- |
| `ConnectorGroup` | A set of connector replicas and the destinations they may reach | Deployment admins |
| `App` | Something people connect to: names, addresses, ports, protocols | App owners, or the operator from an annotated Service |
| `PostureProfile` | A named set of device checks | Security admins |
| `AccessPolicy` | Rules: who may reach what, under which conditions | App owners and security admins |
| `AccessRequestPolicy` | Just-in-time access: who may request what, who approves, for how long | App owners and security admins |

Every object has the same envelope in both forms:

```yaml
apiVersion: warren.dev/v1alpha1   # API group name is provisional until v1.0
kind: App
metadata:
  name: grafana
  labels:
    env: prod
spec: {}
```

The schema is identical in a config directory and as CRDs; the CRD form is the
same document applied to a cluster.

## 2. Connector groups and their scope

A connector group's `destinations` bound everything its apps may point at. An
app whose targets fall outside its group's scope is rejected at compile time,
and at run time a connector refuses any resolved address outside the scope
(G8). A domain is an exact name or a single leading wildcard, `*.` followed by
a domain, which matches names with one or more labels in its place:
`*.svc.cluster.local` matches `grafana.observability.svc.cluster.local` but
not `svc.cluster.local` itself.

```yaml
apiVersion: warren.dev/v1alpha1
kind: ConnectorGroup
metadata:
  name: homelab
spec:
  destinations:
    domains: ["*.lab.example.com", "nas.example.internal"]
    cidrs: ["10.20.0.0/16", "fd00:20::/48"]
  relays: all          # or a list of relay names
```

A cluster's connector group is created when the operator is installed, with a
default scope of the cluster's own Service network and `*.svc.cluster.local`
(or the cluster's configured domain), which covers every Service's cluster DNS
name, `<service>.<namespace>.svc.cluster.local`.
Widening a scope is a deployment-admin change, never something a cluster can do
for itself.

## 3. Apps

An app is a set of destinations served by one connector group. Destinations are
host names (exact or a single leading wildcard, matching as in
[section 2](#2-connector-groups-and-their-scope)), IP addresses or CIDR ranges,
each with ports and a protocol. A `host` is the name clients use; an exact host
may set a separate `target`, the name or address the connector actually
reaches. Without one the target is the host itself.

```yaml
apiVersion: warren.dev/v1alpha1
kind: App
metadata:
  name: grafana
  labels: { env: prod, team: observability }
spec:
  connectorGroup: homelab
  destinations:
    - host: grafana.lab.example.com
      ports: [443]
      protocol: tcp
  discoverable: true          # visible in the portal and requestable; default false
  clientless:                 # optional, HTTP(S) only in v1
    url: https://grafana.access.example.com
    upstream: https://grafana.lab.example.com
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata:
  name: lab-network
spec:
  connectorGroup: homelab
  destinations:
    - cidr: 10.20.0.0/24
      ports: ["22", "8000-8100"]
      protocol: tcp
    - cidr: 10.20.0.0/24
      protocol: icmp
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata:
  name: lab-web
spec:
  connectorGroup: homelab
  destinations:
    - host: "*.lab.example.com"
      ports: [80, 443]
      protocol: tcp
  serverInitiatedFlows: false # default; true lets servers open flows to clients
```

Field notes:

- `protocol` is `tcp`, `udp`, `icmp` or `any`; `ports` is omitted for `icmp`
  and `any`. Omitting `ports` for `tcp` or `udp` means every port, which the
  compiler flags as a warning.
- Host names use synthetic addresses on the client; the connector resolves
  each destination's target inside the private network
  ([design.md](design.md#8-internal-names-and-addressing)). Targets, not
  client-facing hosts, must lie inside the connector group's scope.
- `clientless.upstream` is the URL the connector forwards clientless requests
  to; its host must be one of the app's destination targets.
- `discoverable: true` makes the app visible to users who may request it, so a
  connection attempt fails with a "request access" reason instead of a lookup
  failure.

### Kubernetes API apps

A cluster API published for identity-brokered `kubectl` (G15):

```yaml
apiVersion: warren.dev/v1alpha1
kind: App
metadata:
  name: prod-cluster
spec:
  connectorGroup: prod-cluster
  kubernetes:
    apiServer: https://kubernetes.default.svc.cluster.local
    groupPrefix: "warren:"    # IdP group "sre" is impersonated as "warren:sre"
```

The connector admits the user's API connection by policy and forwards it to
warren's Kubernetes broker, a separate in-cluster component that alone holds
impersonation rights. The broker impersonates the user (`Impersonate-User`)
and their IdP groups with the prefix (`Impersonate-Group`), and refuses any
user or group name in the `system:` namespace. Cluster RBAC then binds roles
to the prefixed groups. Kubernetes RBAC cannot restrict impersonation to a
prefix, so that refusal is enforced by the broker, not by the cluster, and a
compromised broker can impersonate anyone its service account may
([threat-model.md](threat-model.md#t13-abuse-of-kubernetes-impersonation)).

### Publishing a Service

In a cluster, annotating a Service publishes it through the cluster's
connector group. The operator turns the annotation into an `App` it owns, with
the annotated hostname as each destination's `host` and the Service's cluster
DNS name, here `grafana.observability.svc.cluster.local`, as its `target`.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: observability
  annotations:
    warren.dev/publish: "true"
    warren.dev/app: grafana                      # default: <namespace>-<service>
    warren.dev/hostname: grafana.prod.internal   # name clients use
    warren.dev/ports: "443"                      # default: every Service port
    warren.dev/labels: "env=prod,team=observability"
```

## 4. Posture profiles

A posture profile is a list of checks, each against one signal, with a minimum
trust class: `device-reported` (observed by the warren client),
`server-verified` (confirmed by an integration such as an MDM or a security
agent's API) or `hardware-attested` (backed by a hardware attestation chain).

```yaml
apiVersion: warren.dev/v1alpha1
kind: PostureProfile
metadata:
  name: managed-mac
spec:
  platform: macos
  checks:
    - signal: diskEncryption          # FileVault
      remediation: Turn on FileVault in System Settings > Privacy & Security.
    - signal: firewall
    - signal: osVersion
      minimum: "15.4"
    - signal: screenLock
      maxIdle: 5m
    - signal: mdmEnrolled
      minTrust: server-verified       # default for mdmEnrolled and securityAgent
    - signal: securityAgent
      name: corp-agent                # an integration configured on the control plane
```

The default `minTrust` is `device-reported`. A signal is **stale** once the
posture statement carrying it has expired: a statement lasts at most
5 minutes from the oldest observation it carries
([protocol.md](protocol.md#14-named-parameters), `POSTURE_STATEMENT_LIFETIME`),
and a connector accepts it for at most `CLOCK_SKEW_ALLOWANCE` beyond that on
its own clock. A stale signal counts as failing (G11). The optional
`remediation` text is shown to the user when the check blocks them.

## 5. Access policies

An `AccessPolicy` holds rules. A rule names **who**, **what**, and optional
**when** conditions, all of which must hold. Rules allow by default; a rule
with `effect: deny` carves out an exception and always wins over allows.

```yaml
apiVersion: warren.dev/v1alpha1
kind: AccessPolicy
metadata:
  name: observability
spec:
  rules:
    - name: engineers-view-grafana
      who:
        groups: [engineering]
      what:
        apps: [grafana]
      when:
        posture: [managed-mac]
        auth: { maxAge: 12h, mfa: true }
        via: [client, browser]        # default [client]; browser = clientless

    - name: contractors-office-hours
      who:
        groups: [contractors]
      what:
        appSelector: { matchLabels: { team: observability } }
      when:
        posture: [managed-mac]
        schedule:
          timezone: Europe/Berlin
          windows: [{ days: [mon, tue, wed, thu, fri], from: "08:00", to: "19:00" }]
        network:
          sourceCidrs: ["203.0.113.0/24"]   # relay-observed public address

    - name: no-contractors-on-prod
      effect: deny
      who:
        groups: [contractors]
      what:
        appSelector: { matchLabels: { env: prod } }
```

| Part | Fields |
| --- | --- |
| `who` | `users` (IdP identifiers or emails), `groups` (IdP groups). At least one is required; there is no implicit "everyone". |
| `what` | `apps` (names), `appSelector.matchLabels`. |
| `when.posture` | Posture profiles that must all pass. |
| `when.auth` | `maxAge` since the user last authenticated at the IdP; `mfa: true` requires that sign-in to have used MFA. |
| `when.via` | `client` (device tunnel) and/or `browser` (clientless). A `browser` session has no device, so a rule with `posture` never matches it. |
| `when.schedule` | Weekly windows in a named time zone. |
| `when.network` | Source CIDRs, matched against the client's public address as observed by the relay. Trust it as much as you trust your relays, and never as the only condition. |

Some things hold before any rule and no rule can change them (G1): the client
certificate is valid and unrevoked, the device is approved, the destination is
inside both the app and its connector group's scope, and the flow is
client-initiated unless the app allows otherwise.

## 6. Just-in-time access

An `AccessRequestPolicy` says who may request time-boxed access to which apps,
who approves, and for how long.

```yaml
apiVersion: warren.dev/v1alpha1
kind: AccessRequestPolicy
metadata:
  name: prod-db-break-glass
spec:
  who:
    groups: [sre]
  what:
    apps: [prod-db]
  approval:
    approvers: { groups: [sre-leads] }
    minApprovals: 1
    automatic:                       # optional: approve without a human when these hold
      when:
        schedule:
          timezone: UTC
          windows: [{ days: [mon, tue, wed, thu, fri], from: "06:00", to: "18:00" }]
  requireReason: true
  maxDuration: 4h
  defaultDuration: 1h
  when:                              # must hold to request, and for the whole grant
    posture: [managed-mac]
    auth: { maxAge: 1h, mfa: true }
```

- A requester can never approve their own request, whatever the approver list
  says.
- An approval creates a **grant**: runtime state owned by the control plane, not
  an authored object. It names the user, app, reason, approvers and expiry, is
  visible through the API, CLI and console, and is enforced on each connector's
  own clock, so it ends on time even during a control-plane outage.
- Requests, approvals, denials, expiries and revocations are all audited with
  the stated reason. Revoking a grant cuts live connections within 10 seconds
  (G9).

## 7. Ownership and delegation

Every object carries ownership labels:

| Label | Meaning |
| --- | --- |
| `warren.dev/managed-by` | `git` (a config directory applied by the CLI), `kubernetes` (CRDs or annotations through the operator), `console`, `api` or `terraform` |
| `warren.dev/source` | Where it came from: repository path, or cluster and namespace |

- Objects managed by anything other than `console` are read-only in the
  console (G19). The CLI refuses to modify an object owned by another manager
  unless told to take ownership explicitly, and that change is audited.
- **Delegation.** The control plane gives each source a scope. By default a
  cluster's operator may define apps only inside its own connector group's
  scope, and its policies may grant access only to apps that cluster
  publishes. Kubernetes RBAC on the CRDs then decides who in the cluster can
  change them. A namespace owner can therefore never grant access to anything
  outside what their cluster serves.
- `warren plan <dir>` shows the object diff and the access impact (which users
  would gain or lose access to which apps) before `warren apply <dir>` changes
  anything.

## 8. Compilation to Cedar

### 8.1 Schema

The compiler generates a Cedar schema for each policy set. Its core is:

```cedarschema
namespace Warren {
  entity Group;
  entity User in [Group] { email: String };
  entity AutoApprover;                      // warren's built-in automatic approver
  entity AppLabel;                          // one entity per "key=value" label
  entity App in [AppLabel] { connectorGroup: String };

  type Signal = { ok: Bool, trust: Long };  // trust: 1 device-reported,
                                            // 2 server-verified, 3 hardware-attested
  type Device = {
    id: String,
    signals: {
      diskEncryption?: Signal,
      firewall?: Signal,
      osVersion?: { value: Long, trust: Long },          // 15.4.0 -> 150400
      screenLock?: { ok: Bool, trust: Long, maxIdleSeconds: Long },
      mdmEnrolled?: Signal,
      securityAgent?: { names: Set<String>, trust: Long },
    },
  };
  type Context = {
    via: String,                            // "client" or "browser"
    device?: Device,                        // absent for browser sessions
    auth: { ageSeconds: Long, mfa: Bool },
    network?: { source: ipaddr },           // relay-observed
    time: { utcMinuteOfWeek: Long },        // plus one field per referenced time zone
    grants: Set<App>,                       // the user's unexpired JIT grants
  };

  action connect appliesTo { principal: [User], resource: [App], context: Context };
  action request appliesTo { principal: [User], resource: [App], context: Context };
  action approve appliesTo {
    principal: [User, AutoApprover],
    resource: [App],
    context: { requester: User, request: Context },
  };
}
```

The schema and the policy examples in this section validate in Cedar's strict
mode with the Cedar 4.13 CLI.

The enforcement point builds the request: the principal and groups from the
signed entity snapshot, the device and its signals from the latest verified
posture statement (dropping every signal once that statement is stale, as
defined in [section 4](#4-posture-profiles), so a stale signal is simply
absent and every check on it fails), authentication facts from the
certificate, and grants from the snapshot filtered by expiry on the local
clock.

### 8.2 Rules

Each rule compiles to exactly one Cedar policy. The policy ID is the rule's
path, `<policy>/<rule>`, and an `@source` annotation records the file and line
or the CRD it came from, so every decision points back to what a person wrote.

`observability/engineers-view-grafana` from [section 5](#5-access-policies)
compiles to:

```cedar
@id("observability/engineers-view-grafana")
@source("config/policies/observability.yaml:6")
permit (
  principal in Warren::Group::"engineering",
  action == Warren::Action::"connect",
  resource == Warren::App::"grafana"
)
when {
  (context.via == "client" || context.via == "browser") &&
  // posture profile managed-mac
  context has device &&
  context.device.signals has diskEncryption &&
  context.device.signals.diskEncryption.ok &&
  context.device.signals has firewall &&
  context.device.signals.firewall.ok &&
  context.device.signals has osVersion &&
  context.device.signals.osVersion.value >= 150400 &&
  context.device.signals has screenLock &&
  context.device.signals.screenLock.ok &&
  context.device.signals.screenLock.maxIdleSeconds <= 300 &&
  context.device.signals has mdmEnrolled &&
  context.device.signals.mdmEnrolled.ok &&
  context.device.signals.mdmEnrolled.trust >= 2 &&
  context.device.signals has securityAgent &&
  context.device.signals.securityAgent.names.contains("corp-agent") &&
  context.device.signals.securityAgent.trust >= 2 &&
  // auth freshness
  context.auth.mfa &&
  context.auth.ageSeconds <= 43200
};
```

Because the posture profile requires a device, this rule can never match a
browser session even though it lists `browser`; the compiler warns about such
rules.

A label selector becomes membership in a label entity, and a deny rule becomes
a `forbid`, which Cedar always lets win over any `permit`:

```cedar
@id("observability/no-contractors-on-prod")
forbid (
  principal in Warren::Group::"contractors",
  action == Warren::Action::"connect",
  resource in Warren::AppLabel::"env=prod"
);
```

Network and schedule conditions compile to range checks:

```cedar
context has network &&
context.network.source.isInRange(ip("203.0.113.0/24")) &&
// minutes since Sunday 00:00 in Europe/Berlin: Monday 08:00 to 19:00, then
// one such range per listed day
context.time.europe_berlin >= 1920 && context.time.europe_berlin < 2580
```

### 8.3 Just-in-time access

`prod-db-break-glass` from [section 6](#6-just-in-time-access) compiles to three
policies, plus one for automatic approval:

```cedar
@id("prod-db-break-glass/request")
permit (
  principal in Warren::Group::"sre",
  action == Warren::Action::"request",
  resource == Warren::App::"prod-db"
)
when {
  // managed-mac checks as in section 8.2, then:
  context.auth.mfa && context.auth.ageSeconds <= 3600
};

@id("prod-db-break-glass/approve")
permit (
  principal in Warren::Group::"sre-leads",
  action == Warren::Action::"approve",
  resource == Warren::App::"prod-db"
)
when { context.requester != principal };

@id("prod-db-break-glass/connect")
permit (
  principal in Warren::Group::"sre",
  action == Warren::Action::"connect",
  resource == Warren::App::"prod-db"
)
when {
  context.grants.contains(resource) &&
  // managed-mac checks as in section 8.2, then:
  context.auth.mfa && context.auth.ageSeconds <= 3600
};
```

Automatic approval compiles to an `approve` policy whose principal is warren's
built-in automatic approver, conditioned on the `automatic.when` clause as
evaluated for the request:

```cedar
@id("prod-db-break-glass/approve-automatic")
permit (
  principal == Warren::AutoApprover::"automatic",
  action == Warren::Action::"approve",
  resource == Warren::App::"prod-db"
)
when {
  // minutes since Sunday 00:00 UTC: Monday 06:00 to 18:00, then one such
  // range per listed day
  context.request.time.utcMinuteOfWeek >= 1800 &&
  context.request.time.utcMinuteOfWeek < 2520
};
```

### 8.4 Validation

- The compiled set is validated against the generated schema in Cedar's strict
  mode before it is signed and shipped. Any error is reported against the
  YAML file and line or CRD that produced it.
- The compiler also rejects references to unknown apps, groups or profiles,
  apps outside their connector group's scope, and objects outside their
  source's delegation scope; and it warns about rules that can never match.

## 9. Explaining decisions

Every decision is explainable by named rules and named conditions (G12):

- **Allows** name the `permit` policies that determined them.
- **Denies by a rule** name the `forbid` that matched.
- **Default denies** (no rule allowed) list the candidate rules, the ones
  whose `who` and `what` match the request, with the first condition each one
  failed. The compiler keeps each rule's conditions as separate expressions so
  the explainer can evaluate them one at a time.

The connector turns the failing condition into the reason code and message the
user sees ([protocol.md](protocol.md#7-flow-admission-and-deny-signalling)):

| Failing condition | Reason code | What the user sees |
| --- | --- | --- |
| no candidate rule; app requestable | `request_access` | "You don't have access to prod-db. Request access." |
| no candidate rule | `no_rule` | "No policy allows you to reach lab-network." |
| a `forbid` matched | `no_rule` | "Access to billing is blocked by policy." |
| posture check | `posture_failed` | "FileVault is off. Turn on FileVault in System Settings to reach grafana." |
| `auth.maxAge` | `reauth_required` | "Sign in again to reach prod-db (last sign-in 13 h ago; policy requires 1 h)." |
| `auth.mfa` | `mfa_required` | "Sign in again with multi-factor authentication to reach prod-db." |
| `schedule` | `outside_schedule` | "lab-web is available Mon-Fri 08:00-19:00 Europe/Berlin." |
| `network` | `network_not_allowed` | "grafana isn't available from this network." |
| grant expired | `grant_expired` | "Your access to prod-db ended at 14:05. Request access again." |

The console's "why?" explorer shows the same explanation for any audited
decision, and the simulator evaluates hypothetical requests, or replays recent
real decisions, against the current or a proposed policy set. Cedar's
validation and analysis tooling backs the plan's access-impact report.

## 10. Audit of policy

Every policy change, from any source, is audited with its author, source and
the compiled policy-set version. Every access decision records the policy-set
version it was made under and the IDs of the policies that determined it, so
any past decision can be re-explained exactly.

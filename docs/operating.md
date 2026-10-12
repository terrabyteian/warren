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
certificate serves the web console ([console.md](console.md)), browser
sign-in and enrollment only (discovery, `/v1/auth/*` and `/v1/devices`);
every other call made at `publicUrl`'s host is refused with
`421 misdirected_request`. So `tls` needs at least one name in `dnsNames`
besides `publicUrl`'s host that reaches the control plane from
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
`warren admin deployment` prints the deployment root's fingerprint, which
clients pin with `warren login --fingerprint` ([macos.md](macos.md)) and MDM
profiles preset.

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

Built-in account sign-ins have a limit of their own per source:
`localAccounts.maxFailuresPerSource` failed passwords and codes per 15
minutes, 20 by default, after which the source is refused until the window
ends; each account's own lockout applies regardless. Raise it for a large
office behind one address, or set it to 0 where every client shares one, so
a few mistyped passwords do not lock everyone out.

```yaml
connections:
  maxPerSource: 64           # 0: no limit
  trustedProxies: [192.0.2.10, 192.0.2.11]   # the load balancer's own addresses
localAccounts:
  maxFailuresPerSource: 20   # 0: no per-source limit
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
still empty, connect once from a test client, and the warning the control
plane logs names the source address it sees for that connection. Then
follow the bullets below: if that is the test client's own address, turn
PROXY protocol off again; only an address that is not one of the test
client's can be the balancer's own.

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
  per-source limits would see every peer as that address, so set
  `connections.maxPerSource` and `localAccounts.maxFailuresPerSource` to 0.

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

## Accounts and sign-in

People sign in with built-in warren accounts, through the organization's
identity provider, or both. Built-in accounts are on unless
`localAccounts.enabled` is `false`, which needs an `idp`. When an IdP is
configured and no built-in account exists, sign-in goes straight to the IdP;
once one exists, the sign-in page offers both.

### The first admin

The first admin is created from a mounted secret holding its password, on
the first start that finds no built-in account. Later starts never read the
file again, so it can be deleted once the admin has signed in, and deleting
the admin never brings it back.

```yaml
localAccounts:
  bootstrapAdmin:
    username: admin                          # default admin
    passwordFile: /etc/warren/admin-password # at least 12 characters
    groups: [admins]                         # default [admins]; local:admins in policy
```

The admin signs in from the warren app or the web console with that password
and is asked to set up an authenticator app (any TOTP app) at once; the
recovery codes shown then are the way back in if the phone is lost. Policy
grants the admin access like anyone else, for example with
`who: { groups: ["local:admins"] }`, and `console.admins` makes them a
console admin the same way ([console.md](console.md#setting-it-up)).

**On a host,** write the password with no other content, readable only by the
control plane's user, and remove it after the first sign-in:

```sh
install -m 0600 -o warren /dev/null /etc/warren/admin-password
openssl rand -base64 24 > /etc/warren/admin-password   # or a passphrase you choose
```

**On Kubernetes,** keep the password in a Secret and name it in the chart's
`controlPlane.bootstrapAdmin.existingSecret`, which mounts it and sets
`localAccounts.bootstrapAdmin` ([kubernetes.md](kubernetes.md#the-first-admin)).

### Managing built-in accounts

```sh
warren admin users create ada --email ada@example.com --group ops
#   prints a one-time setup link (valid 72 hours); give it to Ada over a channel you trust
warren admin users groups ada --group ops --group oncall   # her local groups, exactly
warren admin users disable ada      # cuts her connections within 10 seconds
warren admin users reset ada        # clears password and authenticator, revokes sessions, new link
warren admin users unlock ada       # after 5 failed attempts in a row (or wait 15 minutes)
warren admin users delete ada       # cuts her connections; the username can be reused
warren admin groups list
```

Accounts and groups can also be declared in the policy directory as
`LocalUser` and `LocalGroup` objects ([policy.md](policy.md#51-users-and-groups));
those change only there. A declared account has no password until
`warren admin users reset <name>` prints its setup link.

### Google sign-in

```yaml
idp:
  type: google
  clientId: 123456789012-abc.apps.googleusercontent.com
  clientSecretFile: /etc/warren/google-client-secret
  hostedDomain: example.com            # optional: only accounts of this Workspace domain
  allowedEmails: [contractor@gmail.com] # optional: and these addresses
```

The issuer, endpoints and scopes are preset. Only accounts whose email Google
has verified can sign in; with `hostedDomain` or `allowedEmails`, only accounts
of that Workspace domain (by Google's `hd` claim) or on that list. Without
either, any Google account can sign in and enroll a device, though it reaches
nothing until policy names it.

To create the OAuth client:

1. In the Google Cloud console, open **APIs & Services**, then **OAuth consent
   screen**, and configure it (**Internal** limits it to your Workspace).
2. Under **Credentials**, choose **Create credentials**, then **OAuth client
   ID**, with application type **Web application**.
3. Add the authorized redirect URI `https://<publicUrl host>/v1/auth/callback`,
   exactly, including any port.
4. Save the client ID in `clientId` and the client secret, alone, in the file
   `clientSecretFile` names.

Google accepts redirect URIs only with `https` on a host name under a public
top-level domain (such as `warren.example.com`), or on `localhost`; it refuses
raw IP addresses and private suffixes such as `.local`, `.lan`, `.internal` or
`.home.arpa`. The name need not be reachable from the internet: the redirect
happens in the user's browser, which only has to reach the control plane.

Google ID tokens carry no groups, so Google users get warren's own: assign them
after a first sign-in (`warren admin users groups <email> --group ops`), or
list their address beforehand under `members.emails` of a `LocalGroup` in the
policy directory ([policy.md](policy.md#51-users-and-groups)), which binds to
the first account that signs in with it. Google
reports neither MFA nor when the user signed in, so rules with `auth.mfa` or
`auth.maxAge` never match Google sign-ins; enforce two-step verification in
Google Workspace, and give apps that need such rules to built-in accounts or an
IdP that reports both.

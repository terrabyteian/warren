# The web console

The control plane serves a web console at `https://<publicUrl>/console/`.
This first version is read-mostly: it shows the deployment's state and lets
admins approve and revoke devices and disable and enable users. Everyone who
signs in sees the apps open to them. It is the start of the console in
[design.md](design.md#13-admin-experience-and-configuration-as-code); the
policy simulator, the JIT queue, audit search and clientless launch come
later in M3.

## Setting it up

The console needs nothing beyond a running control plane, plus:

1. **A certificate browsers trust** for the organization URL (`tls.certFile`
   and `tls.keyFile`, see [operating.md](operating.md#tls-certificates)).
   Without one, the browser shows a certificate warning.
2. **The IdP redirect URI** `https://<publicUrl>/v1/auth/callback`, if an
   IdP is configured: already registered for the warren app. The console
   signs in through the same callback.
3. **Admins**, named in the control-plane configuration. Nobody is an admin
   by default, not even the bootstrap admin: name its group,
   `local:admins` by default.

```yaml
console:
  admins:
    users: [ada@example.com]      # by email (any case), IdP subject, built-in username or warren user ID
    groups: [warren-admins, "local:admins"]  # by IdP group, or local:<group> for warren's own groups
  sessionLifetime: 12h            # default 12h, at most 24h
  changeMaxAge: 1h                # default 1h: how recent a sign-in changes need
```

Open `https://<publicUrl>/` in a browser and sign in.

### Signing in

The sign-in page offers what the deployment has:

- **An IdP only:** **Continue to sign in** goes to the IdP.
- **Built-in accounts only:** a username and password form.
- **Both,** once a built-in account exists: **Sign in with** the IdP, or the
  form.

A built-in account signs in to the console exactly as it does in the warren
app ([protocol.md](protocol.md#111-client-to-control-plane-link-d)): its password, then a code from
its authenticator app or a single-use recovery code, enrolling the
authenticator first if the account has none, so the bootstrap admin can
start in the console. The same checks apply: the same answer for an unknown
username, a locked account, a wrong password and a disabled account's right
password; the lockout after five failures in a row; and
`localAccounts.maxFailuresPerSource`, which counts console and warren app
sign-ins together. Such a sign-in is multi-factor and authenticated when it
finishes, so it may make changes for `console.changeMaxAge`.

### MFA and your identity provider

Every admin may read the admin pages. Changes need a multi-factor sign-in
(threat model [T5](threat-model.md)). A built-in account's always is. One
through the IdP is when the IdP reports it: the ID token's `amr` must hold
a value from `idp.mfaAmrValues` (default `mfa`), or its `acr` one from
`idp.mfaAcrValues`. An admin whose sign-in does not
qualify sees disabled buttons, a notice and a **Sign in again** button that
asks the IdP for a fresh sign-in, or the step-up below; a change they post
is refused with a page saying why.

Some IdPs, Google among them, do not report MFA in the ID token at all. If
yours reports a second factor under other `amr` or `acr` values, list them
in `idp.mfaAmrValues` or `idp.mfaAcrValues`. If it reports none, its admins
step up with warren's own authenticator. MFA is never optional for changes.

### Step-up with a built-in account's authenticator

An admin signed in through the IdP whose sign-in reports no MFA, or no
`auth_time`, or is too old, confirms with the authenticator code of their
built-in account instead of signing in again: the notice offers **Confirm
with your authenticator code** (`/console/step-up`). The code counts as a
multi-factor authentication at that moment, so changes are allowed for
`console.changeMaxAge`; then the admin confirms again. It belongs to that
console session only, and signing out ends it.

Their built-in account is the one that is enabled, not deleted, has an
authenticator, and has the IdP's verified email as its email (in any
case). If no such account exists, or more than one does, there is no
step-up. To set one up, create a built-in account with the admin's email
(`warren admin users create <username> --email <email>`, or a `LocalUser`
in the policy directory) and have the admin sign in with it once, in the
console or the warren app, to enroll the authenticator. The account itself
needs no admin rights; the console still decides those from the IdP
sign-in.

The step-up takes authenticator codes only, not recovery codes, and
counts against the account exactly as a sign-in does: each code once, the
lockout after five failures in a row (which also stops the account's
sign-ins), and `localAccounts.maxFailuresPerSource`.

**Trust.** The binding is the built-in account's email, which an admin set
and warren does not verify, the same trust `console.admins.users` already
places in email addresses. Whoever can set a built-in account's email
(through the admin socket, or the policy directory) can choose whose IdP
sign-ins its authenticator steps up, so treat those as admin powers
([threat model T5](threat-model.md#t5-control-plane-compromise)).

### How recent a sign-in is

Changes also need the admin to have authenticated within
`console.changeMaxAge`: a built-in account when its sign-in finished, an IdP
sign-in when the ID token's `auth_time` says.
**Sign in again** asks the IdP for `prompt=login` and a `max_age` of
`console.changeMaxAge` (or the policy's shortest `auth.maxAge`, if shorter),
which ask it to authenticate the admin afresh and to report `auth_time`.

Some IdPs, Google among them, may leave `auth_time` out. A console sign-in
that sent `prompt=login` then counts as authenticated when its callback
arrives, provided the ID token carries the sign-in's nonce and was issued
(`iat`) no earlier than the sign-in started. Any other sign-in without
`auth_time`, such as a plain one that may have reused the IdP's session,
counts as never recent enough for changes. The warren app's sign-ins never
infer `auth_time` this way.

## Pages

| Page | Who | What it shows |
| --- | --- | --- |
| Overview `/console/` | admins | Users, devices by status, devices holding a current certificate, devices that reached an app in the last 15 minutes, every relay and connector with its health, the policy in force, revocation latency, and the latest denies. Refreshes every 15 seconds. |
| Users & groups `/console/users` | admins | Every user with their groups, devices, last sign-in and status, with **Disable** and **Enable**; every group with its members and the policy rules that name it. |
| Devices `/console/devices` | admins | Every device, pending first, with its users, platform, key storage and trust class, tunnel addresses and current certificate, filterable by status, with **Approve** (pending devices) and **Revoke**. |
| Apps `/console/apps` | admins | Every app with its destinations, connector group, labels and the rules that name it; every connector group with its scope and its connectors' health. |
| Policies `/console/policies` | admins | Every access policy and rule (who, what, when, where it is defined), errors from the last load, warnings, and the compiled Cedar policy set. |
| Decisions `/console/decisions` | admins | The newest access decisions connectors reported, allowed and denied, with who, which device, the app and destination, the reason and the connector. |
| Why? `/console/decisions/{id}` | admins | One decision: what the user saw, what the reason means, the rules that decided it as the policy in force defines them, each condition with the one that failed marked, and the audit record. |
| My apps `/console/me` | everyone | The apps the signed-in user may reach or request, the names and ports to use, and their devices. |

**Health.** A relay or connector is *connected* while its revocation event
stream to the control plane is open; otherwise the page shows when it was
last seen (its stream closing, or its last acknowledgement of an event). The
control plane does not see client tunnels, so the overview counts devices
holding a current user+device certificate and devices that reached an app
recently instead.

**Recent decisions** are kept in memory: the newest 2,000 the connectors
reported since the control plane started. The audit log keeps every record;
audit search over it comes with M3.

## What changes, and what does not

The console makes four changes, through the same code as the admin API
(`warren admin`), so each one is audited and pushes the same revocation:

- **Approve** a pending device.
- **Revoke** a device. Its connections are cut within seconds and it can
  never enroll with that key again.
- **Disable** a user. Their sessions and certificates stop working within
  seconds, their console session ends, and their sign-ins are refused.
- **Enable** a user again.

Admins cannot disable or enable themselves from the console. Audit records
of console changes name the admin as the actor with `app_name: warren
console`.

Everything else is read-only. Policy, apps and connector groups are managed
in Git (the policy directory, or CRDs later) and are marked so: change them
there and reload with `warren admin policy reload` or SIGHUP.

Changes need a multi-factor sign-in within `console.changeMaxAge` (default
one hour) of the admin authenticating (see
[MFA and your identity provider](#mfa-and-your-identity-provider)). Other
admin sign-ins can still look around; their buttons are disabled and a
notice offers **Sign in again**: at the IdP for an IdP sign-in, on the
sign-in page's form for a built-in account, or **Confirm with your
authenticator code** when an IdP sign-in can step up. If the console session ended before a
change, signing in again returns to the page the change was made from.

## Security

- **Sign-in** goes through the IdP with PKCE, like the warren app's. The
  auth request is bound to the browser that started it by a short-lived
  `__Host-warren-login` cookie, so a sign-in someone else started cannot
  finish in your browser. After sign-in the browser only returns to a
  `/console` path.
- **Built-in account sign-in** posts the sign-in page's form with a token
  derived from that same cookie, refused from another origin like every
  console form, so no other site can sign a browser in. The password goes
  through the one check the warren app's sign-in uses; the code and
  enrollment steps are the warren app's own pages, bound to the browser by
  their `__Host-warren-signin` cookie (`SameSite=Strict`) and refused from
  another origin ([threat model T18](threat-model.md#t18-attacks-on-built-in-accounts)).
- **Step-up** posts a console form like any other (session form token,
  origin checks) and goes through the same code check as a built-in
  account's sign-in; its time is stored on the console session.
- **Sessions** are a random 256-bit token in a `__Host-warren-console`
  cookie: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, host-only, lasting
  `console.sessionLifetime`. The database keeps only its hash. The session
  and the user are checked on every request, so signing out or disabling the
  user ends it at once. Console sessions are separate from the warren app's
  device-bound sessions.
- **Forms** carry a token derived from the session token (before sign-in,
  from the sign-in cookie), compared in constant time, and are refused if
  the browser reports another origin (`Origin` or `Sec-Fetch-Site`).
- **Pages** are rendered on the server, escaping every value (users, groups,
  device names, connector records) on the way into the markup. They send a
  strict content security policy (`default-src 'none'`, scripts, styles and
  fetches from the console's own origin only, no inline script or style, no
  framing, forms posting only to the console), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and
  `Cache-Control: no-store`.
- **No toolchain.** The pages are Rust in `crates/warren-console`, with one
  hand-written stylesheet and one small script, which only enhances: every
  page works without it. The crate renders only; the control plane gathers
  the data and decides who may see it. It adds no dependency (see below),
  and stays out of every data-path build.

### Why no templating crate

The pages use a small template macro in `warren-console`
(`warren_console::html!`) that escapes every argument unless it is already
markup, instead of a templating crate. A crate such as maud or askama would
bring proc-macro dependencies into the control plane's closure for what
about a hundred lines do here, against the dependency policy
([dependencies.md](dependencies.md)). The macro passes each template
through `concat!`, so an inline format capture such as `{name}`, which
would skip escaping, is a compile error.

## Routes

The console is served on the HTTPS listener, beside the API:

| Route | What it does |
| --- | --- |
| `GET /` | Redirects to the console. |
| `GET /console/` | The overview for admins; others go to their apps. |
| `GET /console/me` | The signed-in user's apps and devices. |
| `GET /console/users` | Users and groups. |
| `GET /console/devices` | Devices; `?status=pending`, `approved`, `disabled` or `revoked` filters. |
| `GET /console/apps` | Apps and connector groups. |
| `GET /console/policies` | Policies. |
| `GET /console/decisions` | Recent decisions; `?denied=1` shows only denies. |
| `GET /console/decisions/{id}` | Why one decision came out as it did. |
| `POST /console/users/{user}/disable` | Disables a user (by user ID). |
| `POST /console/users/{user}/enable` | Enables a user. |
| `POST /console/devices/{device}/approve` | Approves a pending device. |
| `POST /console/devices/{device}/revoke` | Revokes a device. |
| `GET /console/login` | The sign-in page; `next` is where to return, `reauth=1` shows it even to a signed-in browser, to sign in again. |
| `POST /console/login` | A built-in account's username and password, from the sign-in page's form; answers with its authenticator code step. |
| `GET /console/step-up` | The step-up form for an IdP sign-in that needs a second factor for changes; `next` is where to return. |
| `POST /console/step-up` | An authenticator code of the admin's built-in account; allows changes for `console.changeMaxAge`. |
| `GET /console/login/start` | Starts sign-in at the IdP; `next` is where to return, `reauth=1` asks the IdP to sign in afresh (`prompt=login`, `max_age`). Without an IdP, goes to the sign-in page. |
| `POST /console/logout` | Signs out. |
| `GET /console/assets/console.css` | The stylesheet. |
| `GET /console/assets/console.js` | The script. |

Pages for signed-out browsers redirect to the sign-in page; pages a user may
not see answer 403 with an explanation. The console is for browsers; the
admin API and `warren admin` stay the interface for automation.

## Tests

`crates/warren-control/tests/console.rs` drives the console as a browser
against a control plane and a test IdP: sign-in through the IdP and with
built-in accounts (with and without an IdP: enrollment, wrong passwords and
codes, disabled accounts, the per-source limit, the sign-in form's token and
origin), the step-up of a Google-style sign-in (no MFA, no `auth_time`)
before a change, which account it binds to, replayed and wrong codes,
lockout and the per-source limit, every page, each permission
case (signed out, user, admin without MFA, admin with an old sign-in,
admin, an IdP that leaves out `auth_time`), form tokens and origins, sign-ins finished in another browser,
redirects after sign-in, sign-out, disabling a signed-in user, device and
user changes and their audit records, decisions reported by a connector and
their explanation, and escaping of values users, devices and connectors
control. It also checks this page documents every route.

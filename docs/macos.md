# warren on macOS

Status: milestone M1. The command-line client runs on any Mac with macOS 11
or later: sign in through your browser, then `sudo warren up` routes your
organization's internal apps, and only those, through warren. The menu-bar
app and its packet tunnel system extension are built in CI but need a
signature from an Apple Developer team to run, which the project does not
have yet; until then the command-line client is how warren runs on a Mac.

## Install

Download `warren-<version>-macos-universal.tar.gz` and its `.sha256` from
the [releases page](https://github.com/terrabyteian/warren/releases). The
binary is universal (Apple silicon and Intel), signed ad hoc and not
notarized, so macOS quarantines it when a browser downloads it:

```sh
shasum -a 256 -c warren-<version>-macos-universal.tar.gz.sha256
tar -xzf warren-<version>-macos-universal.tar.gz
cd warren-<version>-macos-universal
xattr -d com.apple.quarantine warren
sudo install -m 0755 warren /usr/local/bin/warren
```

To build it yourself (the toolchain is pinned and every dependency is
vendored):

```sh
cargo build --release -p warren --no-default-features --features client --locked --offline
```

## Sign in

```sh
warren login https://warren.example.com
```

`login` opens your browser at the organization's sign-in page (OAuth 2.0 for
native apps with PKCE; the browser returns to a one-time listener on
`127.0.0.1`). After you sign in at your identity provider, the client
exchanges the one-time code for a session bound to this Mac's device key and
enrolls the device. Run it without `sudo`: it signs you in as yourself.

```
Signed in to https://warren.example.com as ada@example.com.
Device d-48e68e2d55ff4cd0088d enrolled (key: Secure Enclave (hardware-bound)).
This device is waiting for an administrator to approve it: device d-48e68e2d55ff4cd0088d. Run `sudo warren up` once it is approved.
```

An administrator approves the device (`warren admin devices approve
<device>`), unless the deployment approves devices automatically.

- **The organization's certificate.** The client verifies the organization
  URL with this Mac's trust store. A deployment without a certificate from a
  public or company CA (a homelab, say) presents one from its own private
  CA; ask the administrator for the root fingerprint (`warren admin
  deployment` prints it) and pin it:
  `warren login https://warren.lab --fingerprint sha256:9b55...`. An MDM
  profile can preset the same fingerprint. After enrollment the client
  verifies the control plane against the deployment's own trust bundle only.
- **No browser here.** `--no-browser` prints the URL instead, for a remote
  session; `$BROWSER`, when set, is used instead of the default browser.
- **Sign in again.** Run `warren login` again whenever warren says so, for
  example when a rule needs a more recent sign-in (`--fresh` asks the
  identity provider to authenticate you afresh). The same device and key are
  kept.

Everything the client keeps is in `~/Library/Application Support/warren`,
readable only by you: the organization and its trust bundle, the session,
the device, the device key's handle, the current certificate and the last
entitlements. There is nothing to edit. `WARREN_HOME` or `--home` chooses
another directory.

## Connect

```sh
sudo warren up
```

```
Connecting to https://warren.example.com as ada@example.com on utun6...
warren is up: 2 apps, 2 routes through utun6. Stop with Ctrl-C or `warren down`.
20:41:07 connected to homelab through relay1.example.com over QUIC
20:41:12 blocked tcp 10.77.0.30:7 (billing): You may request access to billing. [request_access]
```

`up` keeps running and prints every connection change and every block, with
its reason, as it happens. It:

- creates a utun interface with this device's tunnel addresses and routes
  exactly the address ranges of the apps you may reach or request into it
  (split tunnel; nothing else changes, and never a default route);
- measures every relay and uses the closest, over QUIC on UDP 443 with an
  automatic fallback to HTTP/2 over TCP 443 (`--transport quic` or `h2`
  forces one), and moves to another relay without dropping your
  connections if one goes away;
- keeps one end-to-end session per connector group, renews the certificate
  at half its lifetime, and picks up changed entitlements within a minute,
  adding or removing routes as apps come and go;
- answers a connection the connector refuses at once (a TCP reset or an
  ICMP error) and prints why, so nothing hangs: no rule, a request needed,
  a sign-in that is too old, a revoked device, and so on;
- keeps working while the control plane is unreachable, until the
  certificate expires.

Stop it with Ctrl-C, or `warren down` from another terminal; the interface
and every route through it go away with it.

`up` needs root only to create the interface and change routes. It opens
the interface, starts a small helper that stays root, and runs everything
else as you: TLS, QUIC, HTTP and the device key never run as root. The
helper only configures the interface it created and adds or removes routes
through it, and refuses a default route, any range wider than a /8 and
local ranges (loopback, link-local, multicast) even if asked.

An app's range that contains a relay or the control plane is not routed
(warren must reach those directly) and `up` says so. A range a local
network already routes may not take; `up` says that too.

## Status, down and logout

```sh
warren status            # sign-in, device, certificate, tunnels, apps, recent blocks
warren status --json
warren down              # disconnect a running `warren up`
warren logout            # forget the sign-in and delete the device key
```

`status` asks a running `up` through a socket in the state directory, or
reads the saved state when nothing is running.

## The device key

On a Mac with a Secure Enclave (every Apple silicon Mac, and Intel Macs with
a T2 chip), the device key is a P-256 key generated in the Secure Enclave.
It never leaves it (G3): the client keeps only the enclave-wrapped handle,
which no other Mac can use. This works for an unsigned command-line tool
because the key is not stored in the keychain, which would need an
entitlement. The key is usable after the first unlock since boot, so the
tunnel can renew its certificate while the screen is locked.

Without a Secure Enclave (older Intel Macs and virtual machines), the client
falls back to a software key: it is sealed with AES-256-GCM in a file only
you can read, under a key kept in your login keychain. Enrollment reports
it as a software key, and `warren admin devices list` shows it, so
administrators can decide whether to approve such devices. A software key
does not meet G3: malware running as you could read it. After an upgrade
replaces the binary, macOS may ask once whether warren may use its item in
the login keychain.

`--key-storage` chooses explicitly: `secure-enclave` (fail rather than fall
back), `keychain` or `file`.

**Trust class.** Without an Apple Developer signature, nothing can attest to
the control plane that a key is in the Secure Enclave, so both kinds are
recorded with trust class 1, device-reported, with where the key lives as
the client's claim. Hardware attestation (through MDM-managed device
attestation) needs the signed app and comes later (see
[threat-model.md](threat-model.md#7-open-items)).

**Who can use the key.** The Secure Enclave never releases the key, but its
handle is a file in your state directory, so any process running as you can
ask the enclave to sign with it, as it can use the tunnel itself. The signed
app will restrict the key to warren's own code.

## What M1 does not do yet

- Internal names (split DNS and synthetic addresses) arrive in M2: only apps
  with IP addresses and CIDR ranges are routed. Apps with host names are
  listed in `warren status` but not reachable through the command-line
  client yet.
- Device posture arrives in M2.
- `warren up` runs in a terminal; it is not started at login.
- The menu-bar app and system extension cannot run unsigned.

## The menu-bar app and packet tunnel extension

[`macos/`](../macos) holds the app (SwiftUI, a menu-bar extra), the packet
tunnel provider (a NetworkExtension system extension) and the Swift wrapper
around the client core's C interface,
[`crates/warren-ffi/include/warren.h`](../crates/warren-ffi/include/warren.h).
Both link the core as a static library; neither implements any protocol. The
app signs in through the core and starts the tunnel through
NetworkExtension; the provider runs the core's tunnel engine, which hands it
packets and the routes to set.

```sh
macos/build.sh             # Swift and the Apple SDKs only; unsigned
```

Signing will need a Developer ID, the entitlements in
`macos/App/Warren.entitlements` and `macos/Tunnel/Tunnel.entitlements`
(the team ID replaces `TEAMID`), notarization, and the user's approval of
the system extension (or an MDM profile that pre-approves it). The device
key then moves into a keychain access group the app and the extension share.

## Testing

- **Automated, on every pull request.** `scripts/e2e-macos.sh` runs on a
  GitHub macOS runner with sudo: a control plane with a test IdP, a relay,
  a connector stand-in and two apps on one Mac, then `warren login` through
  a scripted browser, `sudo warren up`, a TCP and a UDP app through the
  tunnel, a block with its reason, an entitlement change picked up live,
  `warren down`, the HTTP/2 carrier and a revocation. The connector runs
  Linux kernel forwarding in production; the stand-in runs the same
  connector code and forwards through a second utun interface with address
  translation. Runners have no Secure Enclave, so this covers the software
  key in the keychain. `crates/warren-harness/tests/client.rs` runs the
  same client core in one process on Linux and macOS, and
  `scripts/e2e-kernel.sh` covers the real connector on Linux.
- **By hand, on a Mac with a Secure Enclave.** `E2E_NO_SUDO=1
  scripts/e2e-macos.sh` runs the unprivileged half (sign-in, enrollment
  with the Secure Enclave key, approval, status) without sudo, and
  `cargo test -p warren-client -- --ignored` exercises the Secure Enclave
  and the login keychain. Against a real deployment:
  1. `warren login <org URL>`; check `warren status` says the key is in
     the Secure Enclave and the administrator sees `secure-enclave`.
  2. `sudo warren up`; reach an allowed app; try an app you may only
     request and see the block with its reason.
  3. Put the Mac to sleep, wake it, change networks: connections continue
     or come back without a new `up`.
  4. Block UDP 443 on the network: `up` moves to HTTP/2.
  5. Disable the device (`warren admin devices disable`): certificate
     renewal is refused and `up` says why. Relays and connectors cut it
     within seconds once they consume the control plane's revocations
     (M2); with M1's static bundles, revoke the device in their bundle and
     `up` reports the cut at once.
  6. `warren down`: `netstat -rn` shows no route through the utun.

## Troubleshooting

| Message | What to do |
| --- | --- |
| this Mac does not trust the certificate of ... | The deployment uses its own CA: pin its root with `--fingerprint` (ask your administrator, who runs `warren admin deployment`). |
| This device is waiting for an administrator to approve it | Ask for device `d-...` to be approved, then run `sudo warren up`. |
| Your sign-in is not valid / Sign in again | Run `warren login` again. |
| warren up creates a network interface, which needs root | Run `sudo warren up`. |
| run warren login without sudo | Sign in as yourself; only `up` needs sudo. |
| warren is already up | `warren status` shows it; `warren down` stops it. |
| "warren" cannot be opened because the developer cannot be verified | Remove the quarantine mark: `xattr -d com.apple.quarantine warren`. |

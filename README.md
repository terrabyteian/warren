# warren

warren is open-source, zero-trust private access: a replacement for VPNs that
gives people identity- and device-aware access to internal applications
through outbound-only connectors and self-hosted relays.

> **Status: milestone M1 in progress.** The data path runs: `warren relay`
> and `warren connector` (kernel forwarding on Linux) carry a test client's
> traffic end to end through the relay, with per-flow policy decisions and
> audit records, the HTTP/2 fallback and the 1280-byte MTU floor
> ([scripts/e2e-kernel.sh](scripts/e2e-kernel.sh),
> [docs/benchmarks.md](docs/benchmarks.md)). The control plane runs too:
> sign-in through any OpenID Connect IdP, device enrollment and approval,
> short-lived user+device certificates, policy compiled to Cedar and
> published as signed bundles, the revocation push channel, and audit. Until
> relays and connectors consume the control plane's bundles, they read policy
> from a static bundle file. The macOS client runs as a command-line tool:
> `warren login` signs in through the browser with a Secure Enclave device
> key, and `sudo warren up` routes the apps you may reach through warren
> ([docs/macos.md](docs/macos.md)); the menu-bar app and its packet tunnel
> extension build, and run once they can be signed.

## What warren will be

- **Zero trust by construction.** Every connection is authenticated as one
  user on one approved device, checked against default-deny policy at the
  connector, and audited. Revocation cuts live connections within 10 seconds.
- **Effortless to use.** A signed macOS menu-bar app (Windows and Linux next):
  enter your organization's URL, sign in once through SSO in the browser, and
  internal apps just work. When something is blocked, it tells you exactly why.
- **Kubernetes-native.** Connectors run as an operator, apps and policies are
  CRDs, and `kubectl` access is brokered through your IdP groups with no
  secrets in kubeconfig.
- **Easy to run anywhere.** One binary with three roles (control plane, relay,
  connector), on Kubernetes or any host, with no vendor cloud behind it.
- **Small and solid.** Standard protocols (QUIC, MASQUE, TLS 1.3), Rust, one
  audited crypto stack (rustls on aws-lc-rs), Cedar for policy, and a short,
  audited dependency list. No feature creep.

## How it works

Clients and connectors both dial out to relays. The client opens an end-to-end,
mutually authenticated QUIC session to the connector through the relay
(CONNECT-UDP), and tunnels IP packets inside it (CONNECT-IP). The relay only
ever sees the tunnel's ciphertext; the connector checks policy on every new
flow; the control plane issues short-lived certificates bound to each device's
Secure Enclave key and pushes revocations. See [docs/design.md](docs/design.md).

## Documentation

Start with the [docs index](docs/README.md):
[design](docs/design.md), [protocol](docs/protocol.md),
[threat model](docs/threat-model.md), [policy](docs/policy.md),
[dependencies](docs/dependencies.md), [Kubernetes](docs/kubernetes.md),
[API](docs/api/openapi.yaml).

## Building

The Rust toolchain is pinned in `rust-toolchain.toml` and every dependency is
vendored, so builds work offline:

```sh
cargo build --workspace --locked --offline
cargo test --workspace --locked --offline
cargo run --locked --offline -- --help
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists the full set of checks CI runs.

## Using warren on a Mac

Download the universal binary from a release (it is not notarized yet, so
remove the quarantine mark; [docs/macos.md](docs/macos.md) has the steps),
then:

```sh
warren login https://warren.example.com   # sign in in your browser
sudo warren up                            # connect; Ctrl-C or `warren down` to stop
warren status
```

## Running the control plane

Write a configuration (see
[docs/examples/control-plane.yaml](docs/examples/control-plane.yaml)) and a
policy directory (see [docs/examples/policy](docs/examples/policy) and
[docs/policy.md](docs/policy.md)), then:

```sh
warren policy check /etc/warren/policy        # compile and show every problem
warren control-plane --config /etc/warren/control-plane.yaml
```

On first start the control plane creates its key-encryption key, its
certificate authorities and its signing keys. Operate it from the same host
through its local admin socket:

```sh
warren admin devices list
warren admin devices approve <device>
warren admin deployment                           # the root fingerprint clients can pin
warren admin users disable alice@example.com      # cut within 10 seconds
warren admin join-token create --role connector --group homelab --name lab-1
warren admin policy reload
```

The APIs are described in [docs/api/openapi.yaml](docs/api/openapi.yaml).

## Running warren on Kubernetes

Each release publishes multi-architecture images
(`ghcr.io/terrabyteian/warren` for the control plane, and the data-path
`ghcr.io/terrabyteian/warren-relay` and
`ghcr.io/terrabyteian/warren-connector`) and a Helm chart for the control
plane, a relay and a kernel-mode connector, all signed with cosign:

```sh
helm install warren oci://ghcr.io/terrabyteian/charts/warren --version X.Y.Z \
  -n warren -f values.yaml
```

[docs/kubernetes.md](docs/kubernetes.md) walks through the install, reaching
the control plane and signing in, joining a relay and a connector, and
every value.

## Contributing and security

Contributions are welcome under the [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin);
sign off every commit with `git commit -s`. Please report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

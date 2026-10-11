# warren

warren is open-source, zero-trust private access: a replacement for VPNs that
gives people identity- and device-aware access to internal applications
through outbound-only connectors and self-hosted relays.

> **Status: milestone M1 in progress.** The data path runs: `warren relay`
> and `warren connector` (kernel forwarding on Linux) carry a test client's
> traffic end to end through the relay, with per-flow policy decisions and
> audit records, the HTTP/2 fallback and the 1280-byte MTU floor
> ([scripts/e2e-kernel.sh](scripts/e2e-kernel.sh),
> [docs/benchmarks.md](docs/benchmarks.md)). Until the control plane lands,
> nodes read policy from a static bundle file. The control plane and the
> macOS app are next.

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
[dependencies](docs/dependencies.md).

## Building

The Rust toolchain is pinned in `rust-toolchain.toml` and every dependency is
vendored, so builds work offline:

```sh
cargo build --workspace --locked --offline
cargo test --workspace --locked --offline
cargo run --locked --offline -- --help
```

[CONTRIBUTING.md](CONTRIBUTING.md) lists the full set of checks CI runs.

## Contributing and security

Contributions are welcome under the [Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin);
sign off every commit with `git commit -s`. Please report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

# warren

warren is open-source, zero-trust private access: a replacement for VPNs that
gives people identity- and device-aware access to internal applications
through outbound-only connectors and self-hosted relays.

> **Status: design stage (milestone M0).** The design is written down and the
> project skeleton is in place, but nothing runs yet. The `warren` binary
> answers `--help` and `--version` and nothing else.

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
ever sees ciphertext; the connector checks policy on every new flow; the
control plane issues short-lived certificates bound to each device's Secure
Enclave key and pushes revocations. See [docs/design.md](docs/design.md).

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

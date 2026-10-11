# Contributing to warren

Thanks for your interest. warren is in early development: the design
documents in [docs/](docs/README.md) are the best place to start, and
discussion of the design in issues is as valuable as code right now.

## Ground rules

- **The design is the contract.** A change that alters a guarantee in
  [docs/design.md](docs/design.md#4-guarantees) updates that document, and
  [docs/threat-model.md](docs/threat-model.md) where a threat depends on it, in
  the same pull request.
- **Dependencies are decisions.** Read [docs/dependencies.md](docs/dependencies.md)
  before adding or updating a crate; CI refuses anything off the allowlist and
  any unexplained growth of a binary's dependency closure.
- **Keep it small.** warren deliberately leaves things out
  ([design section 3](docs/design.md#3-non-goals-and-the-leave-out-list)).
  Proposals that add a new product category belong in another project.
- **Describe warren on its own terms.** Explain what a change does and why,
  without naming or comparing against other products.

## Developer Certificate of Origin

Every commit from an outside contributor must be signed off to certify the
Developer Certificate of Origin below. Use `git commit -s`, which adds a
trailer like:

```
Signed-off-by: Your Name <you@example.com>
```

The email must match the commit's author email. CI checks every commit in a
pull request; to fix a missing sign-off, amend (`git commit --amend -s`) or
rebase (`git rebase --signoff main`).

The DCO is an attestation that outside contributors make about their
contributions, so commits authored by the project owner
(`terrabyteian <terrabyteian@users.noreply.github.com>`) are exempt.
Maintainers confirm the authorship of any owner-attributed commit in an outside
pull request.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Contributions are licensed under the [Apache License 2.0](LICENSE).

## Development

The toolchain is pinned in `rust-toolchain.toml` (rustup installs it on first
use) and every dependency is vendored, so all cargo commands run with
`--locked --offline`.

The checks CI runs, in order:

```sh
cargo fmt --all --check
shellcheck scripts/*.sh
scripts/test-check-dco.sh
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo clippy -p warren --no-default-features --features relay,connector --all-targets --locked --offline -- -D warnings
cargo build --workspace --all-targets --locked --offline
cargo test --workspace --locked --offline
cargo test -p warren --no-default-features --features relay,connector --locked --offline
sudo scripts/e2e-kernel.sh target/debug   # Linux, root: network namespaces
scripts/check-deps.sh
scripts/check-closure.sh
scripts/check-vendor.sh        # needs network access to crates.io
cargo deny --locked check      # needs cargo-deny
cargo vet --locked             # needs cargo-vet
```

[docs/dependencies.md](docs/dependencies.md#2-how-it-is-enforced) says how to
install cargo-deny and cargo-vet. CI also runs the benchmarks
(`scripts/bench-inprocess.sh` and `sudo scripts/bench-kernel.sh`) and
publishes their results in the job summary; they never gate a change
([docs/benchmarks.md](docs/benchmarks.md)).

Code conventions:

- rustfmt defaults; clippy clean with warnings denied.
- `unsafe` is denied workspace-wide. Code that needs it (FFI to the native
  shells, the tunnel device) allows it locally with a comment explaining why
  it is sound, and gets extra review.
- Keep the data path lean: the client core and the relay and connector roles
  must not depend on control-plane, console or Kubernetes crates
  (`scripts/check-closure.sh` enforces this).

## Pull requests

- One logical change per pull request, with a description of what it does and
  why.
- All CI checks green, including DCO.
- Changes to `deps/closure/` baselines explain the growth.

# Dependencies

warren is security software, so every line of third-party code it ships is a
decision. This document is the dependency policy (G17 in
[design.md](design.md#4-guarantees)), how it is enforced in this repository,
and what the dependency closure measures today.

## 1. Policy

1. **Allowlisted.** A crate can be a direct dependency only if it is listed in
   [`deps/allowlist.txt`](../deps/allowlist.txt) with the workspace crates
   allowed to use it and the reason it is there. Entries nobody uses are
   removed.
2. **Pinned.** Every direct dependency is declared once, in
   `[workspace.dependencies]`, with an exact `=` version and only the features
   warren needs. `Cargo.lock` pins the rest of the graph.
3. **Vendored.** Every crate's source is committed under `vendor/`, and builds
   read only from there, offline.
4. **Audited.** The whole graph is covered by cargo-vet (audits, imported
   audits, or recorded publisher trust) and checked by cargo-deny for
   advisories, licenses, banned crates and sources.
5. **Measured.** The transitive closure of every shipped binary is committed as
   a baseline; any change fails CI until the baseline update is reviewed.
6. **Kept out of the data path.** Data-path builds (the client core, and the
   `warren` binary built with only the relay and connector roles) must never
   reach console, operator or Kubernetes crates.
7. **One crypto stack.** rustls on aws-lc-rs. `ring`, OpenSSL and native-tls are
   banned outright.

## 2. How it is enforced

| File or check | What it does |
| --- | --- |
| [`deps/allowlist.txt`](../deps/allowlist.txt) | The allowlist: crate, permitted workspace crates, reason. |
| [`Cargo.toml`](../Cargo.toml) | `[workspace.dependencies]` with exact versions. |
| [`Cargo.lock`](../Cargo.lock) | The pinned graph, with checksums. |
| [`vendor/`](../vendor) and [`.cargo/config.toml`](../.cargo/config.toml) | Vendored sources; cargo is pointed at them instead of crates.io. |
| [`scripts/check-deps.sh`](../scripts/check-deps.sh) | Fails on any direct dependency (normal, build or dev) that is not allowlisted for that workspace crate, not pinned with `=`, not from crates.io, or a path outside the workspace; also on unused allowlist entries. |
| [`scripts/check-closure.sh`](../scripts/check-closure.sh) | Prints the per-binary closure report and fails if any closure differs from its baseline in [`deps/closure/`](../deps/closure), or if a data-path build reaches a crate in [`deps/data-path-forbidden.txt`](../deps/data-path-forbidden.txt). |
| [`scripts/check-vendor.sh`](../scripts/check-vendor.sh) | Re-runs `cargo vendor` and fails if `vendor/` differs from what `Cargo.lock` produces. |
| [`deny.toml`](../deny.toml) | cargo-deny: advisories, license allowlist, banned crates, crates.io as the only source. |
| [`supply-chain/`](../supply-chain) | cargo-vet: criteria, imported audit sets, audits, trust entries. |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | Runs all of the above on every pull request and push to `main`. |

The closure is computed per binary with `cargo tree -e normal,build` over the
release targets (Linux and macOS, x86_64 and aarch64), so it counts every
crate compiled into the binary, build scripts and proc macros included. The
binaries tracked today:

| Name | Build | Data path |
| --- | --- | --- |
| `warren` | `-p warren` (all roles) | no |
| `warren-datapath` | `-p warren --no-default-features --features relay,connector` | yes |
| `warren-client` | `-p warren-client` | yes |

The Kubernetes operator joins this list when it becomes a binary in M2.

**CI-only tools.** cargo-deny and cargo-vet run only in CI and are never
product dependencies. CI installs pinned release binaries (cargo-deny 0.20.2,
cargo-vet 0.10.0) and verifies them against SHA-256 digests recorded in
[`scripts/install-ci-tools.sh`](../scripts/install-ci-tools.sh). Locally,
`cargo install --locked cargo-deny@0.20.2 cargo-vet@0.10.0`.

## 3. Adding or updating a crate

1. **Justify it.** In the pull request, say what the crate does for warren,
   why the standard library or an existing dependency is not enough, how it is
   maintained, whether it uses `unsafe`, and how much it grows each closure.
2. **Declare it** in `[workspace.dependencies]` with an exact `=` version and
   `default-features = false` plus the features you need, then reference it from
   the member with `workspace = true`.
3. **Allowlist it** in `deps/allowlist.txt` for exactly the workspace crates
   that use it.
4. **Lock and vendor:** `cargo vendor vendor` (this also updates `Cargo.lock`),
   then commit `Cargo.lock` and `vendor/`.
5. **Update the closure baselines:** `scripts/check-closure.sh --update`, and
   explain the growth in the pull request.
6. **Vet it:** `cargo vet`, then audit the new code (`cargo vet certify`),
   rely on an imported audit, or record a reviewed publisher trust entry. Run
   `cargo deny check`; a new license or a duplicate version needs a reviewed
   entry in `deny.toml`.
7. **Run every check** in the order CI does: `scripts/check-deps.sh`,
   `scripts/check-closure.sh`, `scripts/check-vendor.sh`,
   `cargo deny --locked check`, `cargo vet --locked`.

Removing a crate is the same in reverse; finish with `cargo vet prune`.

## 4. Audit sources and trust decisions

- **Imported audit sets:** Mozilla, Google, the Bytecode Alliance and ISRG.
  These organizations publish cargo-vet audits of widely used crates;
  importing them is a trust decision recorded in `supply-chain/config.toml`.
- **Default criteria:** `safe-to-deploy` for everything that ships.
- **Publisher trust (M0):** `clap`, `clap_builder`, `clap_lex` and `anstyle`
  are trusted as published by the clap maintainer's crates.io account,
  `safe-to-deploy`, until 2027-10-11. The imported Mozilla, ISRG and Bytecode
  Alliance audit sets trust the same publisher. The entries live in
  `supply-chain/audits.toml` and lapse unless renewed by review.
- There are no exemptions today. Any future exemption carries a note and an
  issue to remove it.

## 5. The closure today (M0)

The skeleton needs one direct dependency: `clap` for the `warren` command line,
with the builder API only (no derive macros, no color support).

| Binary | Third-party crates | Crates |
| --- | --- | --- |
| `warren` | 4 | anstyle 1.0.14, clap 4.6.7, clap_builder 4.6.7, clap_lex 1.1.1 |
| `warren-datapath` | 4 | same as `warren` |
| `warren-client` | 0 | none |

Enabling clap's derive API would add five proc-macro crates (heck,
proc-macro2, quote, syn, unicode-ident), so M0 uses the builder API instead.
Those crates will arrive with the first serde or tokio macros in M1, through
this same review.

## 6. Measured projection for M1

To size the M1 data path before writing it, the expected direct crates were
resolved in a scratch crate outside this repository on 2026-10-11 against the
then-latest crates.io releases, and measured with the same method as
`scripts/check-closure.sh`. Nothing below is a dependency of this repository
yet; each crate still goes through section 3.

- **Transport stack:** tokio 1.53.2 (`rt-multi-thread`, `net`, `time`, `sync`),
  quinn 0.11.12 (`runtime-tokio`, `rustls-aws-lc-rs`), rustls 0.23.45
  (`aws_lc_rs`, `std`), h3 0.0.8, h3-quinn 0.0.10, h3-datagram 0.0.2, bytes,
  tracing.
- **Policy engine:** cedar-policy 4.13.0 without default features.

Third-party crates in the closure, each including the four clap crates:

| Set | Linux x86_64 | without build-only crates | macOS arm64 | All targets |
| --- | --- | --- | --- | --- |
| Transport stack | 67 | 58 | 66 | 91 |
| Cedar | 111 | 72 | 111 | 116 |
| Transport stack and Cedar | 160 | 115 | 159 | 186 |

What the measurement shows, and what M1 must decide:

- **Cedar is the largest single cost**, mostly at build time: its parser is
  generated with lalrpop, which brings regex, petgraph and more into the build.
  Connectors embed Cedar so that enforcement and the console's explanation use
  one engine ([design.md](design.md#75-policy)); the client core does not need
  it. The closure gate makes this cost visible in review.
- **`ring` appears only for wasm32** (through quinn-proto) and never on release
  targets; `deny.toml` bans it.
- **Windows-only crates** (windows-sys, windows-targets and the per-target
  import-library crates) appear only in the all-targets column. They become
  real when the Windows client starts, and because `cargo vendor` copies every
  platform's crates, that milestone must decide how to keep `vendor/` lean.
- **Duplicate versions** appear (for example two `itertools` and two
  `unicode-width` versions under Cedar, two `windows-sys` versions). cargo-deny
  denies duplicates, so each will need a reviewed `skip` entry or an upstream
  fix.
- **h3 is pre-1.0.** If it churns, warren carries its own minimal HTTP/3
  subset, as the design allows.
- **aws-lc-sys compiles C and assembly** at build time (cc, cmake), so the
  build environment, not only the source, is part of the supply chain and of
  the reproducible-build work in M4.
- **Licenses.** The M1 graph adds licenses beyond Apache-2.0 and MIT (for
  example Unicode-3.0 and ISC). Each is added to `deny.toml` deliberately.

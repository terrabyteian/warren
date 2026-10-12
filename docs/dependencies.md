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
| `warren` | `-p warren` (all roles and the client) | no |
| `warren-datapath` | `-p warren --no-default-features --features relay,connector` | yes |
| `warren-client` | `-p warren-client` | yes |
| `warren-client-cli` | `-p warren --no-default-features --features client` (the macOS release) | yes |
| `warren-ffi` | `-p warren-ffi` (the static library the Swift shells link) | yes |

The Kubernetes operator joins this list when it becomes a binary in M2.

**CI-only tools.** cargo-deny and cargo-vet run only in CI and are never
product dependencies. CI installs pinned releases verified against SHA-256
digests recorded in [`scripts/install-ci-tools.sh`](../scripts/install-ci-tools.sh):
cargo-deny 0.20.2 as its release binary, and cargo-vet 0.10.2 as its source
crate, built with the lockfile inside it. cargo-vet publishes no binaries
after 0.10.0, and 0.10.2 is the first release that can record trust in crates
published through crates.io trusted publishing, which several crates in the
M1 graph are. Locally, `cargo install --locked cargo-deny@0.20.2
cargo-vet@0.10.2`.

The chart's CI uses Helm 3.22.0 and kind 0.33.0, pinned and digest-verified
the same way in [`scripts/install-kube-tools.sh`](../scripts/install-kube-tools.sh).
The container images' base images (the Rust build image, distroless and
Debian slim) are pinned by digest in the [Dockerfile](../Dockerfile), and the
image build reads crates only from `vendor/`.

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
- **Publisher trust.** Every crate in the data path's graph is trusted, for
  `safe-to-deploy` until 2027-10-11, as published by the crates.io account
  that publishes its releases, or by the GitHub repository that publishes
  them through crates.io trusted publishing. Each entry in
  `supply-chain/audits.toml` carries a note naming the publisher's role (the
  crate's author or maintainer, or the Rust project's owner account); where
  an imported audit set trusts the same publisher, the note says so; and
  crates that appear only on targets warren does not release for (wasm32,
  Windows, UEFI) say that too, since cargo-vet covers the whole lockfile.
  The M0 entries for the clap family follow the same rule. All of them lapse
  unless renewed by review.
- **Exemptions (M1 control plane).** The control plane brought in its own
  dependency closure (section 5). Every crate of it that no audit or trust
  entry covers is listed as a version-pinned exemption in
  `supply-chain/config.toml`, each with a note. That includes crates that
  appear in `Cargo.lock` only through optional features (Windows, wasm and
  unused sqlx drivers, for example), because cargo-vet checks the whole lock
  file. Replacing them with audits, imported audits or reviewed publisher
  trust before the external audit is an open item
  ([threat-model.md](threat-model.md#7-open-items), M4); a new version of an
  exempted crate is not covered and fails `cargo vet` until it is reviewed.

## 5. The closure today (M1)

M0 needed one direct dependency, `clap`, for the `warren` command line with
the builder API only.

The M1 data path adds these direct crates, each allowlisted with its reason in
[`deps/allowlist.txt`](../deps/allowlist.txt): tokio, quinn, rustls,
rustls-webpki, aws-lc-rs, bytes, h2, http, tokio-rustls, serde, serde_json,
tracing, tracing-subscriber and libc (Linux, for the TUN device). The test
harness, which never ships, also uses aws-lc-rs and serde_json. Interface,
route and NAT setup for kernel forwarding calls the system's `ip` and `nft`
commands instead of linking netlink or nftables crates.

The M1 control plane adds the crates below. Each is allowlisted for exactly
the workspace crates that use it.

| Crate | Used by | Why | Notes |
| --- | --- | --- | --- |
| aws-lc-rs 1.18.1 | warren-core, warren-control | ECDSA P-256 keys and signatures, SHA-256, AES-256-GCM for keys at rest, the CSPRNG | The one crypto provider (G16). FFI to AWS-LC, which aws-lc-sys builds from C and assembly. |
| rustls 0.23.45, tokio-rustls 0.26.6 | warren-control | TLS 1.3 for the control-plane listener and IdP calls | TLS 1.3 only, aws-lc-rs provider, no `tls12` feature. |
| rustls-native-certs 0.8.4 | warren-control | The operating system's trust store for a public IdP | An operator can point at a CA file instead. Reads the platform store; links no OpenSSL. |
| tokio 1.53.2 | warren-control | Async runtime | |
| hyper 1.11.1, hyper-util 0.1.21, http 1.5.0, http-body 1.1.0, http-body-util 0.1.5, bytes 1.12.1 | warren-control | HTTP/1.1 and HTTP/2 server for links D and E and the admin socket, and a one-request client for the IdP | No framework on top; routing is a `match`. |
| sqlx 0.9.0 | warren-control | The one SQL layer: SQLite now, PostgreSQL later, one migration set (design section 12) | Features `runtime-tokio`, `sqlite-bundled` and `migrate` only: no query macros, no SQLite extension loading. Brings `url` and its Unicode tables. |
| cedar-policy 4.13.0 | warren-policy | The policy engine (design section 7.5) | Only the `ipaddr` extension. Behind the `compiler` feature of warren-policy, so the data-path build does not link it yet. |
| saphyr-parser 0.1.0 | warren-policy | YAML with line numbers for `@source` and diagnostics | Behind the `compiler` feature. The YAML crates built on serde are unmaintained or pull in much more. No `unsafe`. |
| serde 1.0.229, serde_json 1.0.154 | warren-core, warren-policy, warren-control | JSON for the APIs, bundles, events, Cedar entities and audit records | |
| base64 0.22.1 | warren-core, warren-control | base64 and base64url | The version sqlx already uses. |
| form_urlencoded 1.2.2 | warren-control | Query strings and form bodies in the OIDC flow | Already in the closure through `url`. |
| zeroize 1.9.1 | warren-core, warren-control | Wiping private keys and secrets after use | Already in the closure through aws-lc-rs. |

| Binary | Third-party crates | Notes |
| --- | --- | --- |
| `warren` | 231 | Cedar (about 100, mostly its build-time parser generator) and sqlx with `url` (about 60) are the bulk; the data path's transport stack is most of the rest. |
| `warren-datapath` | 77 | The transport stack (tokio, quinn, rustls, h2), the aws-lc-rs build (cc, cmake and friends), clap, and base64 and zeroize through warren-core. |
| `warren-client` | 73 | The data-path set without the clap family. |
| `warren-client-cli` | 77 | The client core and the clap family. |
| `warren-ffi` | 73 | Exactly the client core's. |

The M1 macOS client ([macos.md](macos.md)) adds no third-party crate to
any closure. New direct edges, each allowlisted: serde, serde_json and
zeroize for warren-client (its saved state, the control-plane calls, and
wiping the software device key); serde_json and, on macOS, libc for the
`warren` binary's client (status output, and privilege separation for
`warren up`); libc for warren-core on macOS (the utun device); serde_json
and tokio for warren-ffi; and http for warren-harness's tests, which drive
the control plane's HTTP client. The Security framework (the Secure
Enclave key, the login keychain, the system's certificate trust
evaluation) is reached through about thirty C functions declared in
`warren-client`'s `apple` module, not binding crates: security-framework is
in the control plane's closure through rustls-native-certs, but bringing it
into the data path would add crates for what those calls do.

The control plane's crates stay out of both data-path closures:
`scripts/check-closure.sh` checks them against
[`deps/data-path-forbidden.txt`](../deps/data-path-forbidden.txt), and the
baselines in [`deps/closure/`](../deps/closure) list every crate.

Five duplicate versions are allowed in `deny.toml`, each with its reason:
`cpufeatures` 0.2 (sha2 and keccak under sqlx and lalrpop), `hashbrown`
(sqlx's hashlink), `itertools` (lalrpop), `syn` 2 (three proc-macro crates not
yet on syn 3) and `unicode-width` (miette). The graph brings six licenses
beyond Apache-2.0 and MIT, each allowed in `deny.toml` with the crates that
need it: ISC (aws-lc, rustls-webpki, untrusted), BSD-3-Clause (subtle, parts
of aws-lc), MIT-0 (aws-lc-sys), Unicode-3.0 (unicode-ident, and the icu_*
crates under `url`), Zlib (foldhash) and Apache-2.0 WITH LLVM-exception
(ar_archive_writer). `ring` appears in the lockfile only for wasm32 (through
quinn-proto) and in no release target's graph.

`vendor/` is about 340 MB. The largest parts are aws-lc-sys's C and assembly
(69 MB), the Windows import-library crates behind `ring`'s wasm32 and Windows
paths and tokio's Windows support (about 100 MB), which `cargo vendor` copies
for every platform, and the SQLite amalgamation in libsqlite3-sys (21 MB).
Keeping `vendor/` lean is still the decision the Windows client milestone has
to make.

## 6. Measured projection for M1

This section is the M0 projection, kept for comparison with the measured
closure in section 5. To size the M1 data path before writing it, the expected
direct crates were
resolved in a scratch crate outside this repository on 2026-10-11 against the
then-latest crates.io releases, and measured with the same method as
`scripts/check-closure.sh`. This is the projection as recorded at M0;
[section 5](#5-the-closure-today-m1) has what M1 ships.

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

What the measurement showed, and what M1 decided (the transport stack M1
ships has 76 crates against the 91 projected, because h3, h3-quinn and
h3-datagram gave way to warren's own HTTP/3 subset; Cedar is not in this
closure yet):

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
- **h3 is pre-1.0.** It also cannot carry `:protocol = connect-ip`, so M1
  carries its own minimal HTTP/3 subset, as the design allows.
- **aws-lc-sys compiles C and assembly** at build time (cc, cmake), so the
  build environment, not only the source, is part of the supply chain and of
  the reproducible-build work in M4.
- **Licenses.** The M1 graph adds licenses beyond Apache-2.0 and MIT (for
  example Unicode-3.0 and ISC). Each is added to `deny.toml` deliberately.

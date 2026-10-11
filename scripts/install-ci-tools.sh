#!/usr/bin/env bash
# Installs the CI-only supply-chain tools (cargo-deny, cargo-vet), each a
# pinned release verified against a pinned SHA-256 digest: cargo-deny as its
# release binary, cargo-vet as its source crate built with its own lockfile
# (cargo-vet publishes no binaries after 0.10.0, and 0.10.2 is the first
# release that can record trust in crates.io trusted publishing). These
# tools are never product dependencies. Linux x86_64 only, which is what CI
# runs on; locally, `cargo install --locked cargo-deny@<version>
# cargo-vet@<version>`.
#
# Usage: scripts/install-ci-tools.sh DEST_DIR
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 DEST_DIR" >&2
  exit 2
fi
dest=$1

deny_version=0.20.2
deny_sha256=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
vet_version=0.10.2
vet_crate_sha256=dd93790018205cbbfa161f078ca4631afa8ed57fc8f32482268bcfdf0c0d7499

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *)
    echo "error: pinned binaries exist for Linux x86_64 only" >&2
    exit 1
    ;;
esac

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$dest"

fetch() {
  local url=$1 sha=$2 out=$3
  curl --proto '=https' --tlsv1.2 -sSfL -o "$out" "$url"
  echo "$sha  $out" | sha256sum --check --strict --quiet
}

deny_dir="cargo-deny-$deny_version-x86_64-unknown-linux-musl"
fetch "https://github.com/EmbarkStudios/cargo-deny/releases/download/$deny_version/$deny_dir.tar.gz" \
  "$deny_sha256" "$work/deny.tar.gz"
tar -xzf "$work/deny.tar.gz" -C "$work"
install -m 0755 "$work/$deny_dir/cargo-deny" "$dest/cargo-deny"

fetch "https://static.crates.io/crates/cargo-vet/cargo-vet-$vet_version.crate" \
  "$vet_crate_sha256" "$work/vet.crate"
tar -xzf "$work/vet.crate" -C "$work"
# Build outside the repository so its vendored-source configuration does not
# apply; --locked uses the lockfile inside the verified crate.
(cd "$work" && cargo install --locked --quiet --path "cargo-vet-$vet_version" --root "$work/vet-root")
install -m 0755 "$work/vet-root/bin/cargo-vet" "$dest/cargo-vet"

"$dest/cargo-deny" --version
"$dest/cargo-vet" --version

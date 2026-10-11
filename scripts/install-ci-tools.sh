#!/usr/bin/env bash
# Installs the CI-only supply-chain tools (cargo-deny, cargo-vet) as pinned
# release binaries, verified against pinned SHA-256 digests. These tools are
# never product dependencies. Linux x86_64 only, which is what CI runs on;
# locally, `cargo install --locked cargo-deny@<version> cargo-vet@<version>`.
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
vet_version=0.10.0
vet_sha256=c7664d9db5dd2ff813f20303650ac8253fa712ff2a1ea9ce12bed71e346f1744

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

vet_dir="cargo-vet-x86_64-unknown-linux-gnu"
fetch "https://github.com/mozilla/cargo-vet/releases/download/v$vet_version/$vet_dir.tar.xz" \
  "$vet_sha256" "$work/vet.tar.xz"
tar -xJf "$work/vet.tar.xz" -C "$work"
install -m 0755 "$work/$vet_dir/cargo-vet" "$dest/cargo-vet"

"$dest/cargo-deny" --version
"$dest/cargo-vet" --version

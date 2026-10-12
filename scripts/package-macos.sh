#!/usr/bin/env bash
# Packages the macOS command-line client: one universal binary (arm64 and
# x86_64) from the client-only release builds, signed ad hoc (no identity,
# no secrets: the project has no Apple Developer membership yet), in a
# tarball with the license and install notes, and its SHA-256.
#
# Build first, for each target:
#   MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release -p warren \
#     --no-default-features --features client --target <target> --locked --offline
#
# Usage: scripts/package-macos.sh VERSION OUT_DIR
#        (TARGETS overrides "aarch64-apple-darwin x86_64-apple-darwin")
set -euo pipefail

cd "$(dirname "$0")/.."

if [ $# -ne 2 ]; then
  echo "usage: $0 VERSION OUT_DIR" >&2
  exit 2
fi
version=$1
out=$2
targets=${TARGETS:-"aarch64-apple-darwin x86_64-apple-darwin"}

name="warren-$version-macos-universal"
stage="$out/$name"
rm -rf "$stage"
mkdir -p "$stage"

inputs=()
for t in $targets; do
  bin="target/$t/release/warren"
  if [ ! -x "$bin" ]; then
    echo "error: $bin is missing; build the client for $t first" >&2
    exit 1
  fi
  inputs+=("$bin")
done
lipo -create "${inputs[@]}" -output "$stage/warren"
# Every arm64 binary must carry a signature; an ad-hoc one has no identity.
codesign --force --sign - "$stage/warren"
lipo -info "$stage/warren"

cp LICENSE "$stage/LICENSE"
cat >"$stage/README.txt" <<EOF
warren $version: the macOS command-line client

This binary is not signed with an Apple Developer ID or notarized, so macOS
marks it as quarantined when a browser downloads it. Check its SHA-256
against the release page, then remove the mark and install it:

  xattr -d com.apple.quarantine warren
  sudo install -m 0755 warren /usr/local/bin/warren

Then:

  warren login https://warren.example.com   # your organization's URL
  sudo warren up                            # connect; Ctrl-C or warren down to stop
  warren status

See docs/macos.md in https://github.com/terrabyteian/warren for more.
EOF

tar -C "$out" -czf "$out/$name.tar.gz" "$name"
(cd "$out" && shasum -a 256 "$name.tar.gz" >"$name.tar.gz.sha256")
cat "$out/$name.tar.gz.sha256"

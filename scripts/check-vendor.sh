#!/usr/bin/env bash
# Vendor gate: vendor/ must be exactly what `cargo vendor` produces from
# Cargo.lock, with nothing missing, stale or edited. Needs network access to
# crates.io; builds themselves never do (see .cargo/config.toml).
#
# Usage: scripts/check-vendor.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# stdout is only the source-replacement snippet already in .cargo/config.toml.
cargo vendor --locked --quiet vendor >/dev/null

changed=$(git diff --name-status -- vendor; git ls-files --others --exclude-standard -- vendor | sed 's/^/?\t/')
if [ -n "$changed" ]; then
  echo "error: vendor/ does not match Cargo.lock:" >&2
  printf '%s\n' "$changed" | head -n 40 >&2
  echo "vendor check: FAILED. Run 'cargo vendor --locked vendor' and commit the result." >&2
  exit 1
fi
echo "vendor check: ok ($(find vendor -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ') crate(s) match Cargo.lock)"

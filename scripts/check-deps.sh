#!/usr/bin/env bash
# Direct-dependency gate.
#
# Every third-party crate a workspace crate depends on (normal, build or dev)
# must be listed in deps/allowlist.txt for that workspace crate, be declared
# with an exact `=` version, and come from crates.io. Path dependencies must
# stay inside the workspace. Allowlist entries nobody uses fail too, so the
# list always matches reality.
#
# Usage: scripts/check-deps.sh
set -euo pipefail

cd "$(dirname "$0")/.."

allowlist=deps/allowlist.txt
crates_io="registry+https://github.com/rust-lang/crates.io-index"
failed=0

fail() {
  echo "error: $*" >&2
  failed=1
}

entries=$(grep -v '^[[:space:]]*#' "$allowlist" | awk 'NF { print $1, $2 }')

dupes=$(printf '%s\n' "$entries" | awk 'NF { print $1 }' | sort | uniq -d)
for name in $dupes; do
  fail "$allowlist lists $name more than once"
done

metadata=$(cargo metadata --format-version 1 --no-deps --locked --offline)
root=$(printf '%s' "$metadata" | jq -r '.workspace_root')
deps=$(printf '%s' "$metadata" | jq -r '
  .packages[] as $p
  | $p.dependencies[]
  | [$p.name, .name, .req, (.kind // "normal"), (.source // "-"), (.path // "-")]
  | join("|")')

used=""
while IFS='|' read -r member dep req kind source path; do
  [ -n "$member" ] || continue
  if [ "$path" != "-" ]; then
    case "$path" in
      "$root"/*) ;;
      *) fail "$member depends on $dep through a path outside the workspace: $path" ;;
    esac
    continue
  fi
  if [ "$source" != "$crates_io" ]; then
    fail "$member depends on $dep from $source; only crates.io is allowed"
    continue
  fi
  users=$(printf '%s\n' "$entries" | awk -v c="$dep" '$1 == c { print $2 }')
  if [ -z "$users" ]; then
    fail "$member depends on $dep ($kind), which is not in $allowlist"
    continue
  fi
  case ",$users," in
    *",*,"* | *",$member,"*) ;;
    *) fail "$member depends on $dep, but $allowlist allows it only for: $users" ;;
  esac
  case "$req" in
    =*) ;;
    *) fail "$member depends on $dep with requirement '$req'; pin it with '=' in [workspace.dependencies]" ;;
  esac
  used="$used $dep"
done <<<"$deps"

for name in $(printf '%s\n' "$entries" | awk 'NF { print $1 }'); do
  case " $used " in
    *" $name "*) ;;
    *) fail "$allowlist lists $name but no workspace crate uses it; remove the entry" ;;
  esac
done

if [ "$failed" -ne 0 ]; then
  echo "direct dependencies: FAILED (see docs/dependencies.md)" >&2
  exit 1
fi
count=$(printf '%s\n' "$entries" | awk 'NF' | wc -l | tr -d ' ')
echo "direct dependencies: ok ($count allowlisted crate(s), all pinned, all from crates.io)"

#!/usr/bin/env bash
# Tests for scripts/check-dco.sh: builds throwaway repositories with commits by
# the project owner and by outside contributors, signed off or not, and checks
# which ranges the gate accepts.
#
# Usage: scripts/test-check-dco.sh
set -euo pipefail

check="$(cd "$(dirname "$0")" && pwd)/check-dco.sh"
owner="terrabyteian <terrabyteian@users.noreply.github.com>"
outsider="Outside Contributor <outside@example.com>"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# Isolate from the caller's git configuration (hooks, signing, identity).
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

git -C "$work" init -q
git -C "$work" -c user.name=base -c user.email=base@example.com \
  commit -q --allow-empty -m base
base=$(git -C "$work" rev-parse HEAD)

# commit AUTHOR SIGNOFF-IDENTITY|- MESSAGE: prints the new commit's SHA.
commit() {
  local name=${1% <*} email=${1##*<}
  email=${email%>}
  local args=(-q --allow-empty -m "$3")
  if [ "$2" != "-" ]; then
    args+=(--trailer "Signed-off-by: $2")
  fi
  GIT_AUTHOR_NAME=$name GIT_AUTHOR_EMAIL=$email \
    GIT_COMMITTER_NAME=$name GIT_COMMITTER_EMAIL=$email \
    git -C "$work" commit "${args[@]}"
  git -C "$work" rev-parse HEAD
}

failures=0

# expect pass|fail NAME HEAD: runs the gate on base..HEAD.
expect() {
  local want=$1 name=$2 head=$3 got=pass out
  out=$(cd "$work" && "$check" "$base" "$head" 2>&1) || got=fail
  if [ "$got" = "$want" ]; then
    echo "ok: $name"
  else
    echo "FAIL: $name: expected $want, got $got" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    failures=$((failures + 1))
  fi
  git -C "$work" reset -q --hard "$base"
}

expect pass "owner commit without sign-off is exempt" \
  "$(commit "$owner" - "owner, unsigned")"
expect pass "owner commit with sign-off passes" \
  "$(commit "$owner" "$owner" "owner, signed")"
expect pass "owner email matches case-insensitively" \
  "$(commit "terrabyteian <TerrabyteIan@Users.NoReply.GitHub.com>" - "owner, unsigned, mixed case")"
expect pass "outside commit with matching sign-off passes" \
  "$(commit "$outsider" "$outsider" "outsider, signed")"
expect fail "outside commit without sign-off fails" \
  "$(commit "$outsider" - "outsider, unsigned")"
expect fail "outside commit signed off by someone else fails" \
  "$(commit "$outsider" "$owner" "outsider, signed as the owner")"
expect fail "owner-like name with another email is not exempt" \
  "$(commit "terrabyteian <terrabyteian@example.com>" - "lookalike, unsigned")"

commit "$owner" - "owner, unsigned" >/dev/null
expect fail "one unsigned outside commit fails the whole range" \
  "$(commit "$outsider" - "outsider, unsigned, after owner")"

if [ "$failures" -ne 0 ]; then
  echo "check-dco tests: $failures failed" >&2
  exit 1
fi
echo "check-dco tests: all passed"

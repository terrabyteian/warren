#!/usr/bin/env bash
# DCO gate: every non-merge commit in BASE..HEAD must carry a Signed-off-by
# trailer whose email matches the commit author, certifying the Developer
# Certificate of Origin (https://developercertificate.org/). See CONTRIBUTING.md.
#
# Commits authored by the project owner are exempt: the DCO is an attestation
# that outside contributors make about their contributions. The exemption keys
# on the author email, which anyone can set, so maintainers confirm the
# authorship of owner-attributed commits in outside pull requests.
#
# Usage: scripts/check-dco.sh BASE HEAD
set -euo pipefail

owner_emails="terrabyteian@users.noreply.github.com"

if [ $# -ne 2 ]; then
  echo "usage: $0 BASE HEAD" >&2
  exit 2
fi

is_owner() {
  local email
  email=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  for owner in $owner_emails; do
    [ "$email" = "$owner" ] && return 0
  done
  return 1
}

failed=0
signed=0
exempt=0
for commit in $(git rev-list --no-merges "$1..$2"); do
  email=$(git log -1 --format='%ae' "$commit")
  if git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$commit" |
    grep -qiF "<$email>"; then
    signed=$((signed + 1))
  elif is_owner "$email"; then
    exempt=$((exempt + 1))
  else
    echo "error: $(git log -1 --format='%h %s' "$commit")" >&2
    echo "       has no 'Signed-off-by: ... <$email>' trailer (use git commit -s)" >&2
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "DCO check: FAILED. Amend with 'git commit --amend -s' or 'git rebase --signoff $1'." >&2
  exit 1
fi
echo "DCO check: ok ($signed commit(s) signed off, $exempt by the project owner)"

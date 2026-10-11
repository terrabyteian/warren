#!/usr/bin/env bash
# DCO gate: every non-merge commit in BASE..HEAD must carry a Signed-off-by
# trailer whose email matches the commit author, certifying the Developer
# Certificate of Origin (https://developercertificate.org/). See CONTRIBUTING.md.
#
# Usage: scripts/check-dco.sh BASE HEAD
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 BASE HEAD" >&2
  exit 2
fi

failed=0
checked=0
for commit in $(git rev-list --no-merges "$1..$2"); do
  checked=$((checked + 1))
  email=$(git log -1 --format='%ae' "$commit")
  if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$commit" |
    grep -qiF "<$email>"; then
    echo "error: $(git log -1 --format='%h %s' "$commit")" >&2
    echo "       has no 'Signed-off-by: ... <$email>' trailer (use git commit -s)" >&2
    failed=1
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "DCO check: FAILED. Amend with 'git commit --amend -s' or 'git rebase --signoff $1'." >&2
  exit 1
fi
echo "DCO check: ok ($checked commit(s) signed off)"

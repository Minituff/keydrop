#!/bin/sh
# Fails if the tree contains anything from $KEYDROP_LEAK_PATTERNS: one
# case-insensitive extended regex per line, for the maintainer's own
# addresses, domains and host names. The list is a repository secret so
# this file doesn't publish it. Matches are reported by location only.
#
# --history checks every commit, commit message and author too; run it
# before making the repository public.
set -eu
if [ -z "${KEYDROP_LEAK_PATTERNS:-}" ]; then
  echo "::notice::KEYDROP_LEAK_PATTERNS isn't set; skipping the leak check"
  exit 0
fi
pf=$(mktemp)
trap 'rm -f "$pf"' EXIT
printf '%s\n' "$KEYDROP_LEAK_PATTERNS" | grep -v '^[[:space:]]*$' >"$pf"
found=0
report() { echo "::error::$1"; found=1; }

if [ "${1:-}" = --history ]; then
  for c in $(git rev-list --all); do
    for f in $(git grep -I -i -l -E -f "$pf" "$c" -- . | cut -d: -f2-); do
      report "commit $(git rev-parse --short "$c"): $f"
    done
    if git log -1 --format='%an%n%ae%n%cn%n%ce' "$c" | grep -qiEf "$pf"; then
      report "commit $(git rev-parse --short "$c"): author or committer"
    fi
    if git log -1 --format=%B "$c" | grep -qiEf "$pf"; then
      report "commit $(git rev-parse --short "$c"): message"
    fi
  done
else
  for loc in $(git grep -I -i -n -E -f "$pf" -- . | cut -d: -f1,2); do
    report "$loc"
  done
fi
if [ "$found" = 1 ]; then
  echo "Homelab details found (locations above; contents not shown)." >&2
  exit 1
fi
echo "No matches."

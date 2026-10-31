#!/bin/sh
# Fails if the tree contains anything from $KEYDROP_LEAK_PATTERNS: one
# case-insensitive extended regex per line, for the maintainer's own
# addresses, domains and host names. The list is a repository secret so
# this file doesn't publish it. Matches are reported by location only.
#
# --history checks every commit, commit message and author too; run it
# before making the repository public.
#
# It fails closed: a pattern grep can't compile, or a grep/git error
# (exit 2 or more), fails the check instead of reading as "no matches".
set -eu
if [ -z "${KEYDROP_LEAK_PATTERNS:-}" ]; then
  # Forks and local runs have no secret. Say loudly that nothing was checked.
  echo "::warning::KEYDROP_LEAK_PATTERNS isn't set: the leak check did NOT run"
  echo "WARNING: KEYDROP_LEAK_PATTERNS isn't set; nothing was checked." >&2
  exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
pf=$tmp/patterns
printf '%s\n' "$KEYDROP_LEAK_PATTERNS" | grep -v '^[[:space:]]*$' >"$pf" || true
if [ ! -s "$pf" ]; then
  echo "::error::KEYDROP_LEAK_PATTERNS has no patterns"
  exit 2
fi
# Compile every pattern once against empty input: 1 is "no match" (fine),
# 2 or more is a broken pattern.
rc=0
grep -i -E -f "$pf" </dev/null >/dev/null 2>&1 || rc=$?
if [ "$rc" -ge 2 ]; then
  # Name the broken lines by number only; the patterns themselves are secret.
  n=0
  while IFS= read -r p; do
    n=$((n + 1))
    prc=0
    printf '%s\n' "$p" >"$tmp/one"
    grep -i -E -f "$tmp/one" </dev/null >/dev/null 2>&1 || prc=$?
    if [ "$prc" -ge 2 ]; then
      echo "::error::KEYDROP_LEAK_PATTERNS line $n isn't a valid extended regex"
    fi
  done <"$pf"
  echo "::error::invalid pattern(s) in KEYDROP_LEAK_PATTERNS; nothing was checked"
  exit 2
fi

found=0
report() { echo "::error::$1"; found=1; }
fail() {
  echo "::error::$1 failed (exit $2); the check can't vouch for anything"
  exit 2
}

# grepto OUT CMD...: run a grep-like command with its output in OUT. Exit 0
# and 1 are results (match, no match); anything else is an error.
grepto() {
  out=$1
  shift
  rc=0
  "$@" >"$out" 2>"$tmp/err" || rc=$?
  if [ "$rc" -ge 2 ]; then
    cat "$tmp/err" >&2
    fail "$1" "$rc"
  fi
}

if [ "${1:-}" = --history ]; then
  git rev-list --all >"$tmp/commits" || fail "git rev-list" $?
  while IFS= read -r c; do
    short=$(git rev-parse --short "$c") || fail "git rev-parse" $?
    grepto "$tmp/files" git grep -I -i -l -E -f "$pf" "$c" -- .
    while IFS= read -r f; do
      report "commit $short: ${f#*:}"
    done <"$tmp/files"
    git log -1 --format='%an%n%ae%n%cn%n%ce' "$c" >"$tmp/who" || fail "git log" $?
    grepto "$tmp/hit" grep -iEf "$pf" "$tmp/who"
    if [ -s "$tmp/hit" ]; then report "commit $short: author or committer"; fi
    git log -1 --format=%B "$c" >"$tmp/msg" || fail "git log" $?
    grepto "$tmp/hit" grep -iEf "$pf" "$tmp/msg"
    if [ -s "$tmp/hit" ]; then report "commit $short: message"; fi
  done <"$tmp/commits"
else
  grepto "$tmp/hits" git grep -I -i -n -E -f "$pf" -- .
  cut -d: -f1,2 "$tmp/hits" >"$tmp/locs"
  while IFS= read -r loc; do
    report "$loc"
  done <"$tmp/locs"
fi
if [ "$found" = 1 ]; then
  echo "Homelab details found (locations above; contents not shown)." >&2
  exit 1
fi
echo "No matches."

#!/bin/sh
# Regression tests for leak-check.sh, run by CI: it must find a match, pass
# a clean tree, and fail closed on a broken pattern instead of reporting
# "No matches."
set -eu
script=$(cd "$(dirname "$0")" && pwd)/leak-check.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q .
git config user.name test
git config user.email test@example.com
echo "host = 192.168.1.50" >config.txt
git add config.txt
git commit -q -m init

fails=0
expect() { # expect WANT-EXIT DESCRIPTION PATTERNS [ARGS]; $required is passed on
  want=$1 desc=$2 pats=$3
  shift 3
  rc=0
  KEYDROP_LEAK_REQUIRED=${required:-} KEYDROP_LEAK_PATTERNS=$pats sh "$script" "$@" >out 2>&1 || rc=$?
  if [ "$rc" != "$want" ]; then
    echo "FAIL: $desc: exit $rc, want $want"
    sed 's/^/    /' out
    fails=1
  else
    echo "ok: $desc"
  fi
}

expect 1 "a match fails" '192\.168\.1\.50'
expect 1 "a match fails in --history" '192\.168\.1\.50' --history
expect 0 "a clean tree passes" 'nothing-like-this'
expect 0 "a clean history passes" 'nothing-like-this' --history
expect 2 "an invalid pattern fails closed" 'a(b'
expect 2 "an invalid pattern fails closed in --history" 'a(b' --history
expect 2 "one bad line among good ones fails closed" "$(printf 'ok\n[unclosed\n')"
expect 1 "a pattern with trailing spaces still matches" '192\.168\.1\.50   '
expect 1 "a pattern with leading spaces still matches" '  192\.168\.1\.50'
expect 1 "a CRLF line end is trimmed" "$(printf 'nothing-like-this\r\n192\\.168\\.1\\.50\r\n')"
expect 1 "a tab-indented pattern among blank lines matches" "$(printf '\n  \n\t192\\.168\\.1\\.50\t\n\n')"
expect 2 "only whitespace lines is no patterns" "$(printf '  \n\t\n')"
expect 0 "unset patterns skip" ''
if ! grep -q "did NOT run" out; then
  echo "FAIL: skipping didn't warn"
  fails=1
fi
expect 0 "unset patterns skip in --history" '' --history
required=1
expect 2 "unset patterns fail when required" ''
expect 2 "unset patterns fail when required, in --history" '' --history
expect 2 "only whitespace lines fail when required" "$(printf '  \n')"
expect 1 "required still finds a match" '192\.168\.1\.50'
expect 0 "required passes a clean tree" 'nothing-like-this'
required=0
expect 0 "only 1 means required" ''
required=
if KEYDROP_LEAK_PATTERNS='a(b' sh "$script" 2>&1 | grep -q "No matches"; then
  echo "FAIL: a broken pattern printed No matches"
  fails=1
fi
exit "$fails"

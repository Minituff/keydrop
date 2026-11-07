#!/bin/sh
# Checks scripts/release-version.sh: what each tag publishes, and what it
# refuses. A mistake there would move :latest.
set -u
sha=0123456789abcdef
fails=0

want() { # TAG ON_MAIN VERSION SEMVER LATEST PRERELEASE
  got=$(sh scripts/release-version.sh "$1" "$2" "$sha" | tr '\n' ' ')
  exp="tag=$1 version=$3 semver=$4 latest=$5 prerelease=$6 "
  if [ "$got" != "$exp" ]; then
    echo "$1 on_main=$2: got '$got', want '$exp'"
    fails=$((fails + 1))
  fi
}

refused() { # TAG
  if sh scripts/release-version.sh "$1" true "$sha" >/dev/null 2>&1; then
    echo "'$1' should be refused"
    fails=$((fails + 1))
  fi
}

want v1.2.3 true v1.2.3 true true false
want v1.2.3 false v1.2.3 true false true
want v1.2.3-rc.1 true v1.2.3-rc.1 true false true
want dev false dev-0123456 false false true
want dev true dev-0123456 false false true
want feature_x.1 false feature_x.1-0123456 false false true

refused latest
refused 1.2.3
refused ''
refused '-x'
refused 'a b'
refused 'a;b'
refused "$(printf 'x%.0s' $(seq 65))"
refused "$(printf 'dev\nlatest=true')"

[ "$fails" = 0 ] && echo "release-version: ok"
exit "$fails"

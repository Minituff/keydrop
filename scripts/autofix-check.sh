#!/bin/sh
# The autofix routine's prompt and setup script live on claude.ai, pasted
# from .github/autofix/. Its README records the sha256 of the versions the
# live routine uses; this fails while a file differs from what's recorded,
# so a change here can't go unnoticed while the routine runs the old one.
set -eu
dir=${1:-"$(dirname "$0")/../.github/autofix"}
bad=0
for f in prompt.md setup.sh; do
  want=$(sed -n "s/^\([0-9a-f]\{64\}\)  $f\$/\1/p" "$dir/README.md")
  if [ -z "$want" ]; then
    echo "::error::$dir/README.md records no sha256 for $f"
    bad=1
    continue
  fi
  have=$(sha256sum "$dir/$f" | cut -d ' ' -f 1)
  if [ "$have" != "$want" ]; then
    echo "::error::.github/autofix/$f changed: paste it into the autofix routine (or its environment) on claude.ai, then record its new sha256 in .github/autofix/README.md: $have  $f"
    bad=1
  fi
done
[ "$bad" = 0 ] || exit 1
echo "The autofix routine's prompt and setup match .github/autofix/README.md"

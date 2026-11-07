#!/bin/sh
# Works out what a run of release.yml publishes, as name=value lines for
# $GITHUB_OUTPUT. Usage: release-version.sh TAG ON_MAIN SHA
#
#   v1.2.3 from main    a full release: GitHub release, image, :latest
#   v1.2.3 elsewhere,   a pre-release: GitHub release and image, no :latest
#   or v1.2.3-rc.1
#   any other name      an image with that tag and nothing else, e.g. dev
set -eu
tag=$1
on_main=$2
sha=$3

# case, not grep: grep checks line by line, so a newline would get through
# and write its own lines into $GITHUB_OUTPUT.
case $tag in
'' | [!A-Za-z0-9]* | *[!A-Za-z0-9._-]*)
  echo "::error::a tag is letters, digits, '.', '_' and '-', and starts with a letter or digit" >&2
  exit 1
  ;;
esac
if [ "${#tag}" -gt 64 ]; then
  echo "::error::a tag is at most 64 characters" >&2
  exit 1
fi
if [ "$tag" = latest ]; then
  echo "::error::latest is set by a release from main, never by hand" >&2
  exit 1
fi
if printf '%s' "$tag" | grep -Eq '^[0-9]'; then
  echo "::error::version tags start with v, like v1.2.3" >&2
  exit 1
fi

semver=false
latest=false
version=$tag-$(printf '%s' "$sha" | cut -c1-7)
if printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  semver=true
  version=$tag
  if [ "$on_main" = true ] && printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    latest=true
  fi
fi
prerelease=true
[ "$latest" = false ] || prerelease=false

echo "tag=$tag"
echo "version=$version"
echo "semver=$semver"
echo "latest=$latest"
echo "prerelease=$prerelease"

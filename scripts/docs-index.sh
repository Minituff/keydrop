#!/bin/sh
# docs/index.md, the docs site's home page, is README.md with its links
# rewritten for MkDocs. Run this after editing the README; with --check it
# only fails (as CI does) when the two have drifted.
set -eu
cd "$(dirname "$0")/.."
gh=https://github.com/Minituff/keydrop/blob/main
render() {
  printf '<!-- Generated from README.md by scripts/docs-index.sh. Edit the README, then run it. -->\n'
  sed -e 's|<div align="center">|<div align="center" markdown>|' \
      -e 's|docs/images/|images/|g' \
      -e 's|](docs/|](|g' \
      -e 's|href="docs/\([a-z_-]*\)\.md"|href="\1/"|g' \
      -e "s|](LICENSE)|]($gh/LICENSE)|g" \
      -e "s|](go.mod)|]($gh/go.mod)|g" \
      -e "s|](compose.example.yml)|]($gh/compose.example.yml)|g" \
      README.md
}
if [ "${1:-}" = --check ]; then
  if ! render | cmp -s - docs/index.md; then
    echo "docs/index.md is out of date: run sh scripts/docs-index.sh" >&2
    exit 1
  fi
else
  render > docs/index.md
fi

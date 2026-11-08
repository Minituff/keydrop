#!/bin/bash
# The keydrop-autofix environment's setup script (paste it in full). Installs
# the Go that go.mod's toolchain line names, checked against the sha256 go.dev
# publishes, and stops Go from fetching modules or toolchains: keydrop has no
# modules, so the network list needs no Go proxy.
set -euo pipefail

# This may run before the repo is cloned: then read go.mod from main.
if [ -f go.mod ]; then
  mod=$(cat go.mod)
else
  mod=$(curl -fsSL https://raw.githubusercontent.com/Minituff/keydrop/main/go.mod)
fi
v=$(printf '%s\n' "$mod" | sed -n 's/^toolchain \(go[0-9][0-9.]*\)[[:space:]]*$/\1/p')
if [ -z "$v" ]; then
  echo "go.mod has no toolchain line" >&2
  exit 1
fi
case $(uname -m) in
aarch64 | arm64) a=arm64 ;;
x86_64 | amd64) a=amd64 ;;
*) echo "unsupported machine $(uname -m)" >&2; exit 1 ;;
esac
f="$v.linux-$a.tar.gz"

# go.dev lists every release's files with their sha256. One object per file:
# split on '{' and pick the one with this filename (no jq on every image).
sum=$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' | tr -d '\n' | tr '{' '\n' |
  { grep -F "\"filename\": \"$f\"" || true; } | sed -n 's/.*"sha256": *"\([0-9a-f]\{64\}\)".*/\1/p')
if [ "$(printf '%s\n' "$sum" | grep -c .)" != 1 ]; then
  echo "go.dev lists no single sha256 for $f" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$f" "https://dl.google.com/go/$f"
echo "$sum  $tmp/$f" | sha256sum -c -
rm -rf /usr/local/go
tar -C /usr/local -xzf "$tmp/$f"
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

# Persistent (go env -w writes the user's go env file): use only this Go and
# never reach a module proxy or checksum database.
go env -w GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
go version

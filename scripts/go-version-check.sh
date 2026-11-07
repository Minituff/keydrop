#!/bin/sh
# Fails unless the Go version in go.mod's toolchain line and the Dockerfile's
# build image are the same: CI tests with the first and ships the second.
set -eu
mod=$(sed -n 's/^toolchain go//p' go.mod)
img=$(sed -n 's/^FROM .*golang:\([0-9][0-9.]*\)-.*/\1/p' Dockerfile)
if [ -z "$mod" ] || [ -z "$img" ]; then
  echo "::error::couldn't read the Go version (go.mod: '$mod', Dockerfile: '$img')"
  exit 1
fi
if [ "$mod" != "$img" ]; then
  echo "::error::go.mod says Go $mod but the Dockerfile builds with $img"
  exit 1
fi
echo "Go $mod in go.mod and the Dockerfile"

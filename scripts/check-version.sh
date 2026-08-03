#!/usr/bin/env sh
set -eu

version="$(tr -d '\r\n' < VERSION)"
test -n "$version"

grep -Fq "Version = \"${version}-dev\"" internal/buildinfo/buildinfo.go
grep -Fq "@v${version}" README.md
grep -Fq "## [${version}]" CHANGELOG.md

if [ -n "${GITHUB_REF_NAME:-}" ] && [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  test "${GITHUB_REF_NAME}" = "v${version}"
fi

printf 'version references are consistent with %s\n' "$version"

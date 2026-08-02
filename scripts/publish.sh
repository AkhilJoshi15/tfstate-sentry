#!/usr/bin/env bash
set -euo pipefail

repo_url="${1:-https://github.com/AkhilJoshi15/tfstate-sentry.git}"
source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }

git clone "$repo_url" "$workdir/repo"

# Copy the release tree while preserving the cloned repository metadata.
tar -C "$source_root" \
  --exclude=.git \
  --exclude=bin \
  --exclude=dist \
  -cf - . | tar -C "$workdir/repo" -xf -

cd "$workdir/repo"
git add --all

if git diff --cached --quiet; then
  echo "No changes to publish."
  exit 0
fi

if [[ -z "$(git config user.name || true)" || -z "$(git config user.email || true)" ]]; then
  echo "Configure git user.name and user.email before publishing." >&2
  exit 1
fi

git commit -m "feat: publish initial Terraform state exposure scanner"
git push origin main

echo "Published main. Review the CI workflow before creating tag v0.1.0."

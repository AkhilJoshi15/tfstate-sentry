# Publishing

The repository publisher deliberately runs on the maintainer's machine so GitHub credentials never enter source archives, CI logs, or chat messages.

## Authenticate

Use GitHub CLI or Git Credential Manager. Never place a personal access token in a command, script, repository file, or chat message.

```bash
gh auth login
```

## Publish `main`

Linux or macOS:

```bash
./scripts/publish.sh
```

Windows PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\publish.ps1
```

The script clones the existing repository into a temporary directory, overlays this release tree, creates one commit, and pushes `main`.

## Create a release

After the CI and Security workflows pass:

```bash
git clone https://github.com/AkhilJoshi15/tfstate-sentry.git
cd tfstate-sentry
make check-version
git tag -a v0.2.0 -m "tfstate-sentry v0.2.0"
git push origin v0.2.0
```

The Release workflow reruns race tests, builds Linux, macOS, and Windows archives, creates an SPDX SBOM and SHA-256 checksums, signs artifacts with keyless Sigstore, and publishes the GitHub release. Verify that the tag matches `VERSION` before pushing it.

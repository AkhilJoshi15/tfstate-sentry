# tfstate-sentry

A Terraform-native analyzer that detects confidential values being persisted into state or plan data and recommends safer alternatives without printing the values.

```bash
tfstate-sentry plan --fail-on high -- -var-file=prod.tfvars
```

> Early development release. Use synthetic or approved test data only.

## Why

Terraform can mark values as sensitive to hide them in normal terminal output while still storing them in plan and state artifacts. Machine-readable `terraform show -json` output contains those values, along with sensitivity metadata that consumers are expected to honor.

`tfstate-sentry` turns that metadata, provider schemas, recursive structure analysis, and credential signatures into a CI-friendly security gate.

## Current capabilities

- raw `terraform.tfstate` JSON
- `terraform show -json` state output
- `terraform show -json` plan output
- provider schema sensitivity metadata
- provider write-only (`_wo`) alternative discovery
- recursive nested maps, lists, and JSON strings
- known credential structures and high-risk resources
- terminal, JSON, and SARIF 2.1.0 output
- deterministic fingerprints that never include secret values
- tfstate-sentry sends no telemetry and makes no direct network requests. Terraform itself may contact configured backends, providers, and cloud APIs.

## One-command plan gate

Run the one-command workflow from a trusted CI runner or workstation:

```bash
tfstate-sentry plan --fail-on high -- -var-file=prod.tfvars
```

The command does the following:

1. Runs `terraform plan`
2. Retrieves the provider schema
3. Converts the saved plan to JSON in memory
4. Scans for persisted confidential values
5. Deletes rejected plans
6. Retains approved plans for `terraform apply`

After a successful scan, apply the retained plan with:

```bash
terraform apply .tfstate-sentry/tfplan
```

For audit-only behavior that discards the plan after scanning, use:

```bash
tfstate-sentry plan --discard-plan --fail-on high
```

## Install

Download a prebuilt binary from GitHub Releases, or install with Go:

```bash
go install github.com/AkhilJoshi15/tfstate-sentry/cmd/tfstate-sentry@v0.1.0
```

## Build

Requires Go 1.25 or newer. CI and releases use Go 1.26.x.

```bash
make build
./bin/tfstate-sentry version
```

## Advanced: scan existing artifacts

If you already have Terraform artifacts on disk, you can scan them explicitly:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
terraform providers schema -json > provider-schema.json

./bin/tfstate-sentry scan \
  --schema provider-schema.json \
  --fail-on high \
  tfplan.json

rm -f tfplan tfplan.json provider-schema.json
```

Scan from stdin to avoid writing plan JSON to disk:

```bash
terraform show -json tfplan | \
  ./bin/tfstate-sentry scan --schema provider-schema.json -
```

## Example result

```text
HIGH  terraform.sensitive-persisted
Resource:    aws_db_instance.main
Path:        password
Finding:     A Terraform-sensitive value is persisted in plan or state data.
Remediation: Replace password with provider-supported write-only argument password_wo and supply it from an ephemeral value where possible.
Value:       [REDACTED]
```

## CI usage

Use the one-command workflow in GitHub Actions or another CI system:

```yaml
steps:
  - uses: actions/checkout@v6
  - uses: actions/setup-go@v7
    with:
      go-version: '1.26.x'
      check-latest: true
      cache: true
  - run: make build
  - run: ./bin/tfstate-sentry plan --fail-on high -- -var-file=prod.tfvars
```

## Security model

Never commit plan, state, or generated JSON files. Terraform plan and state JSON can contain secrets in plaintext.

tfstate-sentry detects exposure. It does not encrypt, redact, or modify Terraform state.

Approved binary plans can still contain secrets. Terraform explicitly states that saved plans include full values, including sensitive data in cleartext.

## Limitations

- tfstate-sentry detects exposure; it does not encrypt or remove secrets from existing state.
- Provider write-only support varies by provider and version.
- Approved binary plans can still contain plaintext values.
- Detection may produce false positives.
- Early releases should use synthetic or approved test data.

## Demo

All fixtures are synthetic and invalid:

```bash
make scan-demo
```

Approved binary plans can still contain secrets. Terraform explicitly states that saved plans include full values, including sensitive data in cleartext.

Example output:

```text
HIGH  terraform.sensitive-persisted
Resource:    aws_db_instance.main
Path:        password
Finding:     A Terraform-sensitive value is persisted in plan or state data.
Remediation: Replace password with provider-supported write-only argument password_wo and supply it from an ephemeral value where possible.
Value:       [REDACTED]
```

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Scan completed and threshold was not met |
| 1 | Input or runtime error |
| 2 | Invalid CLI usage |
| 3 | Finding met or exceeded `--fail-on` |

## SARIF

```bash
./bin/tfstate-sentry scan \
  --schema provider-schema.json \
  --format sarif \
  --output tfstate-sentry.sarif \
  --fail-on none \
  tfplan.json
```

The SARIF output can be uploaded to GitHub code scanning with `github/codeql-action/upload-sarif` where GitHub Code Security is available.

## Development

```bash
make fmt
make vet
make test
make build
```

See [the threat model](docs/threat-model.md), [clean-room rules](docs/clean-room-development.md), [publishing guide](docs/publishing.md), [security policy](SECURITY.md), and [contribution guide](CONTRIBUTING.md).

## Releases

The initial v0.1.0 release is available from GitHub Releases. Future semantic-version tags automatically run tests, cross-compile binaries, generate checksums, and publish a release.

## License

MIT

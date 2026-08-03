# Repository instructions

## Security

- Never print or persist detected secret values.
- Never commit Terraform state, saved plans, generated plan JSON, provider schemas or credentials.
- Use synthetic fixtures only.
- Preserve offline-by-default behavior.

## Required checks

Run after code changes:

```bash
go fmt ./...
go test ./...
go vet ./...
```

Run race tests in Linux CI:

```bash
go test -race ./...
```

## Git

- Never force-push.
- Keep commits focused.
- Separate formatting, feature and release-metadata changes.
- Show the final diff and validation results before committing.

## Design

- Findings must contain paths and metadata, never secret values.
- Baselines and manifests must not contain secret values.
- Rejected plans must be removed.
- Approved plans must remain protected as sensitive artifacts.

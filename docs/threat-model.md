# Threat model

## Protected assets

- credentials and private keys stored in Terraform plan or state data
- secret-manager payloads
- database passwords and connection strings
- infrastructure metadata in reports

## Primary threats

1. A secret is persisted into Terraform state even though CLI output hides it.
2. A machine-readable plan exposes sensitive values during CI.
3. A scanner prints, uploads, or stores the secret while trying to detect it.
4. Reports expose enough infrastructure metadata to aid an attacker.

## Security boundaries

- Input is untrusted JSON and is capped at 100 MiB.
- The scanner performs no network requests.
- Findings contain resource address, attribute path, evidence category, remediation, and a fingerprint derived only from metadata.
- Output files are created with mode `0600`.
- Secret values are never used in fingerprints.

## Non-goals for v0.1

- credential verification against live services
- automatic state rewriting
- automatic secret rotation
- remote collection of organization state files

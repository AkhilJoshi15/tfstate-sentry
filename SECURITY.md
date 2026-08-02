# Security policy

## Reporting a vulnerability

Do not open a public issue for vulnerabilities that could expose Terraform plan or state data.
Use GitHub private vulnerability reporting for this repository.

Include:

- affected version or commit
- reproduction steps using synthetic data
- impact
- suggested remediation, if known

Do not include real credentials, production state files, customer information, or employer-confidential material.

## Security guarantees

`tfstate-sentry` is designed to report metadata about a finding, never the detected value.
The tool operates locally and has no telemetry.
Reports should still be treated as sensitive because resource addresses and infrastructure structure can be confidential.

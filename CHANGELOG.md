# Changelog

All notable changes to this project will be documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Added a one-command plan workflow that runs Terraform, scans the saved plan, and writes a verification manifest containing plan metadata and integrity information.
- Added Terraform-backed integration tests covering unsafe and safe plan flows.
- Expanded scanner documentation with a stronger README narrative around plan gating, CI usage, and limitations.

### Changed

- Strengthened the scanner’s handling of Terraform plan and state surfaces, including variables, outputs, prior state, and sensitivity-aware traversal.
- Improved provider schema handling for data-source schemas and nested attributes.
- Tightened the detector so generic high-risk resource findings require actual persisted-secret evidence.

## [0.1.0] - 2026-08-02

### Added

- Scan raw Terraform state JSON and `terraform show -json` plan/state output.
- Read provider schema sensitivity metadata.
- Discover provider-supported write-only (`_wo`) alternatives.
- Detect nested JSON secrets, credential structures, and high-risk resources.
- Produce redacted terminal, JSON, and SARIF reports.
- Enforce CI thresholds with stable exit codes.
- Include synthetic fixtures, unit tests, race tests, and release automation.

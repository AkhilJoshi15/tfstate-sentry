# Changelog

All notable changes to this project will be documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-08-03

### Added

- Added a one-command plan workflow that runs Terraform, scans the saved plan, and writes a verification manifest containing plan metadata and integrity information.
- Added `--discard-plan` for audit-only workflows that must not retain approved plans.
- Added Terraform-backed integration tests covering unsafe, safe, discarded, and cleanup flows.
- Added unit tests for model, reporting, build metadata, command validation, and failure paths.
- Added a large-plan scanner benchmark and release-version consistency checks.
- Added release SBOM generation and keyless Sigstore signatures for published artifacts.
- Expanded scanner documentation with a stronger README narrative around plan gating, CI usage, and limitations.

### Changed

- Strengthened the scanner’s handling of Terraform plan and state surfaces, including variables, outputs, prior state, and sensitivity-aware traversal.
- Improved provider schema handling for data-source schemas and nested attributes.
- Tightened the detector so generic high-risk resource findings require actual persisted-secret evidence.
- Consolidated overlapping signals at the same resource path, preferring the strongest evidence to reduce alert fatigue.
- Restricted the plan workspace and retained binary plan to owner-only permissions where supported.

### Fixed

- Removed rejected plans and temporary plan JSON/provider-schema files after scans so sensitive generated artifacts do not linger.
- Implemented the documented `--discard-plan` behavior and honored an explicitly supplied provider schema during plan scans.
- Aligned direct builds, Makefile builds, installation instructions, publishing documentation, and release tags on version 0.2.0.

## [0.1.0] - 2026-08-02

### Added

- Scan raw Terraform state JSON and `terraform show -json` plan/state output.
- Read provider schema sensitivity metadata.
- Discover provider-supported write-only (`_wo`) alternatives.
- Detect nested JSON secrets, credential structures, and high-risk resources.
- Produce redacted terminal, JSON, and SARIF reports.
- Enforce CI thresholds with stable exit codes.
- Include synthetic fixtures, unit tests, race tests, and release automation.

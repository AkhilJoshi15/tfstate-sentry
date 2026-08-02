# Changelog

All notable changes to this project will be documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-08-02

### Added

- Scan raw Terraform state JSON and `terraform show -json` plan/state output.
- Read provider schema sensitivity metadata.
- Discover provider-supported write-only (`_wo`) alternatives.
- Detect nested JSON secrets, credential structures, and high-risk resources.
- Produce redacted terminal, JSON, and SARIF reports.
- Enforce CI thresholds with stable exit codes.
- Include synthetic fixtures, unit tests, race tests, and release automation.

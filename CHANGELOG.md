# Changelog

All notable changes to this project. Each entry links to its full per-version file in [changelog/](changelog/).

## [0.1.10](changelog/0.1.x/0.1.10.md) — 2026-06-04

Fix false errors from empty results in nvd_audit_cpe and nvd_get_cve_history

## [0.1.9](changelog/0.1.x/0.1.9.md) — 2026-06-02

mcp-ts-core 0.9.21 — per-request log context fix, secret-stripped error messages, fail-fast retries

## [0.1.8](changelog/0.1.x/0.1.8.md) — 2026-05-30

Enrichment adoption — CVE/CPE search tools surface result totals, pagination, and empty-result guidance via the typed enrichment block

## [0.1.7](changelog/0.1.x/0.1.7.md) — 2026-05-28

Adopt mcp-ts-core ^0.9.13; error-contract corrections (InvalidParams → ValidationError) across all tools; dependency refresh

## [0.1.6](changelog/0.1.x/0.1.6.md) — 2026-05-26

Add publish-mcp script to package.json

## [0.1.5](changelog/0.1.x/0.1.5.md) — 2026-05-26

FUNDING.yml, hosted server URL, Bun badge fix, manifest.json in files array

## [0.1.4](changelog/0.1.x/0.1.4.md) — 2026-05-24

Drop tsx, align all scripts to bun-native execution, revert Dockerfile to oven/bun:1.3, add funding block, bump typescript ^5.9.3 → ^6.0.3

## [0.1.3](changelog/0.1.x/0.1.3.md) — 2026-05-24

Field-test fixes: CVSS v2 severity derivation, CPE format validation, invalid date errors, severity/version cross-check, offset-past-end message, and description accuracy.

## [0.1.2](changelog/0.1.x/0.1.2.md) — 2026-05-24

Scope npm package to @cyanheads/nist-nvd-mcp-server.

## [0.1.1](changelog/0.1.x/0.1.1.md) — 2026-05-24

Launch release — full implementation: 5 tools, 1 resource, 3 services, 65 tests; field-test fixes for date validation, missing ID tracking, and error classification.

## [0.1.0](changelog/0.1.x/0.1.0.md) — 2026-05-24

Initial release — 5 tools and 1 resource for searching and auditing NIST NVD CVEs, CPEs, and change history.

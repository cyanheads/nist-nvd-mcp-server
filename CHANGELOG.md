# Changelog

All notable changes to this project. Each entry links to its full per-version file in [changelog/](changelog/).

## [0.3.0](changelog/0.3.x/0.3.0.md) — 2026-08-24 · ⚠️ Breaking

nvd_get_cve and nvd_audit_cpe replace their configurations output field with configurationNodes — a flat array of nodes, each tagged with the group it came from — on mcp-ts-core 0.12.3.

## [0.2.0](changelog/0.2.x/0.2.0.md) — 2026-07-31 · ⚠️ Breaking

weaknesses[].source and references[].source now resolve NVD's contributor identifiers to published names (e.g. CVE, CISA-ADP) instead of raw GUIDs — a breaking value-format change with no schema change to warn consumers on upgrade.

## [0.1.19](changelog/0.1.x/0.1.19.md) — 2026-07-31

nvd_audit_cpe and nvd_get_cve share one CveRecord schema; nvd_get_cve's advertised item schema now covers full mode, the default, instead of brief mode only; nvd_get_cve_history gains empty/partial-page notices; an NVD parameter rejection on a CPE input now translates to invalid_cpe_format on nvd_audit_cpe and nvd_search_cpes.

## [0.1.18](changelog/0.1.x/0.1.18.md) — 2026-07-31

nvd_search_cves gains exactPhrase for phrase matching; nvd_audit_cpe returns an empty success instead of cpe_not_found for a target with no known CVEs; CVSS extraction keeps 0.0-scored entries and reads NVD's own v2 baseSeverity instead of deriving it; docs/design.md corrected from InvalidParams to ValidationError.

## [0.1.17](changelog/0.1.x/0.1.17.md) — 2026-07-27

nvd_search_cves, nvd_search_cpes, and nvd_audit_cpe distinguish an offset past the result set from an empty page NVD returned inside a range it says has matches; nvd_search_cves and nvd_audit_cpe gain a next-page notice; nvd_get_cve's brief mode now shares its row builder with nvd_search_cves instead of duplicating it inline.

## [0.1.16](changelog/0.1.x/0.1.16.md) — 2026-07-27

nvd_audit_cpe and nvd_search_cpes gain offset paging; nvd_get_cve's format() renders CPE match criteria and every language a record carries instead of a bare count and English-only text; search results carry a truncated description; docs/design.md and README describe the enrichment block instead of the removed queryMeta envelope.

## [0.1.15](changelog/0.1.x/0.1.15.md) — 2026-07-27

nvd_get_cve_history gains an order input (newest/oldest) and no longer loses pages carrying Affected/SSVC change values; invalid_cve_id_format and cve_not_found now carry their declared recovery hints; nvd_search_cves' severity filter is documented as exact-band, not a floor.

## [0.1.14](changelog/0.1.x/0.1.14.md) — 2026-07-16

Filter context (filtersApplied, severityMin/filteredCount) and per-row filteredSeverity now surface why a nvd_search_cves or nvd_audit_cpe result set is narrow or empty; full-record descriptions default to English with an allLanguages opt-in; rate_limited corrected to declare RateLimited across all five tools.

## [0.1.13](changelog/0.1.x/0.1.13.md) — 2026-07-15

NVD retries now pace through the rate-limit queue instead of bursting inside it, and nvd_audit_cpe renders CPE match criteria instead of bare operator lines. mcp-ts-core ^0.10.14, Socket install scanning, 8 transitive advisories cleared.

## [0.1.12](changelog/0.1.x/0.1.12.md) — 2026-06-20

mcp-ts-core ^0.10.9 maintenance — vendored framework skills/scripts resynced (check-dependency-specifiers, plugin-manifest packaging checks), dev-dep refresh. No server behavior change.

## [0.1.11](changelog/0.1.x/0.1.11.md) — 2026-06-12

mcp-ts-core 0.10.6 — enrichment total() helper, explicit createApp identity, Docker healthcheck, MCPB agent-doc strip

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

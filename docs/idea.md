# nist-nvd-mcp-server

MCP server for the NIST National Vulnerability Database — CVEs, CVSS scores, and software vulnerability data.

## Why

Agents doing security review, dependency audits, or threat analysis need structured vulnerability data. "Is this CVE critical?", "What vulnerabilities affect package X?", "Show me recent CVEs for Linux kernel" — these are common agent queries with no current server to answer them. NVD is the authoritative US government source.

## Source

- **API:** NVD REST API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
- **Auth:** None required — API key available for higher rate limits (free, instant)
- **Rate limits:** 5 requests/30s without key, 50 requests/30s with key
- **Docs:** https://nvd.nist.gov/developers/vulnerabilities

## Scope

### Core tools

| Tool | Description |
|---|---|
| `nvd_get_cve` | Fetch a specific CVE by ID (e.g., CVE-2024-3094) — full details, CVSS scores, references, affected products |
| `nvd_search_cves` | Search CVEs by keyword, CPE name, CVSS severity, date range, or CWE ID |
| `nvd_get_cpe` | Look up a CPE (Common Platform Enumeration) entry — identifies specific software/hardware |
| `nvd_search_cpes` | Search CPE dictionary by keyword or match string — find the CPE for a product |
| `nvd_cve_history` | Change history for a CVE — when scores changed, when references were added |

### Key data fields per CVE

- CVE ID, description, published/modified dates
- CVSS v3.1 and v2.0 scores (base, temporal, environmental)
- CWE classification (weakness type)
- CPE match criteria (affected software/versions)
- References (advisories, patches, exploit databases)
- Known Exploited Vulnerabilities (KEV) catalog flag

### Potential additions

- **`nvd_get_kev`** — query the CISA Known Exploited Vulnerabilities catalog specifically
- **`nvd_cve_stats`** — aggregate counts by severity, CWE, or date range
- CPE version range matching ("is version X.Y.Z affected?")

## Design notes

- The NVD API 2.0 uses `resultsPerPage` and `startIndex` pagination. Default page size is 2000.
- CPE matching is the most valuable query pattern for agents — "what CVEs affect `cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*`" maps directly to dependency audit workflows.
- CVSS scores come in multiple versions (v2.0, v3.0, v3.1, v4.0). Surface all available scores; let the agent decide which to use.
- Rate limiting without a key is tight (5/30s). Implement request queuing and respect `Retry-After` headers. Recommend key in server instructions.
- CVE descriptions are often terse. The references array contains the actual advisories, patches, and write-ups — surface these prominently.

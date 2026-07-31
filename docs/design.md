# nist-nvd-mcp-server — Design

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations | Errors |
|:-----|:------------|:-----------|:------------|:-------|
| `nvd_get_cve` | Fetch one or more CVEs by ID. Returns full details: CVSS scores (all available versions), CWE weaknesses, affected CPE configurations, CISA KEV fields, and references. Up to 100 IDs per call; use `brief` mode for bulk lookups to control output size. | `cveIds` (up to 100), `brief`, `includeReferences`, `allLanguages` | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `invalid_cve_id_format` (ValidationError), `cve_not_found` (NotFound), `rate_limited` (RateLimited) |
| `nvd_search_cves` | Search CVEs by keyword, severity, CWE, date range, or KEV status. The primary discovery tool for surveillance and triage workflows. `pubDays`/`lastModDays` are translated to API date pairs; values over 120 are clamped and flagged in the response. | `keyword`, `exactPhrase`, `severity`, `cweId`, `pubDays`, `lastModDays`, `kevOnly`, `limit`, `offset` | `readOnlyHint: true`, `openWorldHint: false` | `mutually_exclusive_params` (ValidationError), `date_range_exceeds_max` (ValidationError), `rate_limited` (RateLimited) |
| `nvd_audit_cpe` | Find CVEs affecting a specific product and version. Requires a full CPE name (`cpeName`) or a partial match string (`virtualMatchString`) with optional version range bounds. Use `nvd_search_cpes` first to resolve the correct CPE name when it is not known. | `cpeName` OR `virtualMatchString` + `versionStart`/`versionEnd`, `severityMin`, `allLanguages`, `limit`, `offset` | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `missing_cpe_input` (ValidationError), `conflicting_cpe_inputs` (ValidationError), `version_range_without_match_string` (ValidationError), `invalid_cpe_format` (ValidationError), `rate_limited` (RateLimited) |
| `nvd_search_cpes` | Search the CPE dictionary by keyword or match string. Used to discover the correct CPE name for a product before calling `nvd_audit_cpe`. Returns cpeName, title, deprecation status. | `keyword`, `cpeMatchString`, `limit`, `offset` | `readOnlyHint: true`, `openWorldHint: false` | `missing_search_input` (ValidationError), `invalid_cpe_format` (ValidationError), `rate_limited` (RateLimited) |
| `nvd_get_cve_history` | Retrieve the change log for a CVE — score revisions, added references, status transitions. Useful for tracking when a CVE was re-scored or escalated. | `cveId`, `limit`, `offset`, `order` | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `invalid_cve_id_format` (ValidationError), `rate_limited` (RateLimited) |

### Resources

| URI Template | Description | Pagination |
|:-------------|:------------|:-----------|
| `nvd://cve/{cveId}` | A single CVE record by ID — stable URI for injectable context. Same data as `nvd_get_cve` for a single ID. | None (single record) |

### Prompts

None. This server is data-oriented; no recurring message templates are warranted.

---

## Overview

nist-nvd-mcp-server wraps the NIST National Vulnerability Database REST API 2.0. It exposes CVE data, CVSS scoring, CWE weakness classification, CPE software identification, and CISA Known Exploited Vulnerabilities catalog status to MCP clients.

Primary audience: security-focused agents performing risk assessment, dependency auditing, and vulnerability surveillance. The tool surface is designed around decisional workflows — "is this version affected? how bad is it? is it being actively exploited?" — not around API endpoint mirroring.

---

## Requirements

- Read-only access to the NVD CVE API 2.0 (`/rest/json/cves/2.0`) and CPE API 2.0 (`/rest/json/cpes/2.0`)
- Optional API key for higher rate limits (50 req/30s with key vs 5 req/30s without)
- No auth required for basic access; API key is free and instant from nvd.nist.gov
- All operations are read-only — no mutations are possible against NVD
- CVE history via the separate `/rest/json/cvehistory/2.0` endpoint
- Rate limit compliance required: service layer must queue requests and respect `Retry-After` headers
- CVSS versions in the wild: v2.0 (legacy, NVD stopped generating as of July 2022), v3.0, v3.1, v4.0 — surface all present, don't discard any
- KEV fields on CVEs (`cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, `cisaVulnerabilityName`) only appear when the CVE is in the CISA catalog; absence means not in KEV, not unknown
- Pagination: `resultsPerPage` max 2,000 for CVEs, 10,000 for CPEs; `startIndex` for offset; max date range for date-filtered queries is 120 days
- The `cveId` parameter is deprecated in favor of `cveIds` (comma-separated list, max 100)
- `hasKev`, `isVulnerable`, `hasCertAlerts`, `noRejected`, `keywordExactMatch` are boolean flags sent without a value (not `=true`)
- Error format: non-OK HTTP status with no body (e.g., 404 for invalid CVE format) vs empty `vulnerabilities: []` array for valid-format CVE that doesn't exist in NVD

---

## Services

| Service | Wraps | Used By |
|:--------|:------|:--------|
| `NvdCveService` | NVD CVE API 2.0 + CVE History API | `nvd_get_cve`, `nvd_search_cves`, `nvd_audit_cpe`, `nvd_get_cve_history`, `nvd://cve/{cveId}` resource |
| `NvdCpeService` | NVD CPE API 2.0 | `nvd_search_cpes`, `nvd_audit_cpe` (for CPE discovery leg) |

Both services share a common HTTP layer with rate-limit queuing. A single `NvdHttpClient` handles queue management, API key injection, retry with backoff (every attempt paced through the queue), and `Retry-After` header parsing. The two API services delegate network calls to this client.

---

## Config

| Env Var | Required | Description |
|:--------|:---------|:------------|
| `NVD_API_KEY` | No | NIST NVD API key. Without it, rate limit is 5 req/30s. With it, 50 req/30s. Get one free at nvd.nist.gov/developers/request-an-api-key. Strongly recommended for production use. |
| `NVD_REQUEST_TIMEOUT_MS` | No | HTTP request timeout in milliseconds. Default: 10000 (10s). NVD can be slow under load. |

---

## Implementation Order

1. Config and server setup (`NVD_API_KEY`, `NVD_REQUEST_TIMEOUT_MS`, `NvdHttpClient` with rate-limit queue)
2. `NvdCveService` — fetch-by-IDs, search, date range, KEV filter, version-range query
3. `NvdCpeService` — keyword search, match string search
4. `nvd_get_cve` tool
5. `nvd_search_cves` tool
6. `nvd_audit_cpe` tool (depends on both services)
7. `nvd_search_cpes` tool
8. `nvd_get_cve_history` tool
9. `nvd://cve/{cveId}` resource

---

## Domain Mapping

| Noun | Operations | API Endpoint |
|:-----|:-----------|:-------------|
| CVE | get-by-id(s), search-by-keyword, search-by-severity, search-by-cwe, search-by-cpe, search-by-date, filter-by-kev, filter-by-version-range | `GET /cves/2.0` |
| CVE History | list-changes-by-cve-id | `GET /cvehistory/2.0` |
| CPE | search-by-keyword, search-by-match-string, get-by-name-id | `GET /cpes/2.0` |
| CPE Match Criteria | list-by-cve-id (cross-reference) | `GET /cpematch/2.0` (not exposed directly) |

---

## Workflow Analysis

### `nvd_audit_cpe` — dependency audit workflow

This is the highest-value tool for security agents. The full audit flow:

| # | Call | Purpose | Notes |
|:--|:-----|:--------|:------|
| 1 | `GET /cves/2.0?cpeName=...` OR `virtualMatchString=...&versionStart=...&versionEnd=...` | Find CVEs affecting the specified CPE/version range | Single request; `isVulnerable` flag added when CPE name is exact |
| 2 | Normalize CVSS across all version metrics | Pick highest available score for severity label | Client-side; no extra API call |

One upstream call for the common case. The CPE discovery problem (finding the right CPE string) is handled by `nvd_search_cpes` as a prerequisite tool — not internal to `nvd_audit_cpe`, since the agent may already have the CPE string.

### `nvd_get_cve` — batch CVE lookup

| # | Call | Purpose |
|:--|:-----|:--------|
| 1 | `GET /cves/2.0?cveIds=CVE-A,CVE-B,...` | Fetch up to 100 CVEs in one request |

The NVD `cveIds` parameter accepts a comma-separated list (max 100), eliminating N+1 patterns for bulk lookups.

---

## Design Decisions

### CPE search is its own tool, not internal to nvd_audit_cpe

CPE strings are arcane (`cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*`). Agents doing dependency audits often don't have the exact CPE. Rather than building product-name-to-CPE resolution inside `nvd_audit_cpe`, this server exposes `nvd_search_cpes` as a first-class tool. This keeps `nvd_audit_cpe` simple and gives agents explicit control over CPE disambiguation — there can be legitimate ambiguity (Apache HTTP Server vs Apache Tomcat vs Apache Struts all appear under `a:apache:*`) that the agent should resolve, not silently pick.

`nvd_audit_cpe` requires either `cpeName` (full CPEv2.3 string, exact) or `virtualMatchString` (partial match pattern with version range params). There is no `product` keyword shortcut. A "top match" silent resolution of an ambiguous product name is the exact problem the separate `nvd_search_cpes` tool was designed to let the agent control — baking it into `nvd_audit_cpe` would silently audit the wrong product when the top CPE hit is ambiguous. Agents that don't have the CPE string call `nvd_search_cpes` first, review the results, and pass the correct `cpeName` to `nvd_audit_cpe`.

### KEV is a filter on nvd_search_cves, not a separate tool

The CISA Known Exploited Vulnerabilities catalog is exposed in two ways: a `kevOnly` boolean on `nvd_search_cves` (filters to KEV CVEs) and KEV fields in the `nvd_get_cve` output. A dedicated `nvd_get_kev` tool adds no capability — it's just `nvd_search_cves` with `kevOnly: true`. Agents that want to see all actively exploited CVEs use `nvd_search_cves { kevOnly: true }`.

### Severity filtering uses a single CVSS version per search

The NVD API's `cvssV3Severity` and `cvssV4Severity` filters are mutually exclusive — you can only filter by one at a time, and they query the stored severity label for that version. Since most modern CVEs have v3.1 scores and v4.0 is emerging, the `severity` input on `nvd_search_cves` maps to `cvssV3Severity` by default with a `severityVersion` override for `v2` or `v4` when needed. All available CVSS version data is returned in the output regardless of which filter was applied.

### CVSS score normalization in output

CVEs can have scores from v2.0, v3.0, v3.1, and v4.0 — sometimes multiple entries per version (primary source = NVD, secondary = CNA). The output surfaces all scores in a `cvssScores` array keyed by version and source type. A top-level `severity` field reflects the highest available score's severity label with a note on which version it came from. This prevents silent data loss for older CVEs that only have v2.0 scores.

Two properties of the upstream shape drive the extraction. **`baseSeverity` sits at different depths per version:** `cvssMetricV2` carries it as a sibling of `cvssData`, `cvssMetricV30`/`V31`/`V40` carry it inside `cvssData`, and no metric carries it at both. Both paths are read, and NVD's own label always wins; the score-range derivation is the fallback for a v2 metric that carries no label at either depth. **A base score of `0.0` is a real score,** not an absent one — NVD scores informational findings that way and pairs them with a full vector string, so entries are kept unless `baseScore` is genuinely undefined.

The derivation follows NVD's published v2.0 bands — `0.0–3.9` LOW, `4.0–6.9` MEDIUM, `7.0–10.0` HIGH — rather than adding a `NONE` tier at `0.0`. CVSS v2 defines no such tier and NVD labels every `0.0` v2 metric LOW; a label outside LOW/MEDIUM/HIGH/CRITICAL is also one the `severityMin` ordering cannot rank, so any threshold would drop it — the same data loss keeping `0.0` exists to prevent.

### An audit that finds nothing is a result, not an error

`nvd_audit_cpe` returns an empty page with `totalCount: 0` when NVD holds no CVEs for the target, on both input arms. A product with a clean record and a mistyped CPE are indistinguishable from `totalResults: 0` alone, so raising `cpe_not_found` asserted the wrong one — and did so right after `nvd_search_cpes` had resolved the exact name the audit was handed. Telling a caller its CPE may not exist is the more expensive mistake: *this version has no known CVEs* is the answer a vulnerability audit exists to give.

Confirming the name against `cpes/2.0` first would keep an accurate error, at the cost of a second upstream request against a 5 req/30s keyless budget. The empty-success path carries the caveat in the notice instead — it names the CPE string as the one thing still unconfirmed, without spending a request to say so.

### History tool is separate, not an option on nvd_get_cve

CVE history is a distinct endpoint (`/cvehistory/2.0`) returning a different response shape (`cveChanges` array with `details` per event). It's a deliberate separate tool rather than an `includeHistory` flag on `nvd_get_cve` because: (a) it significantly increases payload size and latency for every single CVE lookup, (b) agents only need it for specific investigative workflows ("when was this CVE re-scored?"), not routine lookups.

### nvd_get_cve batch size and output budget

The NVD `cveIds` parameter accepts up to 100 IDs in a single request. A single full CVE record can run 5–15KB (CVSS matrices, CPE configurations, references); 100 records can easily exceed 1MB. This is too large for most context budgets.

The tool exposes a `brief` boolean (default `false`). When `true`, each record is trimmed to: `cveId`, `vulnStatus`, top-severity CVSS score + label + version, `cisaVulnerabilityName` (if KEV), and `published` date — enough for triage without the full configuration details. For bulk lookups (>10 IDs), agents should default to `brief: true` and call `nvd_get_cve` with individual IDs only when full detail is needed.

The tool description documents this explicitly so agents make the tradeoff deliberately, not by accident.

### nvd_search_cves date convenience params

`pubDays` and `lastModDays` are integer shorthands for date-range queries. The tool translates them to the API's required date-pair format at call time:

- `pubDays: N` → `pubStartDate = now − N days`, `pubEndDate = now`
- `lastModDays: N` → `lastModStartDate = now − N days`, `lastModEndDate = now`

The NVD API enforces a 120-day maximum range. If either param exceeds 120, the tool clamps the value to 120 and reports the clamping in the `datesClamped` enrichment field so the agent knows the window was narrowed. Passing both `pubDays` and the raw `pubStartDate`/`pubEndDate` params simultaneously is a validation error — they're mutually exclusive.

### Rate limiting: queue, not per-call sleep

The NVD enforces sliding window rate limits (5 or 50 requests per 30-second window). The service layer paces requests through a single queue enforcing a minimum inter-request gap, rather than per-call sleeps, so burst requests from a tool like `nvd_get_cve` (which could fan out to multiple API pages) are queued correctly rather than racing. Without a key, the effective throughput is one request per 6 seconds — agents should be aware they may wait for queued requests.

**Retry wraps the queue rather than sitting inside it.** Every attempt — the first try and each retry — is enqueued separately and takes its own turn, so a retrying call spends its retries against the same budget as any other request. The alternative (retrying inside one queue slot) lets a single call fire its whole retry fan-out unpaced, which is how a lone transient failure used to exhaust the keyless budget and self-inflict 403s.

**A 403 holds the queue, and only one wait fits inside a call.** The parsed `Retry-After` (~30s) blocks every pending request until NVD's window resets, not just the retrying one. That wait is half the MCP client's 60s request deadline, so at most one fits inside a call: a keyed call spends it on a single patient retry, while a keyless call — whose 5-request budget cannot spare it — fails fast and names `NVD_API_KEY`. Retrying a keyless 403 on the 2s exponential can never clear a 30s window, so it only burns budget before failing anyway. For the same reason keyless calls retry other transient failures once rather than three times.

**Deterministic rejections are never retried.** NVD answers a 404 with an empty body and its diagnosis in a `message` response header. The client throws it as an `McpError` carrying `data.retryable === false` (the framework's opt-out) so `withRetry` fails fast instead of re-sending a request that cannot succeed. Callers key off that error shape via `isNvdRequestRejected()` rather than matching the message text.

That 404 covers two unrelated faults, and only the `message` header separates them: a rejected parameter (`Invalid cveId parameter.`, `Invalid cpeName parameter, see documentation.`) versus a refused API key (`Invalid apiKey.`). The client splits them — a refused key raises `ConfigurationError` / `nvd_invalid_api_key` naming `NVD_API_KEY`, everything else raises `ValidationError` / `nvd_request_rejected` carrying NVD's own wording. Collapsing the two would tell a caller its CVE ID is malformed when the ID is fine and the key is the fault, sending it to correct something that can never succeed.

`nvd_invalid_api_key` is a transport-layer fault rather than a property of any one tool: every tool surfaces it, none can act on it, and the fix is always the `NVD_API_KEY` value. It therefore appears in no per-tool `errors:` contract — the recovery hint the client attaches carries the whole remedy.

---

## API Reference

### CVE Search Parameters

| Parameter | Type | Notes |
|:----------|:-----|:------|
| `cveIds` | comma-separated string | Up to 100 CVE IDs; replaces deprecated `cveId` |
| `keywordSearch` | string | AND-semantics across words; wildcard suffix implicit |
| `keywordExactMatch` | flag (no value) | Only with `keywordSearch`; phrase-exact |
| `cpeName` | string | Full CPEv2.3 name; must include part/vendor/product/version |
| `virtualMatchString` | string | Partial CPE match string; use with version range params |
| `versionStart` / `versionStartType` | string / `including`\|`excluding` | With `virtualMatchString` |
| `versionEnd` / `versionEndType` | string / `including`\|`excluding` | With `virtualMatchString` |
| `isVulnerable` | flag | Requires `cpeName`; excludes non-vulnerable matches |
| `cvssV3Severity` | `LOW`\|`MEDIUM`\|`HIGH`\|`CRITICAL` | Mutually exclusive with v2/v4 severity filters |
| `cvssV4Severity` | `LOW`\|`MEDIUM`\|`HIGH`\|`CRITICAL` | Mutually exclusive with v2/v3 severity filters |
| `cweId` | string | e.g., `CWE-79`; also accepts `NVD-CWE-Other`, `NVD-CWE-noinfo` |
| `hasKev` | flag | Filter to CISA KEV catalog entries only |
| `pubStartDate` / `pubEndDate` | ISO-8601 datetime | Max 120-day range; both required |
| `lastModStartDate` / `lastModEndDate` | ISO-8601 datetime | Max 120-day range; both required |
| `noRejected` | flag | Exclude REJECT/Rejected status CVEs |
| `resultsPerPage` | int | Max 2,000 (default 2,000) |
| `startIndex` | int | Zero-based offset for pagination |

### Error Behavior

- Invalid CVE ID format (e.g., `CVE-INVALID`) → HTTP 404, empty body
- Valid CVE ID that doesn't exist in NVD → HTTP 200, `totalResults: 0`, empty `vulnerabilities: []`
- Rate limit exceeded → HTTP 403 with `Retry-After` header (typically 30s window reset)
- Mutually exclusive params used together → HTTP 400

### KEV Fields on CVE

Present only when the CVE appears in the CISA KEV catalog:

- `cisaExploitAdd` — date added to KEV catalog
- `cisaActionDue` — remediation deadline for federal agencies (BOD 22-01)
- `cisaRequiredAction` — required remediation steps
- `cisaVulnerabilityName` — CISA's human-readable name for the CVE

---

## Tool Detail

### `nvd_get_cve`

**Description:** Fetch one or more CVEs by ID. Returns CVSS scores across all available versions, CWE weaknesses, affected CPE configurations, CISA KEV fields, and (optionally) references. Use `brief: true` for bulk lookups — full records for 100 CVEs can exceed 1MB.

**Input:**
- `cveIds: string | string[]` — one CVE ID or an array of up to 100 (e.g., `"CVE-2021-44228"` or `["CVE-2021-44228", "CVE-2022-0001"]`)
- `brief?: boolean` — default `false`. When `true`, returns trimmed records (ID, status, top CVSS score, KEV name, published date, truncated description) instead of full detail. Recommended for batches of more than 10.
- `includeReferences?: boolean` — default `true`. Set to `false` to omit the references array and reduce response size.
- `allLanguages?: boolean` — default `false`. When `false`, full records keep only the English description (falling back to whatever exists if a record has no English entry); set `true` to keep every localized description. Brief records always carry a single truncated description.

**Output:**
- `brief: boolean` — which mode produced the records below.
- `cves[]` — one item schema spanning both modes, since a tool's `output` must be a flat object and cannot branch on a discriminator. `cveId`, `vulnStatus`, and `published` are the only required fields; every field either mode adds is declared optional, because the framework parses each success return against this schema and a full-record field marked required would reject every `brief: true` call.
  - Full mode (the default) emits `lastModified`, `descriptions`, `cvssScores` (all versions present), `severity` (highest score label + version source), `weaknesses`, `configurations`, `references` (unless `includeReferences: false`), and `cisaKev` (KEV catalog members only).
  - Brief mode emits `description` (first 200 characters, English-preferred), `severity`, and `cisaVulnerabilityName` — the trimmed substitutes for `descriptions` and `cisaKev`.
  - The full-record fields come from the shared `CveRecordSchema` (`src/mcp-server/tools/schemas/full-cve.ts`), which `nvd_audit_cpe` declares its own records with directly, so one declaration describes the domain type on both surfaces.

`format()` tests each field for presence instead of branching on `brief`: the record itself says which fields it carries, and a mode-branched formatter renders only one field set per call — leaving the other mode's fields unverifiable against the declared schema.

**Enrichment:** this tool looks up specific IDs rather than paging a result set, so it carries no pagination fields.
- `requested: number` — how many CVE IDs the call asked for
- `returned: number` — how many records came back
- `missingIds?: string[]` — requested IDs NVD held no record for; absent when every ID matched

**Rendering caps.** `structuredContent` always carries the whole record. The formatted text renders CPE match criteria capped at the first 5 per CVE and references at the first 15, each with a `… N more` trailer. Both are bounded for the same reason: `cveIds` accepts up to 100 IDs, and a single dense CVE can carry hundreds of criteria (CVE-2021-44228 has 396 across 20 node groups — ~27.8KB rendered in full versus ~0.36KB capped, plus 103 references at ~11.6KB versus ~2.07KB capped). The criteria trailer points at `nvd_audit_cpe`, which is how a caller reaches the remainder: auditing a specific `cpeName` answers whether a given product version is affected without enumerating every criterion. Descriptions are not capped by count — the formatter renders every language the record carries, so `allLanguages` reaches `content[]` clients and not just `structuredContent` ones.

**Errors:**
```
errors: [
  { reason: 'invalid_cve_id_format', code: 'ValidationError',
    when: 'One or more CVE IDs fail format validation (NVD returns HTTP 404 with empty body for malformed IDs). Message names the offending IDs.',
    retryable: false },
  { reason: 'cve_not_found', code: 'NotFound',
    when: 'Valid-format ID returns HTTP 200 with empty vulnerabilities array — ID is well-formed but does not exist in NVD. Distinct from format error.',
    retryable: false },
  { reason: 'rate_limited', code: 'RateLimited',
    when: 'HTTP 403 with Retry-After header. The parsed Retry-After holds the queue until NVD window reset; a keyed call spends one patient retry on it, a keyless call fails fast and names NVD_API_KEY.',
    retryable: true },
]
```

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

### `nvd_search_cves`

**Description:** Search CVEs by keyword, severity, CWE, date range, or KEV status. The primary discovery tool for surveillance and triage workflows. `pubDays` and `lastModDays` are convenience shorthands for date-range queries — the tool converts them to API date pairs and clamps values over 120 days (the API maximum), reporting the clamped range in the response enrichment.

**Input:**
- `keyword?: string` — full-text search across CVE descriptions (AND-semantics across words)
- `exactPhrase?: boolean` — default `false`. When `true`, `keyword` matches as a phrase instead of ANDing its words independently, forwarded as the valueless `keywordExactMatch` flag. Requires `keyword`; without one it raises `exact_phrase_without_keyword` rather than running the search unmodified.
- `severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'` — CVSS severity filter; applies to v3.1 by default
- `severityVersion?: 'v2' | 'v3' | 'v4'` — CVSS version for severity filter (default `v3`)
- `cweId?: string` — e.g., `"CWE-79"`, `"NVD-CWE-Other"`
- `pubDays?: number` — CVEs published in the last N days (max 120; values over 120 are clamped). Mutually exclusive with `pubStartDate`/`pubEndDate`.
- `lastModDays?: number` — CVEs modified in the last N days (max 120; values over 120 are clamped). Mutually exclusive with `lastModStartDate`/`lastModEndDate`.
- `pubStartDate?: string` / `pubEndDate?: string` — ISO 8601 datetime; max 120-day span; both required together
- `lastModStartDate?: string` / `lastModEndDate?: string` — ISO 8601 datetime; max 120-day span; both required together
- `kevOnly?: boolean` — filter to CISA KEV catalog entries only
- `noRejected?: boolean` — exclude REJECT/Rejected status CVEs (default `true`)
- `limit?: number` — max results (default 20, max 2000)
- `offset?: number` — zero-based page offset

**Output:**
- `cves: BriefCveRecord[]` — array of CVE summaries, each `{ cveId, vulnStatus, published, description?, severity?, filteredSeverity?, cisaVulnerabilityName? }`. `description` is the first 200 characters of the English text (English-preferred, falling back to whatever prose exists), enough to tell one hit from another without a follow-up fetch; call `nvd_get_cve` for full detail on specific IDs.

**Enrichment:**
- `totalCount: number` — total matching CVEs in NVD before pagination
- `returned: number` — CVEs in this response
- `offset: number` — page offset used
- `datesClamped?: { param, original, clamped }[]` — present when a `pubDays`/`lastModDays` value was reduced to 120
- `filtersApplied?: { keyword?, exactPhrase?, severity?, severityVersion?, cweId?, kevOnly?, noRejected? }` — only the non-default filters the query actually applied, so an empty or unexpectedly narrow result set is accountable; absent when the query ran unfiltered
- `notice?: string` — guidance when nothing matched or the offset ran past the result set

**Errors:**
```
errors: [
  { reason: 'exact_phrase_without_keyword', code: 'ValidationError',
    when: 'exactPhrase set without a keyword — it selects how keyword matches and has nothing to modify alone.',
    retryable: false },
  { reason: 'mutually_exclusive_params', code: 'ValidationError',
    when: 'Both pubDays and pubStartDate/pubEndDate provided, or both lastModDays and lastModStartDate/lastModEndDate.',
    retryable: false },
  { reason: 'date_range_exceeds_max', code: 'ValidationError',
    when: 'Raw pubStartDate/pubEndDate or lastModStartDate/lastModEndDate span more than 120 days. (pubDays/lastModDays over 120 are auto-clamped, not an error.)',
    retryable: false },
  { reason: 'rate_limited', code: 'RateLimited',
    when: 'HTTP 403 with Retry-After; queue exhausted.',
    retryable: true },
]
```

**Annotations:** `readOnlyHint: true`, `openWorldHint: false`

---

### `nvd_audit_cpe`

**Description:** Find all CVEs affecting a specific product and version. Requires either an exact CPE name (`cpeName`) or a partial match string (`virtualMatchString`) with optional version range bounds. When `cpeName` is used, NVD applies the `isVulnerable` flag to exclude configurations where the CPE appears as a dependency but is not itself the vulnerable component. Use `nvd_search_cpes` first to resolve the correct CPE string when it is not known — do not guess.

**Input:**
- `cpeName?: string` — full CPEv2.3 name (e.g., `"cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"`). When provided, `isVulnerable` is automatically added to the API request.
- `virtualMatchString?: string` — partial CPE match pattern (e.g., `"cpe:2.3:a:apache:http_server:*"`). Use with version range params for range-based audits.
- `versionStart?: string`, `versionStartType?: 'including' | 'excluding'` — lower version bound; requires `virtualMatchString`
- `versionEnd?: string`, `versionEndType?: 'including' | 'excluding'` — upper version bound; requires `virtualMatchString`
- `severityMin?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'` — filter out CVEs below this severity. Applied after NVD returns the page, so it only sees CVEs within `limit`.
- `allLanguages?: boolean` — default `false`. When `false`, each record keeps only its English description (falling back to whatever exists if a record has no English entry); set `true` to keep every localized description.
- `limit?: number` — max results (default 20, max 2000)
- `offset?: number` — zero-based page offset, passed upstream as `startIndex`

Exactly one of `cpeName` or `virtualMatchString` is required.

**Paging.** Despite auditing by CPE, this tool queries `cves/2.0`, whose `resultsPerPage` ceiling is 2,000 — not the 10,000 of the `cpes/2.0` endpoint `nvd_search_cpes` pages. `offset` is independent of that ceiling on both endpoints. Page with `offset` at a modest `limit` rather than raising `limit` to reach further: this tool returns full CVE records, so a large `limit` is a large response, and it also widens what `severityMin` filters in a single pass.

**Output:**
- `cves: CveRecord[]` — full CVE records (this is a targeted audit, not a search — full detail is appropriate)

**Enrichment:**
- `totalCount: number` — total CVEs matched before pagination
- `returned: number` — records in this response
- `offset: number` — page offset used
- `auditTarget: string` — the `cpeName` or `virtualMatchString` the audit ran against, so the caller can verify the right product was queried
- `severityMin?: string` — the client-side severity threshold applied; absent when none was set
- `filteredCount?: number` — CVEs the `severityMin` filter dropped from the page NVD returned. Present whenever `severityMin` is set. This is not `totalCount − returned`: CVEs beyond `limit` were never fetched, so they were never evaluated against the filter
- `notice?: string` — distinguishes a target NVD holds no CVEs for, a `severityMin` threshold that emptied the page, and an `offset` past the end of the result set

**Configurations rendering.** `structuredContent` always carries the whole configuration tree. The formatted text renders each CVE's CPE match criteria — the criteria string, its version bounds, whether the CPE is the vulnerable component or only the context it runs in, and the operators combining it — capped at the first 5 per CVE with a `… N more` trailer, matching the cap this formatter already applies to `references`. The cap is what keeps the block bounded: `limit` accepts up to 2000 CVEs, and a single complex CVE can carry dozens of criteria (CVE-2021-44224 has 37 across 7 node groups — 2,727 bytes rendered in full versus 373 capped). `nvd_get_cve` renders criteria through the same shared formatter and cap, so the two tools present the affected-product surface identically.

Both operators are rendered because they mean different things: a node's operator combines that node's own matches, while a group's operator combines its sibling nodes — an `AND` there marks conditions that must hold together (a firmware match plus the hardware it runs on), which reads as two unrelated alternatives if dropped.

**Errors:**
```
errors: [
  { reason: 'missing_cpe_input', code: 'ValidationError',
    when: 'Neither cpeName nor virtualMatchString provided.',
    retryable: false },
  { reason: 'conflicting_cpe_inputs', code: 'ValidationError',
    when: 'Both cpeName and virtualMatchString provided.',
    retryable: false },
  { reason: 'version_range_without_match_string', code: 'ValidationError',
    when: 'versionStart or versionEnd provided without virtualMatchString.',
    retryable: false },
  { reason: 'invalid_cpe_format', code: 'ValidationError',
    when: 'cpeName or virtualMatchString does not start with "cpe:2.3:", or NVD rejected it as a malformed CPE parameter (HTTP 404) on either request arm. The two arms reject different inputs: cpeName refuses anything short of a complete CPEv2.3 name, while virtualMatchString accepts a truncated prefix as a legitimate pattern and refuses only genuinely malformed characters. A well-formed CPE no product matches is not this error — it is an empty success.',
    retryable: false },
  { reason: 'rate_limited', code: 'RateLimited',
    when: 'HTTP 403 with Retry-After. Keyed: one patient retry across the window. Keyless: fails fast naming NVD_API_KEY.',
    retryable: true },
]
```

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

### `nvd_search_cpes`

**Description:** Search the NVD CPE dictionary by keyword or partial match string. Returns CPE names, human-readable titles, and deprecation status. Use this tool to find the correct `cpeName` before calling `nvd_audit_cpe` — when multiple CPEs match a product name, review results and select the right one rather than guessing.

**Input:**
- `keyword?: string` — product name or vendor keyword (e.g., `"apache http server"`, `"openssl"`)
- `cpeMatchString?: string` — partial CPEv2.3 pattern (e.g., `"cpe:2.3:a:apache:http_server"`)
- `limit?: number` — max results (default 20, max 10000)
- `offset?: number` — zero-based page offset, passed upstream as `startIndex`

At least one of `keyword` or `cpeMatchString` required.

**Paging.** This tool queries `cpes/2.0`, whose `resultsPerPage` ceiling is 10,000 — five times the 2,000 of the `cves/2.0` endpoint `nvd_audit_cpe` pages. Dictionary searches routinely overrun any page (`keyword: "apache"` matches over 21,000 entries), and when the keyword is already the vendor there is nothing to narrow toward, so `offset` — not a more specific keyword — is what reaches the rest.

**Output:**
- `cpes: CpeRecord[]` — array of `{ cpeName, title?, deprecated, deprecatedBy?, lastModified? }`

**Enrichment:**
- `totalCount: number` — total matching dictionary entries before the limit
- `returned: number` — entries in this response
- `offset: number` — page offset used
- `notice?: string` — nothing matched, the offset ran past the result set, or entries remain beyond this page (naming the offset that reaches them)

**Errors:**
```
errors: [
  { reason: 'missing_search_input', code: 'ValidationError',
    when: 'Neither keyword nor cpeMatchString provided.',
    retryable: false },
  { reason: 'invalid_cpe_format', code: 'ValidationError',
    when: 'cpeMatchString does not start with "cpe:2.3:", or NVD rejected it as a malformed CPE parameter (HTTP 404). A merely truncated prefix is a legitimate partial match and returns an empty page instead.',
    retryable: false },
  { reason: 'rate_limited', code: 'RateLimited',
    when: 'HTTP 403 with Retry-After; queue exhausted.',
    retryable: true },
]
```

**Annotations:** `readOnlyHint: true`, `openWorldHint: false`

---

### `nvd_get_cve_history`

**Description:** Retrieve the change history for a single CVE — CVSS score revisions, reference additions, status transitions (e.g., `Received` → `Analyzed`), and CPE configuration updates. Use when tracking a CVE's escalation or investigating when a score changed.

**Input:**
- `cveId: string` — e.g., `"CVE-2021-44228"`
- `limit?: number` — max change events returned (default 20, max 2000)
- `offset?: number` — zero-based offset for pagination, counted from the end `order` anchors to
- `order?: 'oldest' | 'newest'` — which end to page from (default `newest`). NVD serves history oldest-first, so `oldest` maps `offset` straight to `startIndex` in one request; `newest` reverses it, adding a second tail-anchored request only when the history is longer than `limit`. `oldest` pays for a second request only when its page comes back empty past offset 0: `cvehistory/2.0` zeroes `totalResults` for a `startIndex` past the end — unlike `cves/2.0` and `cpes/2.0`, which report the true count from any index — so the count is re-probed from the start before an overrun can be told from a CVE with no history

**Output:**
- `cveId: string`
- `changes: CveChangeEvent[]` — each event: `{ changeDate, eventName?, details: [{ action?, type?, oldValue?, newValue? }] }`, ordered to match `order`. Structured upstream values (`Affected` arrays, `SSVC` objects) are JSON-serialized so the values stay flat strings

**Enrichment:**
- `totalCount: number` — total change events on record for this CVE
- `returned: number` — events in this response
- `offset: number` — page offset used
- `order: 'oldest' | 'newest'` — which end of the history this page was anchored to, since `offset` counts from that end
- `notice?: string` — distinguishes an `offset` past the end of the history, an empty page NVD returned inside a range it says has events, and a CVE NVD holds no history for; on a partial page it names the offset that reaches the next one, counted from the end `order` anchors to. The no-history branch names both causes it cannot separate — a record NVD never revised and a CVE ID NVD does not hold — and hands off to `nvd_get_cve`, the one call that tells them apart

**Errors:**
```
errors: [
  { reason: 'invalid_cve_id_format', code: 'ValidationError',
    when: 'CVE ID fails format validation (NVD returns HTTP 404 for malformed IDs).',
    retryable: false },
  { reason: 'rate_limited', code: 'RateLimited',
    when: 'HTTP 403 with Retry-After; queue exhausted.',
    retryable: true },
]
```

**Annotations:** `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false`

---

## Known Limitations

- **Date range cap**: All date-filtered queries (published, last modified, KEV dates) are limited to 120 consecutive days per request. Multi-month surveillance requires multiple paginated requests.
- **No full-text search of references**: `keywordSearch` only matches CVE descriptions, not advisory text, reference titles, or CPE data.
- **CPE version range is partial match only**: `cpeName` with an exact version matches that version against stored CPE match criteria. Whether a specific patch version is affected requires checking `versionEndExcluding`/`versionEndIncluding` fields in the `configurations.nodes.cpeMatch` response data — the API doesn't directly answer "is 2.4.53 affected?" without parsing the match criteria client-side.
- **CVSS v2 deprecated**: NVD stopped generating new v2.0 scores in July 2022. Old CVEs may only have v2.0 scores; post-2022 CVEs will have v3.1 (and increasingly v4.0). The severity filter can't bridge across versions.
- **NVD analysis lag**: Newly published CVEs start in `Received` or `AwaitingAnalysis` status. CVSS scores, CPE configurations, and CWE classifications may be absent until NVD analysts process the CVE. This is a data completeness fact, not a server bug — surface `vulnStatus` in outputs.
- **Rate limit without API key is tight**: 5 requests per 30 seconds limits throughput severely. The queue handles compliance but can introduce multi-second latency under load. Strongly recommend obtaining a free API key.

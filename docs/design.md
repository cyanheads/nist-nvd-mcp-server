# nist-nvd-mcp-server — Design

## MCP Surface

### Tools

| Name | Description | Key Inputs | Annotations | Errors |
|:-----|:------------|:-----------|:------------|:-------|
| `nvd_get_cve` | Fetch one or more CVEs by ID. Returns full details: CVSS scores (all available versions, each with its supplier), CWE weaknesses, affected CPE configurations from NVD analysis, the affected products the CNA and any ADP state themselves, the record's source and tags, CISA KEV fields, SSVC assessments, and references. Up to 100 IDs per call; use `brief` mode for bulk lookups to control output size. | `cveIds` (up to 100 distinct IDs, as an array or one comma- or whitespace-separated string), `brief`, `includeReferences`, `includeConfigurations`, `includeAffected`, `allLanguages` | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `invalid_cve_id_format` (ValidationError), `too_many_cve_ids` (ValidationError), `cve_not_found` (NotFound), `rate_limited` (RateLimited) |
| `nvd_search_cves` | Search CVEs by keyword, severity, CWE, publication or last-modified date, KEV status, or the date CISA added a CVE to KEV. The primary discovery tool for surveillance and triage workflows. `pubDays`/`lastModDays`/`kevDays` are translated to API date pairs ending at call time; values over 120 are clamped and flagged in the response. | `keyword`, `exactPhrase`, `severity`/`severityVersion`, `cweId`, `pubDays`/`lastModDays`/`kevDays` and their date pairs, `kevOnly`, `noRejected`, `limit`, `offset` | `readOnlyHint: true`, `openWorldHint: false` | `exact_phrase_without_keyword` (ValidationError), `invalid_severity_for_version` (ValidationError), the five date-window reasons (ValidationError), `nvd_request_rejected` (ValidationError), `rate_limited` (RateLimited) |
| `nvd_audit_cpe` | Find CVEs affecting a specific product and version. Requires a full CPE name (`cpeName`) or a partial match string (`virtualMatchString`) with optional version range bounds. Use `nvd_search_cpes` first to resolve the correct CPE name when it is not known. | `cpeName` OR `virtualMatchString` + `versionStart`/`versionEnd`, `kevOnly`, `severity`/`severityVersion`, `pubDays`/`lastModDays`/`kevDays` and their date pairs, `severityMin`, `includeReferences`, `includeConfigurations`, `includeAffected`, `allLanguages`, `limit`, `offset` | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `missing_cpe_input` (ValidationError), `conflicting_cpe_inputs` (ValidationError), `version_range_without_match_string` (ValidationError), `invalid_cpe_format` (ValidationError), `nvd_request_rejected` (ValidationError), `invalid_severity_for_version` (ValidationError), the five date-window reasons (ValidationError), `rate_limited` (RateLimited) |
| `nvd_search_cpes` | Search the CPE dictionary by keyword or match string. Used to discover the correct CPE name for a product before calling `nvd_audit_cpe`. Returns cpeName, title, deprecation status. | `keyword`, `cpeMatchString`, `limit`, `offset` | `readOnlyHint: true`, `openWorldHint: false` | `missing_search_input` (ValidationError), `invalid_cpe_format` (ValidationError), `nvd_request_rejected` (ValidationError), `rate_limited` (RateLimited) |
| `nvd_get_cve_history` | Retrieve the change log for a CVE — score revisions, added references, status transitions. Useful for tracking when a CVE was re-scored or escalated. | `cveId`, `limit`, `offset`, `order` | `readOnlyHint: true`, `idempotentHint: true`, `openWorldHint: false` | `invalid_cve_id_format` (ValidationError), `rate_limited` (RateLimited) |

The five date-window reasons are `mutually_exclusive_params`, `missing_date_pair`, `date_range_inverted`, `date_range_exceeds_max`, and `invalid_date_format`. Every tool and the CVE resource also declare the transport reasons `nvd_invalid_response`, `nvd_request_blocked`, `nvd_unavailable`, `nvd_timeout`, and `nvd_invalid_api_key`.

### Resources

| URI Template | Description | Pagination |
|:-------------|:------------|:-----------|
| `nvd://cve/{cveId}` | A single CVE record by ID — stable URI for injectable context. Same data as `nvd_get_cve` for a single ID. | None (single record) |
| `skill://nist-nvd-guide/SKILL.md` | Product applicability, identifier chains, severity interpretation, and coverage guidance. | None (complete guide) |

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
| `NvdSourceService` | NVD Source API 2.0 | `NvdCveService`, to resolve every contributor identifier (`weaknesses[].source`, `references[].source`, `cvssScores[].source`, `ssvc[].source`, `sourceIdentifier`, `cveTags[].source`, `affectedProducts[].source`) while normalizing a full record |

All three share a common HTTP layer with rate-limit queuing. A single `NvdHttpClient` handles queue management, API key injection, retry with backoff (every attempt paced through the queue), `Retry-After` header parsing, and the one 55-second deadline that bounds every request a tool call makes. The API services delegate network calls to this client.

---

## Config

| Env Var | Required | Description |
|:--------|:---------|:------------|
| `NVD_API_KEY` | No | NIST NVD API key. Without it, rate limit is 5 req/30s. With it, 50 req/30s. Get one free at nvd.nist.gov/developers/request-an-api-key. Strongly recommended for production use. |
| `NVD_REQUEST_TIMEOUT_MS` | No | Timeout for each NVD request attempt in milliseconds. Default: 10000 (10s). NVD can be slow under load. Every attempt is also capped by what remains of the tool call's 55s deadline, so raising it lengthens attempts, never the call. |
| `NVD_CLAMP_LIMITS` | No | Default true. Clamp oversized reads to 2000 CVEs/events, 10000 CPEs, or 100 distinct CVE IDs. False restores advertised schema maxima and rejection. |

Server configuration loads the working-directory `.env` before parsing on both Node and Bun, preserves exported values, and caches the parsed configuration. Invalid switch values and unreadable env files fail as configuration errors; a missing `.env` is allowed.

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

The CISA Known Exploited Vulnerabilities catalog is exposed three ways: a `kevOnly` boolean on `nvd_search_cves` and `nvd_audit_cpe` (filters to KEV CVEs, whenever CISA added them), a KEV-addition window on both (`kevDays` or `kevStartDate`/`kevEndDate`), and KEV fields in the `nvd_get_cve` output. A dedicated `nvd_get_kev` tool adds no capability — it's just `nvd_search_cves` with `kevOnly: true`. Agents that want to see all actively exploited CVEs use `nvd_search_cves { kevOnly: true }`.

The window filters on the date CISA added a CVE to the catalog, which answers "what was added" directly. A publication window combined with `kevOnly` answers a different question — CVEs published in that span that are in KEV today — and misses a CVE published earlier that CISA added inside the span. The window alone restricts results to catalog members, so `kevOnly` beside it is accepted and echoed but changes nothing.

### Severity filtering uses a single CVSS version per search

The NVD API's `cvssV3Severity` and `cvssV4Severity` filters are mutually exclusive — you can only filter by one at a time, and they query the stored severity label for that version. Since most modern CVEs have v3.1 scores and v4.0 is emerging, the `severity` input on `nvd_search_cves` maps to `cvssV3Severity` by default with a `severityVersion` override for `v2` or `v4` when needed. All available CVSS version data is returned in the output regardless of which filter was applied.

### CVSS score normalization in output

CVEs can have scores from v2.0, v3.0, v3.1, and v4.0 — sometimes multiple entries per version. The output surfaces all scores in a `cvssScores` array keyed by version, NVD's `sourceType` label, and the scorer's `source`. `sourceType` is NVD's own "Primary" or "Secondary" tag and does not say who scored — a CNA's score can be Primary and an ADP's Secondary — so `source` names the scorer, resolved through the contributor dictionary like every other source field. A top-level `severity` field reflects the highest available score's severity label with a note on which version it came from. This prevents silent data loss for older CVEs that only have v2.0 scores.

Two properties of the upstream shape drive the extraction. **`baseSeverity` sits at different depths per version:** `cvssMetricV2` carries it as a sibling of `cvssData`, `cvssMetricV30`/`V31`/`V40` carry it inside `cvssData`, and no metric carries it at both. Both paths are read, and NVD's own label always wins; the score-range derivation is the fallback for a v2 metric that carries no label at either depth. **A base score of `0.0` is a real score,** not an absent one — NVD scores informational findings that way and pairs them with a full vector string, so entries are kept unless `baseScore` is genuinely undefined.

The derivation follows NVD's published v2.0 bands — `0.0–3.9` LOW, `4.0–6.9` MEDIUM, `7.0–10.0` HIGH — rather than adding a `NONE` tier at `0.0`. CVSS v2 defines no such tier and NVD labels every `0.0` v2 metric LOW; a label outside LOW/MEDIUM/HIGH/CRITICAL is also one the `severityMin` ordering cannot rank, so any threshold would drop it — the same data loss keeping `0.0` exists to prevent.

`nvd_audit_cpe` takes the same `severity`/`severityVersion` pair, and both tools map it through one shared band mapping in the service. The exact band is sent to NVD, so `totalCount` counts that band and paging stays clean; CRITICAL with `v2` is rejected as `invalid_severity_for_version`.

`severityMin` evaluates the highest severity band across every metric independently of the highest numerical score used for the canonical headline. A qualifying lower-score metric therefore keeps the CVE even when its headline comes from another version. Records without a qualifying band are dropped from the fetched page; filtering never fetches additional pages. On an audit `severity` and `severityMin` compose as AND: NVD narrows to the band, then `severityMin` filters the fetched page across every CVSS version, so `severityMin` alone cannot change `totalCount`.

### An audit that finds nothing is a result, not an error

`nvd_audit_cpe` returns an empty page with `totalCount: 0` when NVD holds no CVEs for the target, on both input arms. A product with a clean record and a mistyped CPE are indistinguishable from `totalResults: 0` alone, so raising `cpe_not_found` asserted the wrong one — and did so right after `nvd_search_cpes` had resolved the exact name the audit was handed. Telling a caller its CPE may not exist is the more expensive mistake: *this version has no known CVEs* is the answer a vulnerability audit exists to give.

Confirming the name against `cpes/2.0` first would keep an accurate error, at the cost of a second upstream request against a 5 req/30s keyless budget. The empty-success path carries the caveat in the notice instead — it names the CPE string as the one thing still unconfirmed, without spending a request to say so.

With a server-side filter set (`kevOnly`, an exact `severity`, or a date window), a zero `totalCount` says only that nothing matched the filters, and the target may hold other CVEs. That case gets its own notice, which says it is not a clean audit and points at an unfiltered audit; the clean-audit wording is reserved for an unfiltered zero.

### Source identifiers are resolved in place, not carried alongside

Every contributor field on a full record — `weaknesses[].source`, `references[].source`, `cvssScores[].source`, `ssvc[].source`, `sourceIdentifier`, `cveTags[].source`, and `affectedProducts[].source` — holds NVD's raw contributor identifier. For a CNA that is a readable email (`security@apache.org`); for the two heaviest contributors on modern records it is a GUID — `af854a3a-2127-422b-91ae-364da2661108` (`CVE`) and `134c704f-9b21-4f2e-91b3-4a467353bcc0` (`CISA-ADP`) — which a reader cannot interpret and cannot look up without a second, undocumented API. Normalization resolves the identifier to the name NVD publishes for it and emits that in the identifier's place, on both `structuredContent` and `format()`.

No sibling field preserves the GUID. The consumer of these records is a language model, for which the identifier is uninterpretable noise, and it stays recoverable from NVD's own dictionary for anyone who needs it. Email-form identifiers are left alone: they already name their contributor, so churning `security@apache.org` into `Apache Software Foundation` would change a familiar value for nothing.

The dictionary comes from `/rest/json/source/2.0` — one page, 529 contributors, growing 55–60 a year since 2024 — fetched live rather than bundled as a snapshot. A snapshot costs no request but silently fails to resolve every contributor onboarded after the build, which is the exact failure the resolution exists to remove; the live fetch costs one request a day (cached, single-flighted so a burst cannot stampede it) and none at all on the surfaces that emit no `source` field — a search, and a `brief: true` fetch, whose trimmed rows drop it. When the dictionary cannot be loaded the identifiers pass through raw and the CVE lookup succeeds unchanged — a CVE query must not start failing because a secondary metadata endpoint is down.

Succeeding unchanged is not enough on its own. The load runs inside the calling tool and shares the single pacing queue every NVD request passes through, so on the client's default effort an unreachable `source/2.0` would hold a CVE lookup across every attempt the retry budget allows — each with the full request timeout, plus the backoff between them — with every queued CVE request stuck behind it. The dictionary therefore gets one 20-second attempt with no retry, capped by what remains of the call's deadline, and a five-minute failure TTL, so a sustained outage costs one bounded wait rather than one per call. Only the load's own failure — an NVD error, a network error, its own timeout, or an unusable body — opens the failure window. A load cancelled by its caller, or cut short by the call's deadline, is not remembered as a failure: neither says anything about whether NVD can serve the dictionary, so the cache stays as it was and the next call tries again. A call waiting on another call's in-flight load stops at its own deadline or cancellation, never the opener's, and proceeds with the names already cached.

### Configuration nodes are hoisted out of their groups

NVD nests affected-product data three arrays deep — `configurations[].nodes[].cpeMatch[]` — which puts the criteria past the definition linter's parity walker (depth 8), leaving `format-parity` unverified for every leaf under it. One array level has to go.

The level removed is the **group**, not the node. `configurationNodes[]` carries one entry per upstream node, each tagged with the `groupIndex` of the group it came from, plus that group's operator as `groupOperator` and the node's own operator as `nodeOperator`. Node boundaries survive exactly and group membership is recoverable from a scalar.

Removing the node level instead — merging every node's criteria into one group-level array — loses the applicability semantics the tool exists to answer. A group with `operator: "AND"` over node A `{OR: [X 1.0, X 1.1]}` and node B `{OR: [Y]}` means `(X1.0 OR X1.1) AND Y`. Merged, the three criteria sit in one array and which criteria formed each conjunct is unrecoverable, so a consumer reads `X1.0 AND X1.1 AND Y` — a different and false statement about what the CVE affects.

The field is named `configurationNodes` rather than `configurations` because each entry is a node, not a group; reusing the old name for a differently-shaped value is worse for a client than a rename.

### Affected-product groups and version changes are hoisted too

The CNA's and ADPs' own statements nest as `affected[].affectedData[].versions[].changes[]`, which is past the same walker depth. Two levels are hoisted. Each `affected[]` group's `source` moves into every product it holds, so `affectedProducts[]` is one flat entry per product that names who made the statement. Each range's `changes` move out to `versionChanges[]` on the product, each entry keyed by the `versionIndex` of the `versions` entry it sits inside, and every `versions` entry is kept, empty or not, so those indexes stay aligned with upstream.

Dropping `changes` instead would turn a range such as "affected from 1.0, unaffected from 1.4, affected again from 2.0" into "affected from 1.0 to the upper bound" — a fixed release read as vulnerable. Applying them takes a sort: within one range, order the changes by version under that range's `versionType` before reading them.

### History tool is separate, not an option on nvd_get_cve

CVE history is a distinct endpoint (`/cvehistory/2.0`) returning a different response shape (`cveChanges` array with `details` per event). It's a deliberate separate tool rather than an `includeHistory` flag on `nvd_get_cve` because: (a) it significantly increases payload size and latency for every single CVE lookup, (b) agents only need it for specific investigative workflows ("when was this CVE re-scored?"), not routine lookups.

### nvd_get_cve batch size and output budget

The NVD `cveIds` parameter accepts up to 100 IDs in a single request. A single full CVE record can run 5–15KB (CVSS matrices, CPE configurations, references); 100 records can easily exceed 1MB. This is too large for most context budgets.

The tool exposes a `brief` boolean (default `false`). When `true`, each record is trimmed to: `cveId`, `vulnStatus`, top-severity CVSS score + label + version, `cisaVulnerabilityName` (if KEV), and `published` date — enough for triage without the full configuration details. For bulk lookups (>10 IDs), agents should default to `brief: true` and call `nvd_get_cve` with individual IDs only when full detail is needed.

The tool description documents this explicitly so agents make the tradeoff deliberately, not by accident.

### Oversized read requests clamp with disclosure

With `NVD_CLAMP_LIMITS=true` (default), paged requests above the NVD limit process 2000 CVEs/events or 10000 CPEs, and batch lookup processes the first 100 distinct IDs. Clamped calls carry optional `requestedLimit`, `effectiveLimit`, and a notice on both surfaces, log once, and increment a counter with bounded tool-name labels. Unclamped calls add no clamp fields. The false setting restores advertised maxima and rejection. Zero, negative, and fractional page limits always fail.

Batch lookup splits a string `cveIds` on commas and whitespace, matches IDs regardless of case, deduplicates them (first occurrence kept), and validates every ID before selecting the prefix, so the cap counts distinct IDs. `unprocessedIds` holds normalized IDs after that prefix; `missingIds` holds attempted IDs NVD did not return, each once. `requested` counts the processed prefix and `requestedLimit` the distinct IDs. This preserves upstream request bounds while allowing a caller to continue explicitly. With `NVD_CLAMP_LIMITS=false`, an array is held to 100 elements by its schema, and a string naming more than 100 distinct IDs fails `too_many_cve_ids` before any request, because its count is known only after the split.

### nvd_search_cves date convenience params

`pubDays`, `lastModDays`, and `kevDays` are integer shorthands for date-range queries on NVD's three date axes: publication, last modification, and the date CISA added the CVE to KEV. A shared resolver (`src/mcp-server/tools/date-windows.ts`, used by `nvd_search_cves` and `nvd_audit_cpe`) translates them to the API's required date-pair format at call time:

- `pubDays: N` → `pubStartDate = now − N × 24 h`, `pubEndDate = now`
- `lastModDays: N` → `lastModStartDate = now − N × 24 h`, `lastModEndDate = now`
- `kevDays: N` → `kevStartDate = now − N × 24 h`, `kevEndDate = now`

Arithmetic is UTC milliseconds from one `now` per call, ending on a whole second, so a shorthand spans exactly N × 24 hours in any server time zone. Local-calendar arithmetic shifts any window containing a clock change by an hour, which stretches a 120-day window past the limit NVD enforces.

The NVD API enforces a 120-day maximum range. If a shorthand exceeds 120, the tool clamps the value to 120 and reports the clamping in the `datesClamped` enrichment field so the agent knows the window was narrowed. Passing a shorthand together with its explicit pair is a validation error — they're mutually exclusive. An explicit pair needs both ends and at most 120 days between them.

Every explicit date must be `YYYY-MM-DDThh:mm[:ss[.fraction]]` with an optional `Z` or `±hh:mm` offset — a four-digit or signed six-digit year, a real calendar date, an hour of at most 23, a fraction of at most nine digits, an offset of at most ±18:00, `T` and `Z` in either case — or the call fails with `invalid_date_format` before any request. NVD answers a bare date, a space separator, a colonless offset, an offset past ±18:00, and a fraction past nine digits with a 404, so the tool rejects them up front with the accepted form in the message. A value without an offset is read as UTC for the span check, and values are sent to NVD unchanged.

A shorthand re-expands on every call, so offset paging over one skips or repeats records as the window moves. The first page's next-page notice therefore names the `filtersApplied` dates to send in place of the shorthand. Past offset 0, `filtersApplied` holds that call's re-expanded window rather than the first page's, so the next-page notice names only the offset and a second notice says the window was re-expanded and that the first page's dates hold it still.

### Rate limiting: queue, not per-call sleep

The NVD enforces sliding window rate limits (5 or 50 requests per 30-second window). The service layer paces requests through a single queue enforcing a minimum inter-request gap, rather than per-call sleeps, so burst requests from a tool like `nvd_get_cve` (which could fan out to multiple API pages) are queued correctly rather than racing. Without a key, the effective throughput is one request per 6 seconds — agents should be aware they may wait for queued requests.

**Retry wraps the queue rather than sitting inside it.** Every attempt — the first try and each retry — is enqueued separately and takes its own turn, so a retrying call spends its retries against the same budget as any other request. The alternative (retrying inside one queue slot) lets a single call fire its whole retry fan-out unpaced, which is how a lone transient failure used to exhaust the keyless budget and self-inflict 403s.

**A rate-limit response holds the queue, and only one wait fits inside a call.** The parsed `Retry-After` (~30s) blocks every pending request until NVD's window resets, not just the retrying one. Two such waits would outlast the 55-second call deadline, so at most one fits inside a call: a keyed call spends it on a single patient retry, while a keyless call fails fast and names `NVD_API_KEY`. Keyless calls retry other transient failures once rather than three times. A 403 HTML response containing NVD's block marker and no `Retry-After` instead raises nonretryable `nvd_request_blocked` without changing queue backoff.

**One 55-second deadline covers the whole call.** Every NVD request a tool call makes — its queue wait, attempts, backoff, and any `Retry-After` wait — settles within 55 seconds of the call's start, which sits under the 60-second request timeout MCP SDK clients default to. A failure that lands after the client gives up never reaches the caller, so the server ends the call first with a retryable error the caller can act on. Each attempt's timeout is the lesser of `NVD_REQUEST_TIMEOUT_MS` and what remains of the deadline, so raising the setting lengthens attempts, never the call. A call still queued when its deadline arrives leaves the queue and sends nothing.

**Response bodies remain inside the attempt lifetime.** The timeout and caller signal cover headers and body consumption. Caller cancellation propagates as `RequestCancelled` at every stage — before headers, mid-body, mid-backoff, queued, or held by `Retry-After`; an attempt outliving its timeout, or a call outliving its deadline, is `nvd_timeout`. A cancelled source-dictionary lookup leaves its cache cold. JSON parsing and endpoint-envelope validation happen after transport retries; malformed JSON or unusable envelopes raise nonretryable `nvd_invalid_response` rather than an empty success or a missing-record result. Optional source metadata can still fall back to raw identifiers when unavailable.

Two transport reasons carry the retryable failures. `nvd_unavailable` (`ServiceUnavailable`) is an HTTP 5xx, or a network or body-read failure, after the client's retries; `nvd_timeout` (`Timeout`) is an attempt outliving its timeout or the call outliving its deadline, and its data carries the `endpoint`. Both are `retryable: true` and attach no recovery hint of their own, so each definition's declared recovery reaches the caller. Any other unexpected status stays unclassified.

All five tools and the CVE resource declare `nvd_invalid_response` (`ServiceUnavailable`), `nvd_request_blocked` (`Forbidden`), `nvd_unavailable`, `nvd_timeout`, and `nvd_invalid_api_key` (`ConfigurationError`) with recovery guidance. The `rate_limited` recovery tells the caller to wait and retry and leaves `NVD_API_KEY` to a server operator, since a caller cannot set it. Search also declares `nvd_request_rejected` with case-sensitive CWE forms and full datetime examples. The two CPE tools declare it too, for a 404 whose `message` does not name the CPE parameter: only one that names it (`cpeName` or `virtualMatchString` on the audit, `cpeMatchString` on the CPE search) becomes `invalid_cpe_format`, since the same 404 answers a date the audit sends and NVD sometimes names no parameter at all.

**Deterministic rejections are never retried.** NVD answers a 404 with an empty body and its diagnosis in a `message` response header. The client throws it as an `McpError` carrying `data.retryable === false` (the framework's opt-out) so `withRetry` fails fast instead of re-sending a request that cannot succeed. Callers key off that error shape via `isNvdRequestRejected()` rather than matching the message text.

That 404 covers two unrelated faults, and only the `message` header separates them: a rejected parameter (`Invalid cveId parameter.`, `Invalid cpeName parameter, see documentation.`) versus a refused API key (`Invalid apiKey.`). The client splits them — a refused key raises `ConfigurationError` / `nvd_invalid_api_key` naming `NVD_API_KEY`, everything else raises `ValidationError` / `nvd_request_rejected` carrying NVD's own wording. Collapsing the two would tell a caller its CVE ID is malformed when the ID is fine and the key is the fault, sending it to correct something that can never succeed.

`nvd_invalid_api_key` is a transport-layer fault rather than a property of any one tool: every tool surfaces it, none can act on it, and the fix is always the `NVD_API_KEY` value. Every definition still declares it, because the contract is the failure surface a caller can plan around and this failure reaches every caller. The client attaches its own operator-worded hint, which wins over a declared one, so each declared recovery repeats that hint word for word.

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
| `cvssV2Severity` | `LOW`\|`MEDIUM`\|`HIGH` | Mutually exclusive with v3/v4 severity filters; one band parameter per request |
| `cvssV3Severity` | `LOW`\|`MEDIUM`\|`HIGH`\|`CRITICAL` | Mutually exclusive with v2/v4 severity filters |
| `cvssV4Severity` | `LOW`\|`MEDIUM`\|`HIGH`\|`CRITICAL` | Mutually exclusive with v2/v3 severity filters |
| `cweId` | string | e.g., `CWE-79`; also accepts `NVD-CWE-Other`, `NVD-CWE-noinfo` |
| `hasKev` | flag | Filter to CISA KEV catalog entries only |
| `pubStartDate` / `pubEndDate` | `YYYY-MM-DDThh:mm[:ss[.fraction]][Z\|±hh:mm]` | Max 120-day range; both required; no offset is read as UTC |
| `lastModStartDate` / `lastModEndDate` | `YYYY-MM-DDThh:mm[:ss[.fraction]][Z\|±hh:mm]` | Max 120-day range; both required; no offset is read as UTC |
| `kevStartDate` / `kevEndDate` | `YYYY-MM-DDThh:mm[:ss[.fraction]][Z\|±hh:mm]` | Window in which CISA added the CVE to KEV; max 120-day range; both required; returns only catalog members |
| `noRejected` | flag | Exclude REJECT/Rejected status CVEs |
| `resultsPerPage` | int | Max 2,000 (default 2,000) |
| `startIndex` | int | Zero-based offset for pagination |

### Error Behavior

- Invalid CVE ID format (e.g., `CVE-INVALID`) → HTTP 404, empty body
- Valid CVE ID that doesn't exist in NVD → HTTP 200, `totalResults: 0`, empty `vulnerabilities: []`
- Rate limit exceeded → HTTP 403 with `Retry-After` header (typically 30s window reset)
- Mutually exclusive params used together → HTTP 400
- Date value outside the accepted form (a bare date, a space separator, a colonless offset) → HTTP 404, empty body
- Keyword refused as too broad → HTTP 404, `message: Keyword search too broad.`; exact-phrase matching does not lift it, more specific words do

### KEV Fields on CVE

Present only when the CVE appears in the CISA KEV catalog:

- `cisaExploitAdd` — date added to KEV catalog
- `cisaActionDue` — remediation deadline for federal agencies (BOD 22-01)
- `cisaRequiredAction` — required remediation steps
- `cisaVulnerabilityName` — CISA's human-readable name for the CVE

---

## Tool Detail

### `nvd_get_cve`

**Description:** Fetch one or more CVEs by ID. Returns CVSS scores across all available versions with who supplied each, CWE weaknesses, affected CPE configurations from NVD analysis, the affected products the CNA and any ADP state themselves, the record's source and tags, CISA KEV fields, current SSVC assessments, and (optionally) references. Up to 100 distinct CVE IDs per call. Use `brief: true` for bulk lookups — full records for 100 CVEs can exceed 1MB.

**Input:**
- `cveIds: string | string[]` — one CVE ID, a comma- or whitespace-separated string of IDs (split on `/[\s,]+/`, empty pieces dropped), or an array (elements are never split) of up to 100 distinct IDs (e.g., `"CVE-2021-44228"`, `"CVE-2021-44228,CVE-2022-0001"`, or `["CVE-2021-44228", "CVE-2022-0001"]`). IDs match regardless of case and each distinct ID is fetched once. A malformed piece of a joined string fails `invalid_cve_id_format` quoting that piece alone.
- `brief?: boolean` — default `false`. When `true`, returns trimmed records (ID, status, top CVSS score, KEV name, published date, truncated description) instead of full detail. Recommended for batches of more than 10.
- `includeReferences?: boolean` — default `true`. Set to `false` to omit the references array and reduce response size.
- `includeConfigurations?: boolean` — default `true`. Set to `false` to omit configuration nodes from both surfaces.
- `includeAffected?: boolean` — default `true`. Set to `false` to omit `affectedProducts` from full records and their rendered text. The field adds roughly 0.3–0.5 KB to an ordinary record and over 25 KB to one with many product statements.
- `allLanguages?: boolean` — default `false`. When `false`, full records keep only the English description (falling back to whatever exists if a record has no English entry); set `true` to keep every localized description. Brief records always carry a single truncated description.

**Output:**
- `brief: boolean` — which mode produced the records below.
- `cves[]` — one item schema spanning both modes, since a tool's `output` must be a flat object and cannot branch on a discriminator. `cveId`, `vulnStatus`, and `published` are the only required fields; every field either mode adds is declared optional, because the framework parses each success return against this schema and a full-record field marked required would reject every `brief: true` call.
  - Full mode (the default) emits `lastModified`, `descriptions`, `cvssScores` (all versions present, each with its `source`), `severity` (highest score label + version source), `weaknesses`, `configurationNodes`, `references` (unless `includeReferences: false`), `cisaKev` (KEV catalog members only), `sourceIdentifier` (the CNA that submitted the record), `cveTags` (omitted when no contributor attached any), and `affectedProducts` (unless `includeAffected: false`; `[]` when no contributor sent any). Each `affectedProducts` entry is one product statement by the CNA or an ADP: `source`, `vendor`, `product`, package identity (`collectionURL`, `packageName`, `packageURL`, `repo`), `defaultStatus`, `cpes`, `modules`, `programFiles`, `programRoutines`, `platforms`, `versions` (bounds, `versionType`, status), and `versionChanges`. The `source` on a weakness, reference, score, tag set, or product carries the contributor name NVD publishes for the identifier (`CVE`, `CISA-ADP`); an email-form identifier keeps its address, and an identifier the dictionary does not hold passes through raw. Brief mode drops `source` entirely, so it neither resolves nor reports one.
  - Brief mode emits `description` (first 200 characters, English-preferred), `severity`, and `cisaVulnerabilityName` — the trimmed substitutes for `descriptions` and `cisaKev`.
  - The full-record fields come from the shared `CveRecordSchema` (`src/mcp-server/tools/schemas/full-cve.ts`). Audit derives its output schema with optional `configurationNodes` and `affectedProducts` for section selection; the full domain record retains those required fields.

`format()` tests each field for presence instead of branching on `brief`: the record itself says which fields it carries, and a mode-branched formatter renders only one field set per call — leaving the other mode's fields unverifiable against the declared schema.

**Enrichment:** this tool looks up specific IDs rather than paging a result set, so it carries no pagination fields.
- `requested: number` — how many distinct CVE IDs the processed prefix contains
- `returned: number` — how many records came back
- `missingIds?: string[]` — requested IDs NVD held no record for; absent when every ID matched
- `unprocessedIds?: string[]` — normalized IDs outside the processed prefix, deduplicated in request order
- `requestedLimit?: number` / `effectiveLimit?: number` — distinct requested IDs and processed batch size, present only when clamped

**Rendering parity.** Both surfaces carry every selected field: descriptions, references, configuration groups, nodes, match criteria, and affected-product statements render in full. The status line adds ` | **Source:** …` and ` | **CVE Tags:** …`, each CVSS line names its scorer in brackets after the Primary/Secondary label, and an `**Affected Products (CNA/ADP):**` section follows the configurations when the record has any. `includeReferences`, `includeConfigurations`, and `includeAffected` default to true; any can be false to omit its field from both surfaces without changing the upstream lookup. Brief mode remains the deliberate compact shape. Optional `ssvc` assessments retain the source, timestamp, and decision points NVD supplies; absence remains absence.

**Errors:**
```
errors: [
  { reason: 'invalid_cve_id_format', code: 'ValidationError',
    when: 'One or more CVE IDs fail format validation (NVD returns HTTP 404 with empty body for malformed IDs). Message names the offending IDs.',
    retryable: false },
  { reason: 'too_many_cve_ids', code: 'ValidationError',
    when: 'A cveIds string names more than 100 distinct IDs and the server rejects oversized requests (NVD_CLAMP_LIMITS=false). Message: "cveIds names N distinct CVE IDs; at most 100 are accepted per call."',
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

**Description:** Search CVEs by keyword, severity, CWE, publication or last-modified date, KEV status, or the date CISA added a CVE to KEV. The primary discovery tool for surveillance and triage workflows. `pubDays`, `lastModDays`, and `kevDays` are convenience shorthands for date-range queries — the tool converts them to API date pairs ending at call time and clamps values over 120 days (the API maximum), reporting the clamped range in the response enrichment. A shorthand re-expands on every call, so a crawl pages with the dates echoed in `filtersApplied`.

**Input:**
- `keyword?: string` — full-text search across CVE descriptions (AND-semantics across words)
- `exactPhrase?: boolean` — default `false`. When `true`, `keyword` matches as a phrase instead of ANDing its words independently, forwarded as the valueless `keywordExactMatch` flag. Requires `keyword`; without one it raises `exact_phrase_without_keyword` rather than running the search unmodified.
- `severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'` — CVSS severity filter: NVD matches exactly this band at `severityVersion`, not a floor, so covering several bands takes one call per band
- `severityVersion?: 'v2' | 'v3' | 'v4'` — CVSS version for severity filter (default `v3`, which matches either v3.x metric)
- `cweId?: string` — e.g., `"CWE-79"`, `"NVD-CWE-Other"`
- `pubDays?: number` — CVEs published in the last N days, expanded to a pair spanning exactly N × 24 hours up to call time (max 120; values over 120 are clamped). Mutually exclusive with `pubStartDate`/`pubEndDate`.
- `lastModDays?: number` — CVEs modified in the last N days, expanded the same way (max 120; values over 120 are clamped). Mutually exclusive with `lastModStartDate`/`lastModEndDate`.
- `kevDays?: number` — CVEs CISA added to the KEV catalog in the last N days, expanded the same way (max 120; values over 120 are clamped). Returns only catalog members. Mutually exclusive with `kevStartDate`/`kevEndDate`.
- `pubStartDate?: string` / `pubEndDate?: string` — `YYYY-MM-DDThh:mm[:ss[.fraction]]` with an optional `Z` or `±hh:mm` offset (no offset is read as UTC); max 120-day span; both required together
- `lastModStartDate?: string` / `lastModEndDate?: string` — same form; max 120-day span; both required together
- `kevStartDate?: string` / `kevEndDate?: string` — same form; the window in which CISA added the CVE to the catalog; max 120-day span; both required together; returns only catalog members
- `kevOnly?: boolean` — filter to CISA KEV catalog entries only, whenever CISA added them. A KEV window already returns only catalog members.
- `noRejected?: boolean` — exclude REJECT/Rejected status CVEs (default `true`)
- `limit?: number` — max results (default 20, max 2000)
- `offset?: number` — zero-based page offset

**Output:**
- `cves: BriefCveRecord[]` — array of CVE summaries, each `{ cveId, vulnStatus, published, description?, severity?, filteredSeverity?, cisaVulnerabilityName? }`. `description` is the first 200 characters of the English text (English-preferred, falling back to whatever prose exists), enough to tell one hit from another without a follow-up fetch; call `nvd_get_cve` for full detail on specific IDs.

**Enrichment:**
- `totalCount: number` — total matching CVEs in NVD before pagination
- `returned: number` — CVEs in this response
- `offset: number` — page offset used
- `datesClamped?: { param, original, clamped }[]` — present when a `pubDays`/`lastModDays`/`kevDays` value was reduced to 120; `param` names the shorthand
- `filtersApplied?: { keyword?, exactPhrase?, severity?, severityVersion?, cweId?, pubStartDate?, pubEndDate?, lastModStartDate?, lastModEndDate?, kevStartDate?, kevEndDate?, kevOnly?, noRejected? }` — effective filters sent to NVD, including explicit or expanded date windows for exact replay; absent when the query ran unfiltered
- `notice?: string` — ignored blank filters, limit clamping, and pagination guidance. String filters are trimmed; blank filters are omitted before companion checks. A next-page notice names the offset and, on the first page of a window a shorthand set, the `filtersApplied` dates to send in its place; past offset 0, a notice flags a shorthand window re-expanded for this call and names the first page's dates as the ones to send.

**Errors:**
```
errors: [
  { reason: 'exact_phrase_without_keyword', code: 'ValidationError',
    when: 'exactPhrase set without a keyword — it selects how keyword matches and has nothing to modify alone.',
    retryable: false },
  { reason: 'mutually_exclusive_params', code: 'ValidationError',
    when: 'A date shorthand sent with its explicit range: pubDays with pubStartDate/pubEndDate, lastModDays with lastModStartDate/lastModEndDate, or kevDays with kevStartDate/kevEndDate.',
    retryable: false },
  { reason: 'missing_date_pair', code: 'ValidationError',
    when: 'Only one end of an explicit date range provided — NVD requires both.',
    retryable: false },
  { reason: 'date_range_inverted', code: 'ValidationError',
    when: 'The end date of a date range is before its start date.',
    retryable: false },
  { reason: 'date_range_exceeds_max', code: 'ValidationError',
    when: 'An explicit pub, lastMod, or KEV date range spans more than 120 days. (Shorthands over 120 are auto-clamped, not an error.)',
    retryable: false },
  { reason: 'invalid_date_format', code: 'ValidationError',
    when: 'A date field is not YYYY-MM-DDThh:mm[:ss[.fraction]] with an optional Z or ±hh:mm offset, or names a day the calendar lacks. Raised before any request.',
    retryable: false },
  { reason: 'invalid_severity_for_version', code: 'ValidationError',
    when: 'severity="CRITICAL" with severityVersion="v2" — CVSS v2 has no CRITICAL tier.',
    retryable: false },
  { reason: 'nvd_request_rejected', code: 'ValidationError',
    when: 'NVD rejected a search parameter. A keyword NVD refuses as too broad keeps this reason with a hint to add more specific words (every word must match) or drop the keyword.',
    retryable: false },
  { reason: 'rate_limited', code: 'RateLimited',
    when: 'HTTP 403 with Retry-After; queue exhausted.',
    retryable: true },
]
```

**Annotations:** `readOnlyHint: true`, `openWorldHint: false`

---

### `nvd_audit_cpe`

**Description:** Find all CVEs affecting a specific product and version. Requires either an exact CPE name (`cpeName`) or a partial match string (`virtualMatchString`) with optional version range bounds. When `cpeName` is used, NVD applies the `isVulnerable` flag to exclude configurations where the CPE appears as a dependency but is not itself the vulnerable component. Use `nvd_search_cpes` first to resolve the correct CPE string when it is not known — do not guess. The audit can be narrowed server-side with `kevOnly`, an exact severity band, or publication, last-modified, or KEV-addition date windows; a shorthand re-expands on every call, so a crawl pages with the dates echoed in `filtersApplied`.

**Input:**
- `cpeName?: string` — full CPEv2.3 name (e.g., `"cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"`). When provided, `isVulnerable` is automatically added to the API request.
- `virtualMatchString?: string` — partial CPE match pattern (e.g., `"cpe:2.3:a:apache:http_server:*"`). Use with version range params for range-based audits.
- `versionStart?: string`, `versionStartType?: 'including' | 'excluding'` — lower version bound; requires `virtualMatchString`
- `versionEnd?: string`, `versionEndType?: 'including' | 'excluding'` — upper version bound; requires `virtualMatchString`
- `kevOnly?: boolean` — default `false`. Limits the audit to CVEs in the CISA KEV catalog, whenever CISA added them (sent as `hasKev`). A KEV window already returns only catalog members.
- `severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'` / `severityVersion?: 'v2' | 'v3' | 'v4'` (default `v3`) — server-side filter to exactly this band at that CVSS version, as on `nvd_search_cves`. NVD matches the one band, not a floor, so `totalCount` and paging count that band alone; covering several bands takes one call per band. CRITICAL with `v2` fails `invalid_severity_for_version`.
- `pubDays?` / `lastModDays?` / `kevDays?` and `pubStartDate?`/`pubEndDate?`, `lastModStartDate?`/`lastModEndDate?`, `kevStartDate?`/`kevEndDate?` — the same date windows as `nvd_search_cves`: same parser, grammar, 120-day maximum, clamping, and shorthand paging notices. Blank date fields are dropped with an `Ignored empty <fields>.` notice.
- `severityMin?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'` — filter by the highest band across every CVSS metric without changing the canonical headline. Applied to the fetched page only, so `totalCount` is unchanged; use `severity` for a band that `totalCount` and paging count. Composes with `severity` as AND.
- `allLanguages?: boolean` — default `false`. When `false`, each record keeps only its English description (falling back to whatever exists if a record has no English entry); set `true` to keep every localized description.
- `includeConfigurations?: boolean` / `includeAffected?: boolean` / `includeReferences?: boolean` — all default `true`; false omits that field from both output surfaces.
- `limit?: number` — max results (default 20, max 2000)
- `offset?: number` — zero-based page offset, passed upstream as `startIndex`

Exactly one of `cpeName` or `virtualMatchString` is required.

**Paging.** Despite auditing by CPE, this tool queries `cves/2.0`, whose `resultsPerPage` ceiling is 2,000 — not the 10,000 of the `cpes/2.0` endpoint `nvd_search_cpes` pages. `offset` is independent of that ceiling on both endpoints. Page with `offset` at a modest `limit` rather than raising `limit` to reach further: this tool returns full CVE records, so a large `limit` is a large response, and it also widens what `severityMin` filters in a single pass.

**Output:**
- `cves: CveRecord[]` — full CVE records (this is a targeted audit, not a search — full detail is appropriate), carrying the same fields as `nvd_get_cve` full mode, including each score's supplier and the CNA/ADP `affectedProducts`

**Enrichment:**
- `totalCount: number` — total CVEs matched before pagination
- `returned: number` — records in this response
- `offset: number` — page offset used
- `auditTarget: string` — the `cpeName` or `virtualMatchString` the audit ran against, so the caller can verify the right product was queried
- `severityMin?: string` — the client-side severity threshold applied; absent when none was set
- `filteredCount?: number` — CVEs the `severityMin` filter dropped from the page NVD returned. Present whenever `severityMin` is set. This is not `totalCount − returned`: CVEs beyond `limit` were never fetched, so they were never evaluated against the filter
- `datesClamped?: { param, original, clamped }[]` — present when a date shorthand was reduced to 120
- `filtersApplied?: { severity?, severityVersion?, pubStartDate?, pubEndDate?, lastModStartDate?, lastModEndDate?, kevStartDate?, kevEndDate?, kevOnly? }` — the server-side filters this audit applied beyond its target, the ones `totalCount` counts within, including expanded date windows for exact replay; absent when none was set. `severityMin` keeps its own field because it filters the fetched page, not the query
- `notice?: string` — distinguishes a target NVD holds no CVEs for, a target with none matching the server-side filters (not a clean audit), a `severityMin` threshold that emptied the page, and an `offset` past the end of the result set. A page `severityMin` emptied names the next offset (`offset + filteredCount`) while CVEs remain past it; once none do, it says the target is exhausted at that threshold and offers only lowering `severityMin`. On the first page of a shorthand window a next-page offset carries the `filtersApplied` dates; past offset 0 a re-expanded shorthand window is flagged with the first page's dates as the ones to send, and ignored blank date filters are reported. The next offset on a partial page is `offset + returned + filteredCount`.

**Configurations rendering.** Both surfaces carry every selected normalized configuration node and match criterion, preserving group membership, operators, version bounds, and vulnerable/context flags. References and affected-product statements render in full. `includeConfigurations: false`, `includeAffected: false`, or `includeReferences: false` omits that field from both surfaces; the selectors default to true.

Each rendered line names the node's `groupIndex`, its `groupOperator`, and its `nodeOperator`, because the three answer different questions: `nodeOperator` combines the criteria inside one node, `groupOperator` combines that node with its sibling nodes, and `groupIndex` says which nodes those siblings are. An `AND` at the group level marks conditions that must hold together (a firmware node plus the hardware it runs on); without the group index a reader cannot tell which nodes it joins, and the criteria read as unrelated alternatives.

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
  { reason: 'nvd_request_rejected', code: 'ValidationError',
    when: 'NVD rejected a parameter other than the CPE (a date it cannot parse), or rejected the request without naming one. Only a 404 whose message names cpeName or virtualMatchString is invalid_cpe_format.',
    retryable: false },
  { reason: 'mutually_exclusive_params' | 'missing_date_pair' | 'date_range_inverted' | 'date_range_exceeds_max' | 'invalid_date_format', code: 'ValidationError',
    when: 'The date-window failures of nvd_search_cves, identical on both tools, raised before any request.',
    retryable: false },
  { reason: 'invalid_severity_for_version', code: 'ValidationError',
    when: 'severity="CRITICAL" with severityVersion="v2" — CVSS v2 has no CRITICAL tier.',
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
  { reason: 'nvd_request_rejected', code: 'ValidationError',
    when: 'NVD rejected a parameter other than cpeMatchString, or rejected the request without naming one. Only a 404 whose message names cpeMatchString is invalid_cpe_format.',
    retryable: false },
  { reason: 'rate_limited', code: 'RateLimited',
    when: 'HTTP 403 with Retry-After; queue exhausted.',
    retryable: true },
]
```

**Annotations:** `readOnlyHint: true`, `openWorldHint: false`

---

### `nvd_get_cve_history`

**Description:** Retrieve the change history for a single CVE — CVSS score revisions, reference additions, status transitions (e.g., `Received` → `Analyzed`), and CPE configuration updates. Use when tracking a CVE's escalation or investigating when a score changed. The history endpoint is significantly slower than the other NVD endpoints, especially on a server running without an API key; a call that outlasts its 55-second deadline fails as a retryable `nvd_timeout`.

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

- **Date range cap**: All date-filtered queries (published, last modified, KEV dates) are limited to 120 consecutive days per request. Multi-month surveillance requires consecutive windows of at most 120 days, each paged to the end.
- **No full-text search of references**: `keywordSearch` only matches CVE descriptions, not advisory text, reference titles, or CPE data.
- **CPE version range is partial match only**: `cpeName` with an exact version matches that version against stored CPE match criteria. Whether a specific patch version is affected requires checking `versionEndExcluding`/`versionEndIncluding` fields in the `configurationNodes[].cpeMatch[]` response data — the API doesn't directly answer "is 2.4.53 affected?" without parsing the match criteria client-side.
- **CVSS v2 deprecated**: NVD stopped generating new v2.0 scores in July 2022. Old CVEs may only have v2.0 scores; post-2022 CVEs will have v3.1 (and increasingly v4.0). The severity filter can't bridge across versions.
- **NVD analysis lag**: Newly published CVEs start in `Received` or `AwaitingAnalysis` status. CVSS scores, CPE configurations, and CWE classifications may be absent until NVD analysts process the CVE. This is a data completeness fact, not a server bug — surface `vulnStatus` in outputs. `affectedProducts` is the CNA's own statement, not NVD analysis, so it is present before analysis and is often the only product and version evidence on such a record; an empty `configurationNodes` on an unanalyzed record is not "no affected products".
- **Rate limit without API key is tight**: 5 requests per 30 seconds limits throughput severely. The queue handles compliance but can introduce multi-second latency under load. Strongly recommend obtaining a free API key.

<div align="center">
  <h1>@cyanheads/nist-nvd-mcp-server</h1>
  <p><b>Search and audit CVEs by keyword, severity, CWE, CISA KEV status, and CPE via the NIST National Vulnerability Database. STDIO or Streamable HTTP.</b>
  <div>5 Tools • 2 Resources</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.4.0-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/nist-nvd-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^2.4.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/nist-nvd-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/nist-nvd-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^7.0.2-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.4.4-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/nist-nvd-mcp-server/releases/latest/download/nist-nvd-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=nist-nvd-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvbmlzdC1udmQtbWNwLXNlcnZlciJdfQ==) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22nist-nvd-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fnist-nvd-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

<div align="center">

**Public Hosted Server:** [https://nist-nvd.caseyjhand.com/mcp](https://nist-nvd.caseyjhand.com/mcp)

</div>

---

## Overview

CVE and CPE data from the NIST National Vulnerability Database. Search and audit vulnerabilities by keyword, severity, CWE, or CISA KEV status, resolve products to CPE names, and track a CVE's revision history.

### Tools

| Tool | Description |
|:-----|:------------|
| `nvd_search_cves` | Search CVEs by keyword, severity, CWE, publication or last-modified date, CISA KEV status, or the date CISA added a CVE to KEV. |
| `nvd_get_cve` | Fetch one or more CVEs by ID — full CVSS scores with their suppliers, CWE, CPE configs, CNA/ADP affected products, KEV fields, and references. |
| `nvd_search_cpes` | Search the NVD CPE dictionary by product keyword or partial match string. |
| `nvd_audit_cpe` | Find all CVEs affecting a specific product version by CPE name or virtual match string, optionally narrowed server-side by KEV status, severity band, or date window. |
| `nvd_get_cve_history` | Retrieve the change history for a CVE — score revisions, status transitions, and reference additions. |

### Resources

| Resource | Description |
|:---------|:------------|
| `nvd://cve/{cveId}` | Full CVE record by ID — same data as `nvd_get_cve` for a single ID, as a stable URI for injectable context. |
| `skill://nist-nvd-guide/SKILL.md` | Product applicability, identifier chains, severity interpretation, and coverage guidance. |

CVE resource data is also reachable via `nvd_get_cve`. The published guide is also available to plugin installs under [`skills/nist-nvd-guide/SKILL.md`](./skills/nist-nvd-guide/SKILL.md).

## Capability reference

Oversized read limits clamp by default: 2000 for CVE search, audit, and history; 10000 for CPE search; 100 distinct IDs for batch lookup. Clamped calls report `requestedLimit`, `effectiveLimit`, and a notice on both output surfaces. Batch lookup validates every supplied ID and lists normalized, deduplicated IDs beyond the processed prefix in `unprocessedIds`; `missingIds` covers queried IDs only. Set `NVD_CLAMP_LIMITS=false` before startup to restore advertised maxima and reject oversized requests (a `cveIds` string naming more than 100 distinct IDs fails `too_many_cve_ids`). Zero, negative, and fractional limits remain invalid.

### `nvd_search_cves` <sub>tool</sub>

- Full-text keyword search (AND-semantics across words), or `exactPhrase: true` for an exact-phrase match — requires `keyword`
- Filters: CVSS severity band (LOW/MEDIUM/HIGH/CRITICAL — CRITICAL requires `severityVersion: "v3"` or `"v4"`), CWE ID, CISA KEV status (`kevOnly`), `noRejected` (default true)
- Date filters on three axes — publication, last modification, and the date CISA added the CVE to KEV: `pubDays`/`lastModDays`/`kevDays` shorthands (exactly N × 24 hours up to call time, auto-clamped to 120 days, clamping reported in the enrichment) or explicit ranges (`pubStartDate`/`pubEndDate`, `lastModStartDate`/`lastModEndDate`, `kevStartDate`/`kevEndDate`; 120-day max span, both ends required); the two forms per axis are mutually exclusive. A KEV window returns only catalog members
- Explicit dates are `YYYY-MM-DDThh:mm[:ss[.fraction]]` with an optional `Z` or `±hh:mm` offset; a value without an offset is read as UTC
- A shorthand re-expands on every call: page with the dates echoed in `filtersApplied` (the next-page notice names them) so every page reads one window
- Pagination via `limit` (up to 2000, default 20) and `offset`
- Always returns brief summaries with a truncated description; call `nvd_get_cve` for full detail

---

### `nvd_get_cve` <sub>tool</sub>

- Batch up to 100 distinct CVE IDs per call, as an array or one comma- or whitespace-separated string; IDs match regardless of case and a repeat is fetched once
- Full mode (default): CVSS scores across v2.0/v3.0/v3.1/v4.0, each with the contributor that supplied it, CWE weaknesses, CPE configurations from NVD analysis, the affected products the CNA and any ADP state themselves (`affectedProducts`), the record's `sourceIdentifier` and `cveTags`, CISA KEV fields, references
- `brief: true` returns trimmed rows (ID, status, top severity, KEV name, truncated description) — recommended for batches over 10
- `includeReferences`, `includeConfigurations`, and `includeAffected` default to true; set any false to omit that field from both output surfaces. `allLanguages: true` keeps every localized description instead of English-only
- `missingIds` enrichment field lists any requested IDs NVD didn't return
- Both output surfaces carry every selected reference, CPE configuration, and affected-product statement; optional SSVC assessments appear when NVD supplies them

---

### `nvd_search_cpes` <sub>tool</sub>

- Keyword search (e.g. `"apache http server"`) or a partial CPEv2.3 pattern via `cpeMatchString` — at least one required
- Returns full CPE name, human-readable title, deprecation status, and superseding CPEs
- Pagination via `limit` (up to 10,000, default 20) and `offset` — a vendor-level keyword can match tens of thousands of entries, so page rather than narrowing further
- Use before `nvd_audit_cpe` to resolve the exact CPE name a product needs

---

### `nvd_audit_cpe` <sub>tool</sub>

- Two modes: exact `cpeName` (NVD auto-applies `isVulnerable`) or `virtualMatchString` with optional `versionStart`/`versionEnd` bounds (inclusive/exclusive)
- Server-side filters, same forms as `nvd_search_cves`: `kevOnly`, an exact severity band (`severity` + `severityVersion`, CRITICAL requires v3 or v4), and the publication, last-modified, and KEV-addition date windows (`pubDays`/`lastModDays`/`kevDays` shorthands or explicit pairs). `totalCount` and paging count within them; the echoed dates in `filtersApplied` page a shorthand window
- Client-side `severityMin` filters the fetched page by the highest severity band across all CVSS metrics; the headline still follows the highest numerical score. It can only remove what `limit` retrieved, composes with `severity` as AND, and leaves `totalCount` unchanged
- A zero total under a server-side filter is reported as no match for the filters, not a clean audit; only an unfiltered zero reads as "no known vulnerabilities"
- Returns full CVE records (CVSS scores with their suppliers, CWE, CPE configurations, CNA/ADP affected products, KEV fields, references)
- `includeReferences`, `includeConfigurations`, and `includeAffected` default to true; false omits that field from both output surfaces. SSVC assessments remain optional
- Pagination via `limit` (up to 2000, default 20) and `offset` — page at a modest limit rather than raising it, since each result is a full record
- `auditTarget` enrichment field echoes the CPE identifier used, so callers can verify the correct product was queried

---

### `nvd_get_cve_history` <sub>tool</sub>

- Returns change events: CVSS revisions, status transitions, reference additions, CPE configuration updates
- `order` picks the anchor end — `newest` (default) reads most-recent-first, `oldest` reads NVD's native order
- Paginated via `limit` (up to 2000, default 20) and `offset`, counted from the end `order` anchors to
- The history endpoint is markedly slower than the others, especially on a server running without an API key (`NVD_API_KEY` raises the rate limit)

---

### `nvd://cve/{cveId}` <sub>resource</sub>

- Full CVE record as `application/json` — same data as `nvd_get_cve` for one ID, with references, CNA/ADP `affectedProducts`, and English-only descriptions
- `cveId` must match `CVE-YYYY-NNNNN`; a well-formed but unknown ID throws `cve_not_found`

## Features

Built on [`@cyanheads/mcp-ts-core`](https://github.com/cyanheads/mcp-ts-core): stdio and Streamable HTTP transports, pluggable auth (`none` / `jwt` / `oauth`), swappable storage (`in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`), structured logging with optional OpenTelemetry tracing.

NVD-specific:

- Request pacer enforces NVD's 5 req/30s (no key) and 50 req/30s (with key) limits with automatic queuing, at a minimum inter-request gap derived from the window and limit
- Retry wraps the pacer rather than sitting inside it — every attempt takes its own turn in the queue, so retries count against the rate budget instead of bursting past it
- A 403's `Retry-After` holds the whole queue until NVD's window resets; keyless, a 403 fails fast and names `NVD_API_KEY` rather than spending the 5-request budget on retries that cannot outlast a 30-second window
- Deterministic rejections fail fast instead of consuming retries — NVD answers both a bad parameter and a refused API key with HTTP 404, separated only by a `message` header, so a refused key surfaces as a config fault naming `NVD_API_KEY` rather than as a malformed CVE ID
- NVD block pages return a nonretryable blocked-request error; malformed JSON and response envelopes return an invalid-response error with recovery guidance
- One 55-second deadline covers every NVD request a tool call makes — queue wait, attempts, backoff, and any `Retry-After` wait — so a slow or failing NVD ends the call with a retryable `nvd_timeout` or `nvd_unavailable` before MCP clients' 60-second default timeout; each attempt's timeout is capped by what remains of it
- Request timeouts and caller cancellation remain active through response-body reads

Agent-friendly output:

- An `enrichment` block on every response, carried on both `structuredContent` and the rendered text — total results, returned count, page offset, the filters actually applied, and any date-clamping events, so agents can reason about what was really queried
- `missingIds` in batch CVE lookups — a per-ID parity check instead of a silent partial result
- CPE echo in audit responses — `cpeName` or `virtualMatchString` reflected back so callers can verify the correct product was audited
- Empty-result notices that name the cause — an unmatched query, a severity threshold that emptied the page, an offset past the end of the result set, a filtered audit with no match, and a clean audit ("no known vulnerabilities") are told apart rather than all reading as errors or "nothing found"

## Getting started

### Public Hosted Instance

A public instance is available at `https://nist-nvd.caseyjhand.com/mcp` — no installation required. Point any MCP client at it via Streamable HTTP:

```json
{
  "mcpServers": {
    "nist-nvd-mcp-server": {
      "type": "streamable-http",
      "url": "https://nist-nvd.caseyjhand.com/mcp"
    }
  }
}
```

### Self-Hosted / Local

Add the following to your MCP client configuration file.

```json
{
  "mcpServers": {
    "nist-nvd-mcp-server": {
      "type": "stdio",
      "command": "bunx",
      "args": ["@cyanheads/nist-nvd-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info",
        "NVD_API_KEY": "your-api-key"
      }
    }
  }
}
```

Or with npx (no Bun required):

```json
{
  "mcpServers": {
    "nist-nvd-mcp-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@cyanheads/nist-nvd-mcp-server@latest"],
      "env": {
        "MCP_TRANSPORT_TYPE": "stdio",
        "MCP_LOG_LEVEL": "info",
        "NVD_API_KEY": "your-api-key"
      }
    }
  }
}
```

Or with Docker:

```json
{
  "mcpServers": {
    "nist-nvd-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "MCP_TRANSPORT_TYPE=stdio",
        "-e", "NVD_API_KEY=your-api-key",
        "ghcr.io/cyanheads/nist-nvd-mcp-server:latest"
      ]
    }
  }
}
```

For Streamable HTTP, set the transport and start the server:

```sh
MCP_TRANSPORT_TYPE=http MCP_HTTP_PORT=3010 NVD_API_KEY=... bun run start:http
# Server listens at http://localhost:3010/mcp
```

### Prerequisites

- [Bun v1.4.4](https://bun.sh/) or higher (or Node.js v24+).
- Optional: [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) — free, raises rate limit from 5 req/30s to 50 req/30s.

### Installation

1. **Clone the repository:**

```sh
git clone https://github.com/cyanheads/nist-nvd-mcp-server.git
```

2. **Navigate into the directory:**

```sh
cd nist-nvd-mcp-server
```

3. **Install dependencies:**

```sh
bun install
```

4. **Configure environment:**

```sh
cp .env.example .env
# edit .env and set NVD_API_KEY if you have one
```

## Configuration

| Variable | Description | Default |
|:---------|:------------|:--------|
| `NVD_API_KEY` | NVD API key. Without it, rate limit is 5 req/30s; with it, 50 req/30s. Get one free at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key). | — |
| `NVD_REQUEST_TIMEOUT_MS` | Timeout for each NVD request attempt in milliseconds. Every attempt is also capped by what remains of the tool call's 55-second deadline, so raising it lengthens attempts, never the call. | `10000` |
| `NVD_CLAMP_LIMITS` | Clamp oversized reads to 2000 CVEs/events, 10000 CPEs, or 100 distinct CVE IDs. `false` restores schema maxima and rejection. | `true` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_AUTH_MODE` | Auth mode: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (RFC 5424). | `info` |
| `LOGS_DIR` | Directory for log files (Node.js only). | `<project-root>/logs` |
| `OTEL_ENABLED` | Enable [OpenTelemetry instrumentation](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry). | `false` |

See [`.env.example`](./.env.example) for the full list of optional overrides.

Node and Bun load `.env` from the working directory before server configuration is parsed. Exported variables take precedence. Invalid `NVD_CLAMP_LIMITS` values fail configuration validation; use `true` or `false`.

## Running the server

### Local development

- **Build and run:**

  ```sh
  # One-time build
  bun run rebuild

  # Run the built server
  bun run start:stdio
  # or
  bun run start:http
  ```

- **Run checks and tests:**

  ```sh
  bun run devcheck   # Lint, format, typecheck, security
  bun run test       # Vitest test suite
  bun run lint:mcp   # Validate MCP definitions against spec
  ```

### Docker

```sh
docker build -t nist-nvd-mcp-server .
docker run --rm -e NVD_API_KEY=your-key -p 3010:3010 nist-nvd-mcp-server
```

The Dockerfile defaults to HTTP transport, stateless session mode, and logs to `/var/log/nist-nvd-mcp-server`. OpenTelemetry peer dependencies are installed by default — build with `--build-arg OTEL_ENABLED=false` to omit them.

## Project structure

| Directory | Purpose |
|:----------|:--------|
| `src/index.ts` | `createApp()` entry point — registers tools/resources and inits services. |
| `src/config` | Server-specific environment variable parsing and validation with Zod. |
| `src/mcp-server/tools` | Tool definitions (`*.tool.ts`). |
| `src/mcp-server/resources` | Resource definitions (`*.resource.ts`). |
| `src/services/nvd-http` | NVD HTTP client with rate-limit pacing and retry. |
| `src/services/nvd-cve` | CVE service — search, fetch-by-ID, CPE audit, change history, normalization. |
| `src/services/nvd-cpe` | CPE service — dictionary search and normalization. |
| `src/services/nvd-source` | Source service — resolves NVD contributor identifiers to their published names. |
| `tests/` | Unit and integration tests mirroring `src/`. |

## Development guide

See [`CLAUDE.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for request-scoped logging, `ctx.state` for tenant-scoped storage
- Register new tools and resources via the barrels in `src/mcp-server/*/definitions/index.ts`
- Wrap external API calls: validate raw → normalize to domain type → return output schema; never fabricate missing fields

## Contributing

Issues are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

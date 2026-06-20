<div align="center">
  <h1>@cyanheads/nist-nvd-mcp-server</h1>
  <p><b>Search and audit CVEs by keyword, severity, CWE, CISA KEV status, and CPE via the NIST National Vulnerability Database. STDIO or Streamable HTTP.</b>
  <div>5 Tools • 1 Resource</div>
  </p>
</div>

<div align="center">

[![Version](https://img.shields.io/badge/Version-0.1.12-blue.svg?style=flat-square)](./CHANGELOG.md) [![License](https://img.shields.io/badge/License-Apache%202.0-orange.svg?style=flat-square)](./LICENSE) [![Docker](https://img.shields.io/badge/Docker-ghcr.io-2496ED?style=flat-square&logo=docker&logoColor=white)](https://github.com/users/cyanheads/packages/container/package/nist-nvd-mcp-server) [![MCP SDK](https://img.shields.io/badge/MCP%20SDK-^1.29.0-green.svg?style=flat-square)](https://modelcontextprotocol.io/) [![npm](https://img.shields.io/npm/v/@cyanheads/nist-nvd-mcp-server?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@cyanheads/nist-nvd-mcp-server) [![TypeScript](https://img.shields.io/badge/TypeScript-^6.0.3-3178C6.svg?style=flat-square)](https://www.typescriptlang.org/) [![Bun](https://img.shields.io/badge/Bun-v1.3.2-blueviolet.svg?style=flat-square)](https://bun.sh/)

</div>

<div align="center">

[![Install in Claude Desktop](https://img.shields.io/badge/Install_in-Claude_Desktop-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://github.com/cyanheads/nist-nvd-mcp-server/releases/latest/download/nist-nvd-mcp-server.mcpb) [![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](https://cursor.com/en/install-mcp?name=nist-nvd-mcp-server&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBjeWFuaGVhZHMvbmlzdC1udmQtbWNwLXNlcnZlciJdfQ==) [![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect?url=vscode:mcp/install?%7B%22name%22%3A%22nist-nvd-mcp-server%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40cyanheads%2Fnist-nvd-mcp-server%22%5D%7D)

[![Framework](https://img.shields.io/badge/Built%20on-@cyanheads/mcp--ts--core-67E8F9?style=flat-square)](https://www.npmjs.com/package/@cyanheads/mcp-ts-core)

</div>

<div align="center">

**Public Hosted Server:** [https://nist-nvd.caseyjhand.com/mcp](https://nist-nvd.caseyjhand.com/mcp)

</div>

---

## Tools

Five tools for vulnerability research, CPE auditing, and change tracking against the NIST NVD API 2.0:

| Tool | Description |
|:-----|:------------|
| `nvd_search_cves` | Search CVEs by keyword, severity, CWE, date range, or CISA KEV status. |
| `nvd_get_cve` | Fetch one or more CVEs by ID — full CVSS scores, CWE, CPE configs, KEV fields, and references. |
| `nvd_search_cpes` | Search the NVD CPE dictionary by product keyword or partial match string. |
| `nvd_audit_cpe` | Find all CVEs affecting a specific product version by CPE name or virtual match string. |
| `nvd_get_cve_history` | Retrieve the change history for a CVE — score revisions, status transitions, and reference additions. |

### `nvd_search_cves`

The primary discovery tool for vulnerability surveillance and triage workflows.

- Full-text keyword search across CVE descriptions (AND-semantics across words)
- Severity filter by CVSS v2/v3/v4 label (LOW, MEDIUM, HIGH, CRITICAL)
- CWE weakness filter (e.g., `CWE-79`, `NVD-CWE-Other`)
- CISA KEV filter — limit results to known-exploited vulnerabilities
- Convenience date shorthands: `pubDays` and `lastModDays` for "last N days" queries
- Explicit ISO 8601 date range parameters (`pubStartDate`/`pubEndDate`, etc.) with 120-day max span
- Auto-clamps convenience date params that exceed 120 days and reports clamped values in `queryMeta`
- Pagination via `limit` (up to 2000) and `offset`
- Results are always brief; call `nvd_get_cve` for full detail

---

### `nvd_get_cve`

Fetch one or more CVEs by ID with full detail or brief summaries.

- Batch up to 100 CVE IDs per call
- Full mode: all CVSS scores across v2.0, v3.0, v3.1, and v4.0; CWE weaknesses; CPE configurations; CISA KEV fields; references
- Brief mode (`brief: true`): ID, status, top severity, KEV name — recommended for batches larger than 10
- `includeReferences: false` to strip the references array and reduce response size
- Per-ID parity check: `queryMeta.missingIds` lists any requested IDs NVD didn't return

---

### `nvd_search_cpes`

Look up product identifiers before auditing.

- Keyword search (e.g., `"apache http server"`, `"openssl"`) or partial CPEv2.3 pattern
- Returns full CPE name, human-readable title, deprecation status, and superseding CPEs
- Pagination up to 10,000 entries — narrow the keyword when `totalResults > returned`
- Use this before `nvd_audit_cpe` — CPE names are arcane strings; guessing audits the wrong product

---

### `nvd_audit_cpe`

Full CVE audit for a specific product version.

- Two modes: exact `cpeName` (NVD auto-applies `isVulnerable`) or `virtualMatchString` with optional version range bounds
- Version range via `versionStart`/`versionEnd` with inclusive/exclusive type control
- Client-side severity filter (`severityMin`) to strip low-signal entries
- Returns full CVE records (ID, CVSS scores, CWE, CPE configurations, KEV fields, references)
- Echoes the CPE identifier used in `queryMeta` so callers can verify the correct product was queried

---

### `nvd_get_cve_history`

Track a CVE's lifecycle over time.

- Returns change events in reverse-chronological order: CVSS revisions, status transitions, reference additions, CPE configuration updates
- Paginated via `limit` and `offset`
- Note: the NVD history endpoint is significantly slower without an API key — set `NVD_API_KEY` and raise `NVD_REQUEST_TIMEOUT_MS` for reliable operation

## Resource

| Type | Name | Description |
|:-----|:-----|:------------|
| Resource | `nvd://cve/{cveId}` | Full CVE record by ID — same data as `nvd_get_cve` for a single ID, as a stable URI for injectable context. |

All resource data is also reachable via tools.

## Features

Built on [`@cyanheads/mcp-ts-core`](https://www.npmjs.com/package/@cyanheads/mcp-ts-core):

- Declarative tool, resource, and prompt definitions — single file per primitive, framework handles registration and validation
- Unified error handling — handlers throw, framework catches, classifies, and formats
- Pluggable auth: `none`, `jwt`, `oauth`
- Swappable storage backends: `in-memory`, `filesystem`, `Supabase`, `Cloudflare KV/R2/D1`
- Structured logging with optional OpenTelemetry tracing
- STDIO and Streamable HTTP transports

NVD-specific:

- Token-bucket rate limiter enforces NVD's 5 req/30s (no key) and 50 req/30s (with key) limits with automatic queuing
- Sliding-window minimum inter-request gap derived from the window and limit — no burst, no 403s
- Automatic retry with backoff via `withRetry`; parses `Retry-After` header on 403 responses
- HTML-response guard catches NVD rate-limit pages served as HTML instead of 403

Agent-friendly output:

- `queryMeta` on every response — total results, returned count, page offset, and any date-clamping events so agents can reason about what was actually queried
- `missingIds` in batch CVE lookups — per-ID parity check instead of a silent partial result
- CPE echo in audit responses — `cpeName` or `virtualMatchString` reflected back so callers can verify the correct product was audited

## Getting started

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

- [Bun v1.3.0](https://bun.sh/) or higher (or Node.js v24+).
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
| `NVD_REQUEST_TIMEOUT_MS` | Per-request timeout in milliseconds. The history endpoint is slow without an API key — raise to 60000 if using `nvd_get_cve_history` without a key. | `10000` |
| `MCP_TRANSPORT_TYPE` | Transport: `stdio` or `http`. | `stdio` |
| `MCP_HTTP_PORT` | Port for HTTP server. | `3010` |
| `MCP_AUTH_MODE` | Auth mode: `none`, `jwt`, or `oauth`. | `none` |
| `MCP_LOG_LEVEL` | Log level (RFC 5424). | `info` |
| `LOGS_DIR` | Directory for log files (Node.js only). | `<project-root>/logs` |
| `OTEL_ENABLED` | Enable [OpenTelemetry instrumentation](https://github.com/cyanheads/mcp-ts-core/tree/main/docs/telemetry). | `false` |

See [`.env.example`](./.env.example) for the full list of optional overrides.

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
| `src/services/nvd-http` | NVD HTTP client with token-bucket rate limiting and retry. |
| `src/services/nvd-cve` | CVE service — search, fetch-by-ID, CPE audit, change history, normalization. |
| `src/services/nvd-cpe` | CPE service — dictionary search and normalization. |
| `tests/` | Unit and integration tests mirroring `src/`. |

## Development guide

See [`CLAUDE.md`](./CLAUDE.md) for development guidelines and architectural rules. The short version:

- Handlers throw, framework catches — no `try/catch` in tool logic
- Use `ctx.log` for request-scoped logging, `ctx.state` for tenant-scoped storage
- Register new tools and resources via the barrels in `src/mcp-server/*/definitions/index.ts`
- Wrap external API calls: validate raw → normalize to domain type → return output schema; never fabricate missing fields

## Contributing

Issues and pull requests are welcome. Run checks and tests before submitting:

```sh
bun run devcheck
bun run test
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

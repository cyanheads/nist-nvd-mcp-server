#!/usr/bin/env node
/**
 * @fileoverview nist-nvd-mcp-server MCP server entry point.
 * Registers NVD tools and resources, initializes HTTP client and domain services.
 * @module index
 */

import { createApp } from '@cyanheads/mcp-ts-core';
import { getServerConfig } from './config/server-config.js';
import { nvdCveResource } from './mcp-server/resources/definitions/index.js';
import {
  nvdAuditCpe,
  nvdGetCve,
  nvdGetCveHistory,
  nvdSearchCpes,
  nvdSearchCves,
} from './mcp-server/tools/definitions/index.js';
import { initNvdCpeService } from './services/nvd-cpe/nvd-cpe-service.js';
import { initNvdCveService } from './services/nvd-cve/nvd-cve-service.js';
import { initNvdHttpClient } from './services/nvd-http/nvd-http-client.js';

await createApp({
  tools: [nvdGetCve, nvdSearchCves, nvdAuditCpe, nvdSearchCpes, nvdGetCveHistory],
  resources: [nvdCveResource],
  prompts: [],
  instructions:
    'This server provides read-only access to the NIST National Vulnerability Database (NVD).\n' +
    '- Use nvd_search_cves to discover CVEs by keyword, severity, CWE, date range, or CISA KEV status.\n' +
    '- Use nvd_get_cve for full CVSS details on specific CVE IDs (up to 100 per call).\n' +
    '- Use nvd_search_cpes to find the correct CPE name for a product before auditing.\n' +
    '- Use nvd_audit_cpe to find all CVEs affecting a specific product version.\n' +
    '- Use nvd_get_cve_history to track when a CVE was re-scored or escalated.\n' +
    '- Rate limit: 5 req/30s without API key, 50 req/30s with NVD_API_KEY.',

  setup(core) {
    const cfg = getServerConfig();
    initNvdHttpClient(cfg.apiKey, cfg.requestTimeoutMs);
    initNvdCveService(core.config, core.storage);
    initNvdCpeService(core.config, core.storage);
  },
});

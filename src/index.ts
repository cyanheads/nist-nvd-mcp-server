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
import { initNvdSourceService } from './services/nvd-source/nvd-source-service.js';

await createApp({
  name: 'nist-nvd-mcp-server',
  title: 'nist-nvd-mcp-server',
  /**
   * Every tool here is a read-only NVD lookup — no handler calls `ctx.requestInput`,
   * so nothing needs a session to come back to. `MCP_SESSION_MODE` still overrides.
   */
  sessionMode: 'stateless',
  tools: [nvdGetCve, nvdSearchCves, nvdAuditCpe, nvdSearchCpes, nvdGetCveHistory],
  resources: [nvdCveResource],
  prompts: [],
  skills: 'skills',
  instructions:
    'Read-only access to the NIST National Vulnerability Database (NVD). Resolve an unknown product CPE with nvd_search_cpes before passing its exact CPEv2.3 name to nvd_audit_cpe; audit results cover NVD records for that target, subject to pagination and analysis completeness. Reuse CVE IDs from search or audit results with nvd_get_cve for current details and nvd_get_cve_history for revisions. Access works without a key at 5 requests per 30 seconds; NVD_API_KEY raises this to 50. Requests share a paced queue.',

  setup(core) {
    const cfg = getServerConfig();
    initNvdHttpClient(cfg.apiKey, cfg.requestTimeoutMs);
    initNvdCveService(core.config, core.storage);
    initNvdCpeService(core.config, core.storage);
    initNvdSourceService(core.config, core.storage);
  },
});

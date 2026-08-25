/**
 * @fileoverview Contract tests for the wire behavior the framework owns on this server's behalf,
 * exercised through `runToolContract` — the same path a real `tools/call` takes, including input
 * parsing, the handler, output parsing, `format()`, and the error envelope.
 *
 * These pin two properties that are invisible to a handler-level test: an argument key the schema
 * does not declare is rejected by name before the handler runs, and that rejection reaches the
 * caller as a tool result rather than a JSON-RPC error — so a client reading `content[]` can see
 * which key it got wrong.
 *
 * @module tests/framework-contract.test
 */

import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdAuditCpe } from '@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js';
import { nvdGetCve } from '@/mcp-server/tools/definitions/nvd-get-cve.tool.js';
import { nvdGetCveHistory } from '@/mcp-server/tools/definitions/nvd-get-cve-history.tool.js';
import { nvdSearchCpes } from '@/mcp-server/tools/definitions/nvd-search-cpes.tool.js';
import { nvdSearchCves } from '@/mcp-server/tools/definitions/nvd-search-cves.tool.js';
import * as nvdCpeServiceModule from '@/services/nvd-cpe/nvd-cpe-service.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import { at } from './support/at.js';

/** Text of the first content block, which is where a rejection names the offending key. */
function firstText(result: { content: Array<{ type: string; text?: unknown }> }): string {
  const block = at(result.content);
  if (block.type !== 'text' || typeof block.text !== 'string') {
    throw new Error(`expected a text content block, got ${block.type}`);
  }
  return block.text;
}

/**
 * Every tool with a valid minimal argument set, and the service call each one would make. The
 * services are stubbed so a rejected call is distinguishable from one that reached the handler.
 */
const cveServiceStub = () => ({
  searchCves: vi.fn().mockResolvedValue({ cves: [], totalResults: 0, returned: 0, offset: 0 }),
  fetchById: vi.fn().mockResolvedValue({ cves: [], returned: 0, requested: 1, missingIds: [] }),
  auditCpe: vi.fn().mockResolvedValue({
    cves: [],
    totalResults: 0,
    returned: 0,
    cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
  }),
  getCveHistory: vi.fn().mockResolvedValue({
    cveId: 'CVE-2021-44228',
    changes: [],
    totalResults: 0,
    returned: 0,
    offset: 0,
  }),
});

const cpeServiceStub = () => ({
  searchCpes: vi.fn().mockResolvedValue({ cpes: [], totalResults: 0, returned: 0, offset: 0 }),
});

describe('tool inputs are strict at the wire boundary', () => {
  let cveService: ReturnType<typeof cveServiceStub>;
  let cpeService: ReturnType<typeof cpeServiceStub>;

  beforeEach(() => {
    cveService = cveServiceStub();
    cpeService = cpeServiceStub();
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(cveService as never);
    vi.spyOn(nvdCpeServiceModule, 'getNvdCpeService').mockReturnValue(cpeService as never);
  });

  /** Each tool with a minimally valid call, and the service method reaching the handler spends. */
  const cases = [
    { definition: nvdSearchCves, valid: { keyword: 'log4j' }, spends: () => cveService.searchCves },
    {
      definition: nvdGetCve,
      valid: { cveIds: ['CVE-2021-44228'] },
      spends: () => cveService.fetchById,
    },
    {
      definition: nvdSearchCpes,
      valid: { keyword: 'apache' },
      spends: () => cpeService.searchCpes,
    },
    {
      definition: nvdAuditCpe,
      valid: { cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*' },
      spends: () => cveService.auditCpe,
    },
    {
      definition: nvdGetCveHistory,
      valid: { cveId: 'CVE-2021-44228' },
      spends: () => cveService.getCveHistory,
    },
  ] as const;

  for (const { definition, valid, spends } of cases) {
    it(`${definition.name} rejects an undeclared argument key by name`, async () => {
      const result = await runToolContract(definition, {
        ...valid,
        notAParameter: 'x',
      } as never);

      expect(result.isError).toBe(true);
      // The caller sees the offending key, so a model can correct the call rather than guess.
      expect(firstText(result as never)).toContain('notAParameter');
      // Rejected before the handler ran — no upstream request was spent on it.
      for (const call of Object.values(cveService)) expect(call).not.toHaveBeenCalled();
      for (const call of Object.values(cpeService)) expect(call).not.toHaveBeenCalled();
    });

    it(`${definition.name} reaches its handler once the undeclared key is dropped`, async () => {
      // Same arguments minus the stray key: the call now gets past input parsing and spends an
      // upstream request, which is what proves the rejection above was the key and nothing else.
      await runToolContract(definition, valid as never);
      expect(spends()).toHaveBeenCalledTimes(1);
    });
  }
});

describe('a rejection is a tool result, not a JSON-RPC error', () => {
  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(cveServiceStub() as never);
  });

  it('carries the failure in structuredContent.error rather than throwing', async () => {
    const result = await runToolContract(nvdSearchCves, {
      keyword: 'log4j',
      notAParameter: 'x',
    } as never);

    // 0.12.0 moved the error envelope into the advertised output schema — a client that parses
    // structuredContent against it must find the failure there, not as a transport-level error.
    expect(result.structuredContent).toMatchObject({
      error: { code: expect.any(Number), message: expect.stringContaining('notAParameter') },
    });
  });

  it('surfaces a declared contract failure the same way', async () => {
    // `missing_search_input` is one of nvd_search_cpes' declared reasons.
    vi.spyOn(nvdCpeServiceModule, 'getNvdCpeService').mockReturnValue(cpeServiceStub() as never);
    const result = await runToolContract(nvdSearchCpes, {} as never);

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'missing_search_input' } },
    });
  });
});

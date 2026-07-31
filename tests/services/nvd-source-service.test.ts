/**
 * @fileoverview Tests for NvdSourceService and the source-name resolution it feeds into
 * `normalizeCve` — GUID resolution, email passthrough, unknown-identifier passthrough,
 * degradation when the dictionary is unavailable, and the caching that keeps it to one
 * upstream request. Fixtures mirror the live `/rest/json/source/2.0` payload.
 * @module tests/services/nvd-source-service.test
 */

import { serviceUnavailable, timeout } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, type MockContextLogger } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import type { RawCveResponse } from '@/services/nvd-cve/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';
import {
  initNvdSourceService,
  NvdSourceService,
} from '@/services/nvd-source/nvd-source-service.js';
import type { RawNvdSourceResponse } from '@/services/nvd-source/types.js';

/** Three real dictionary entries: two GUID-only contributors and one identified by email. */
const SOURCE_RESPONSE: RawNvdSourceResponse = {
  resultsPerPage: 3,
  startIndex: 0,
  totalResults: 3,
  sources: [
    {
      name: 'CVE',
      contactEmail: 'cve-request@mitre.org',
      sourceIdentifiers: ['af854a3a-2127-422b-91ae-364da2661108'],
    },
    {
      name: 'CISA-ADP',
      contactEmail: 'cisa@example.com',
      sourceIdentifiers: ['134c704f-9b21-4f2e-91b3-4a467353bcc0'],
    },
    {
      name: 'Apache Software Foundation',
      contactEmail: 'security@apache.org',
      sourceIdentifiers: ['security@apache.org', 'f0158376-9dc2-43b6-827c-5f631a4d8d09'],
    },
  ],
};

/**
 * The three identifier forms a modern record carries on one CVE, as CVE-2024-23225 does: the
 * CVE Program GUID, the CISA-ADP GUID, and a CNA's email address.
 */
const CVE_RESPONSE: RawCveResponse = {
  totalResults: 1,
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-23225',
        vulnStatus: 'Modified',
        published: '2024-03-05T23:15:00.000',
        lastModified: '2025-11-03T22:16:00.000',
        weaknesses: [
          {
            source: '134c704f-9b21-4f2e-91b3-4a467353bcc0',
            description: [{ lang: 'en', value: 'CWE-787' }],
          },
          { source: 'security@apache.org', description: [{ lang: 'en', value: 'CWE-20' }] },
          {
            source: '00000000-0000-0000-0000-000000000000',
            description: [{ lang: 'en', value: 'CWE-119' }],
          },
        ],
        references: [
          {
            url: 'https://support.apple.com/en-us/HT214081',
            source: 'af854a3a-2127-422b-91ae-364da2661108',
            tags: ['Release Notes'],
          },
          { url: 'https://httpd.apache.org/security/', source: 'security@apache.org' },
          { url: 'https://example.invalid/adv', source: '00000000-0000-0000-0000-000000000000' },
        ],
      },
    },
  ],
};

/** Route the mocked client by endpoint so the dictionary and CVE calls stay distinguishable. */
function makeClient(sourceResult: () => Promise<unknown>) {
  const get = vi.fn(async (endpoint: string) =>
    endpoint === 'source/2.0' ? await sourceResult() : CVE_RESPONSE,
  );
  return {
    get,
    sourceCalls: () => get.mock.calls.filter(([endpoint]) => endpoint === 'source/2.0').length,
  };
}

describe('NvdSourceService — source identifier resolution', () => {
  let client: ReturnType<typeof makeClient>;

  function install(sourceResult: () => Promise<unknown> = async () => SOURCE_RESPONSE) {
    client = makeClient(sourceResult);
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      client as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
  }

  beforeEach(() => {
    // A fresh instance per test — the dictionary cache is per-instance and holds for a day.
    initNvdSourceService({} as never, {} as never);
    install();
  });

  const service = new NvdCveService({} as never, {} as never);

  async function fetchOne() {
    const result = await service.fetchById(
      ['CVE-2024-23225'],
      { includeReferences: true, allLanguages: false },
      createMockContext(),
    );
    return result.cves[0];
  }

  it('resolves a GUID identifier to its published contributor name', async () => {
    const cve = await fetchOne();
    expect(cve.weaknesses[0].source).toBe('CISA-ADP');
    expect(cve.references?.[0].source).toBe('CVE');
  });

  it('leaves an email-form identifier untouched', async () => {
    const cve = await fetchOne();
    // `security@apache.org` is already legible — it must not become "Apache Software Foundation".
    expect(cve.weaknesses[1].source).toBe('security@apache.org');
    expect(cve.references?.[1].source).toBe('security@apache.org');
  });

  it('passes an identifier the dictionary does not carry through as its raw value', async () => {
    const cve = await fetchOne();
    expect(cve.weaknesses[2].source).toBe('00000000-0000-0000-0000-000000000000');
    expect(cve.references?.[2].source).toBe('00000000-0000-0000-0000-000000000000');
  });

  it('degrades to raw identifiers when the dictionary request fails, without failing the call', async () => {
    install(async () => {
      throw serviceUnavailable('NVD API returned HTTP 503.');
    });
    const cve = await fetchOne();

    expect(cve.cveId).toBe('CVE-2024-23225');
    expect(cve.weaknesses[0].source).toBe('134c704f-9b21-4f2e-91b3-4a467353bcc0');
    expect(cve.references?.[0].source).toBe('af854a3a-2127-422b-91ae-364da2661108');
  });

  it('degrades to raw identifiers when the dictionary body is unusable', async () => {
    // HTTP 200 with a body carrying no `sources` — an empty dictionary, not a thrown error.
    install(async () => ({ totalResults: 0 }));
    const cve = await fetchOne();
    expect(cve.weaknesses[0].source).toBe('134c704f-9b21-4f2e-91b3-4a467353bcc0');
  });

  it('fetches the dictionary once across repeated calls', async () => {
    await fetchOne();
    await fetchOne();
    await fetchOne();

    expect(client.sourceCalls()).toBe(1);
  });

  it('does not refetch the dictionary on every call after a failure', async () => {
    install(async () => {
      throw serviceUnavailable('NVD API returned HTTP 503.');
    });
    await fetchOne();
    await fetchOne();

    // A sustained outage must not cost an upstream request per tool call.
    expect(client.sourceCalls()).toBe(1);
  });

  it('shares one in-flight request across concurrent cold-cache callers', async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    install(async () => {
      await gate;
      return SOURCE_RESPONSE;
    });

    const calls = Promise.all([fetchOne(), fetchOne(), fetchOne()]);
    release?.();
    const cves = await calls;

    expect(client.sourceCalls()).toBe(1);
    for (const cve of cves) expect(cve.weaknesses[0].source).toBe('CISA-ADP');
  });

  it('does not fetch the dictionary for a search, whose brief rows carry no source field', async () => {
    await service.searchCves({ keyword: 'apple' }, createMockContext());
    expect(client.sourceCalls()).toBe(0);
  });

  it('does not fetch the dictionary for an audit that returned no CVEs', async () => {
    client.get.mockImplementation(async (endpoint: string) =>
      endpoint === 'source/2.0' ? SOURCE_RESPONSE : { totalResults: 0, vulnerabilities: [] },
    );
    const result = await service.auditCpe(
      { virtualMatchString: 'cpe:2.3:a:nonexistent:product:*' },
      createMockContext(),
    );

    expect(result.cves).toHaveLength(0);
    expect(client.sourceCalls()).toBe(0);
  });

  it('resolves identifiers on the audit surface too', async () => {
    const result = await service.auditCpe(
      { cpeName: 'cpe:2.3:a:apple:macos:14.3:*:*:*:*:*:*:*' },
      createMockContext(),
    );

    expect(result.cves[0].weaknesses[0].source).toBe('CISA-ADP');
    expect(result.cves[0].references?.[0].source).toBe('CVE');
  });

  it('requests the dictionary within the endpoint page-size ceiling', async () => {
    await new NvdSourceService({} as never, {} as never).getResolver(createMockContext());

    const call = client.get.mock.calls.find(([endpoint]) => endpoint === 'source/2.0');
    expect(call).toBeDefined();
    const params = call?.[1] as Record<string, unknown>;
    // `source/2.0` answers a resultsPerPage above 1000 with the same HTTP 404 it uses to reject
    // any other bad parameter, so the request must stay at or under it.
    expect(Number(params.resultsPerPage)).toBeLessThanOrEqual(1000);
  });

  it('spends less effort on the dictionary than on the record it decorates', async () => {
    await new NvdSourceService({} as never, {} as never).getResolver(createMockContext());

    const call = client.get.mock.calls.find(([endpoint]) => endpoint === 'source/2.0');
    const budget = call?.[3] as { maxRetries?: number; timeoutMs?: number } | undefined;
    /**
     * The load sits inside the calling tool and shares one pacing queue with the CVE requests, so
     * an unreachable endpoint must cost a single short wait — not attempts × timeout × backoff.
     */
    expect(budget?.maxRetries).toBe(0);
    expect(budget?.timeoutMs).toBeLessThanOrEqual(3_000);
  });

  it('warns and resolves the rest raw when the dictionary page is truncated', async () => {
    // One page short of what NVD reports it holds — the shape a >1000-contributor dictionary takes.
    install(async () => ({ ...SOURCE_RESPONSE, totalResults: 1_200 }));
    const ctx = createMockContext();
    const resolve = await new NvdSourceService({} as never, {} as never).getResolver(ctx);

    const warning = (ctx.log as MockContextLogger).calls.find((c) => c.level === 'warning');
    expect(warning?.msg).toContain('incomplete');
    expect(warning?.data).toMatchObject({ returned: 3, totalResults: 1_200 });
    // Entries on the page still resolve; everything past it degrades to the raw identifier.
    expect(resolve('af854a3a-2127-422b-91ae-364da2661108')).toBe('CVE');
    expect(resolve('0253b833-3e77-4dfe-9d57-17db1a2f0a74')).toBe(
      '0253b833-3e77-4dfe-9d57-17db1a2f0a74',
    );
  });

  it('does not remember a caller-cancelled load as an outage', async () => {
    const controller = new AbortController();
    install(async () => {
      controller.abort();
      throw timeout('NVD request cancelled by caller.');
    });
    const service = new NvdSourceService({} as never, {} as never);

    await service.getResolver(createMockContext({ signal: controller.signal }));
    // A caller walking away says nothing about NVD's health, so the next call retries rather than
    // serving raw identifiers for the whole failure window.
    install();
    const resolve = await service.getResolver(createMockContext());
    expect(resolve('af854a3a-2127-422b-91ae-364da2661108')).toBe('CVE');
  });

  it('does not fetch the dictionary for a brief fetch, whose rows drop the source field', async () => {
    await service.fetchById(
      ['CVE-2024-23225'],
      { includeReferences: false, allLanguages: false, resolveSources: false },
      createMockContext(),
    );

    expect(client.sourceCalls()).toBe(0);
  });
});

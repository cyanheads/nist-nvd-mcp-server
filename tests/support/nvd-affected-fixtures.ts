/**
 * @fileoverview Raw NVD CVE items trimmed from real `cves/2.0` captures, for the CNA/ADP affected
 * products, record tags, record source, and per-score CVSS source. Each keeps NVD's own key
 * names and nesting; only fields no assertion reads were cut. `nvdFake()` serves them, and a
 * trimmed contributor dictionary, from one mocked `get` that records every endpoint it was asked
 * for, so a test can count source-dictionary requests.
 * @module tests/support/nvd-affected-fixtures
 */

import { vi } from 'vitest';
import type { RawCveItem } from '@/services/nvd-cve/types.js';

export const CPANSEC = '9b29abf9-4ab0-4765-b253-1875cd9b441e';
export const CISA_ADP = '134c704f-9b21-4f2e-91b3-4a467353bcc0';

/** Deferred, no configurations: the CNA's package entry is its only structured product evidence. */
export const CVE_2026_115946: RawCveItem = {
  id: 'CVE-2026-115946',
  sourceIdentifier: CPANSEC,
  published: '2026-11-01T00:16:34.437',
  lastModified: '2026-11-09T17:17:12.067',
  vulnStatus: 'Deferred',
  cveTags: [],
  descriptions: [
    {
      lang: 'en',
      value:
        'XS::libbrotli versions before 1.2.1.0 for Perl bundle a brotli library with an out-of-bounds write in the decoder.',
    },
  ],
  metrics: {
    cvssMetricV31: [
      {
        source: CISA_ADP,
        type: 'Secondary',
        cvssData: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          baseScore: 9.8,
          baseSeverity: 'CRITICAL',
        },
      },
    ],
  },
  affected: [
    {
      source: CPANSEC,
      affectedData: [
        {
          defaultStatus: 'unaffected',
          collectionURL: 'https://cpan.org/modules',
          packageName: 'XS-libbrotli',
          modules: ['XS::libbrotli'],
          programFiles: ['brotli/c/dec/decode.c'],
          packageURL: 'pkg:cpan/XS-libbrotli',
          versions: [
            { version: '0', lessThan: '1.2.1.0', versionType: 'custom', status: 'affected' },
          ],
        },
      ],
    },
  ],
};

/** One "affected" range with five status changes inside it — the fixed points must stay fixed. */
export const CVE_2021_44228: RawCveItem = {
  id: 'CVE-2021-44228',
  sourceIdentifier: 'security@apache.org',
  published: '2021-12-10T10:15:09.143',
  lastModified: '2026-08-11T19:33:44.513',
  vulnStatus: 'Analyzed',
  cveTags: [],
  affected: [
    {
      source: 'security@apache.org',
      affectedData: [
        {
          vendor: 'Apache Software Foundation',
          product: 'Apache Log4j2',
          versions: [
            {
              version: '2.0-beta9',
              lessThan: 'log4j-core*',
              versionType: 'custom',
              status: 'affected',
              changes: [
                { at: '2.3.1', status: 'unaffected' },
                { at: '2.4', status: 'affected' },
                { at: '2.12.2', status: 'unaffected' },
                { at: '2.13.0', status: 'affected' },
                { at: '2.15.0', status: 'unaffected' },
              ],
            },
          ],
        },
      ],
    },
  ],
};

/** Two source groups — Apple's own statement and CISA-ADP's — trimmed to two products each. */
export const CVE_2024_23225: RawCveItem = {
  id: 'CVE-2024-23225',
  sourceIdentifier: 'product-security@apple.com',
  published: '2024-03-05T20:16:01.370',
  lastModified: '2026-06-17T07:12:20.443',
  vulnStatus: 'Analyzed',
  cveTags: [],
  affected: [
    {
      source: 'product-security@apple.com',
      affectedData: [
        {
          vendor: 'Apple',
          product: 'iOS and iPadOS',
          versions: [
            { version: '0', lessThan: '16.7.6', versionType: 'custom', status: 'affected' },
            { version: '0', lessThan: '17.4', versionType: 'custom', status: 'affected' },
          ],
        },
        {
          vendor: 'Apple',
          product: 'macOS',
          versions: [
            { version: '0', lessThan: '12.7.4', versionType: 'custom', status: 'affected' },
          ],
        },
      ],
    },
    {
      source: CISA_ADP,
      affectedData: [
        {
          vendor: 'apple',
          product: 'ipad_os',
          defaultStatus: 'unknown',
          cpes: ['cpe:2.3:o:apple:ipad_os:17.0:*:*:*:*:*:*:*'],
          versions: [
            { version: '17.0', lessThan: '17.4', versionType: 'custom', status: 'affected' },
          ],
        },
        {
          vendor: 'apple',
          product: 'macos',
          defaultStatus: 'unknown',
          cpes: ['cpe:2.3:o:apple:macos:12.0.0:*:*:*:*:*:*:*'],
          versions: [
            { version: '12.0.0', lessThan: '12.7.4', versionType: 'custom', status: 'affected' },
          ],
        },
      ],
    },
  ],
};

/** Disputed by MITRE, with MITRE's `n/a` placeholder product carried as sent. */
export const CVE_2021_3007: RawCveItem = {
  id: 'CVE-2021-3007',
  sourceIdentifier: 'cve@mitre.org',
  published: '2021-01-04T03:15:13.527',
  lastModified: '2026-06-17T04:04:33.270',
  vulnStatus: 'Modified',
  cveTags: [{ sourceIdentifier: 'cve@mitre.org', tags: ['disputed'] }],
  affected: [
    {
      source: 'cve@mitre.org',
      affectedData: [
        { vendor: 'n/a', product: 'n/a', versions: [{ version: 'n/a', status: 'affected' }] },
      ],
    },
  ],
};

/** NVD's Primary v3.1 beside CISA-ADP's Secondary v3.1. */
export const CVE_2023_4863: RawCveItem = {
  id: 'CVE-2023-4863',
  sourceIdentifier: 'chrome-cve-admin@google.com',
  published: '2023-09-12T15:15:24.327',
  lastModified: '2026-06-17T06:38:46.547',
  vulnStatus: 'Analyzed',
  metrics: {
    cvssMetricV31: [
      {
        source: 'nvd@nist.gov',
        type: 'Primary',
        cvssData: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
          baseScore: 8.8,
          baseSeverity: 'HIGH',
        },
      },
      {
        source: CISA_ADP,
        type: 'Secondary',
        cvssData: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
          baseScore: 8.8,
          baseSeverity: 'HIGH',
        },
      },
    ],
  },
  affected: [
    {
      source: 'chrome-cve-admin@google.com',
      affectedData: [
        {
          vendor: 'Google',
          product: 'Chrome',
          versions: [
            {
              version: '116.0.5845.187',
              lessThan: '116.0.5845.187',
              versionType: 'custom',
              status: 'affected',
            },
          ],
        },
        {
          vendor: 'Google',
          product: 'libwebp',
          versions: [
            { version: '1.3.2', lessThan: '1.3.2', versionType: 'custom', status: 'affected' },
          ],
        },
      ],
    },
  ],
};

/** Rejected by its CNA: NVD sends such a record with no `affected` block at all. */
export const CVE_2026_67186: RawCveItem = {
  id: 'CVE-2026-67186',
  sourceIdentifier: 'disclosure@vulncheck.com',
  published: '2026-11-02T19:18:10.073',
  lastModified: '2026-11-09T20:10:00.200',
  vulnStatus: 'Rejected',
  cveTags: [],
};

/** A CNA's own score labelled Primary — "Primary" is not "NVD". */
export const CVE_2026_77881: RawCveItem = {
  id: 'CVE-2026-77881',
  sourceIdentifier: 'disclosure@vulncheck.com',
  published: '2026-11-02T16:17:44.137',
  lastModified: '2026-11-03T17:18:16.367',
  vulnStatus: 'Deferred',
  cveTags: [],
  metrics: {
    cvssMetricV40: [
      {
        source: 'disclosure@vulncheck.com',
        type: 'Secondary',
        cvssData: { version: '4.0', baseScore: 6.8, baseSeverity: 'MEDIUM' },
      },
    ],
    cvssMetricV31: [
      {
        source: 'disclosure@vulncheck.com',
        type: 'Primary',
        cvssData: {
          version: '3.1',
          vectorString: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
          baseScore: 5.5,
          baseSeverity: 'MEDIUM',
        },
      },
    ],
  },
};

const ALTIUM = '4760f414-e1ae-4ff1-bdad-c7a9c3538b79';

/** A CNA known to NVD only by GUID, tagging its own record: the tag's source resolves too. */
export const CVE_2026_123184: RawCveItem = {
  id: 'CVE-2026-123184',
  sourceIdentifier: ALTIUM,
  published: '2026-11-05T18:17:08.000',
  lastModified: '2026-11-12T19:26:10.547',
  vulnStatus: 'Awaiting Analysis',
  cveTags: [{ sourceIdentifier: ALTIUM, tags: ['exclusively-hosted-service'] }],
};

/** Trimmed from `source/2.0`: the contributors the fixtures above name by GUID. */
export const SOURCE_DICTIONARY = {
  totalResults: 4,
  sources: [
    { name: 'CPANSec', sourceIdentifiers: [CPANSEC] },
    { name: 'CISA-ADP', sourceIdentifiers: [CISA_ADP] },
    { name: 'Altium', sourceIdentifiers: [ALTIUM] },
    {
      name: 'Apple Inc.',
      sourceIdentifiers: ['product-security@apple.com', '286789f9-fbc2-4510-9f9a-43facdede74c'],
    },
  ],
};

/**
 * A mocked NVD `get`: `source/2.0` answers the dictionary, a `cveIds` lookup answers the named
 * items it holds, and any other query answers one page holding every item. `endpoints()` lists
 * the endpoint of every call made so far.
 */
export function nvdFake(items: RawCveItem[]) {
  const get = vi.fn(async (endpoint: string, params?: Record<string, unknown>) => {
    if (endpoint === 'source/2.0') return SOURCE_DICTIONARY;
    const ids = typeof params?.cveIds === 'string' ? params.cveIds.split(',') : undefined;
    const page = ids ? items.filter((item) => ids.includes(item.id)) : items;
    return { totalResults: page.length, vulnerabilities: page.map((cve) => ({ cve })) };
  });
  return { get, endpoints: () => get.mock.calls.map((call) => call[0]) };
}

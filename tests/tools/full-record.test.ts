/**
 * @fileoverview Tests for the shared full-record renderers: the CNA/ADP affected-product section,
 * the status-line source and tags, and the CVSS score line. Both full-record tools call these, so
 * the rendering table is pinned once here; the tool suites prove only the wiring.
 * @module tests/tools/full-record.test
 */

import { escapeMarkdownInline } from '@cyanheads/mcp-ts-core/utils';
import { describe, expect, it } from 'vitest';
import {
  formatAffectedProducts,
  formatCvssScore,
  formatRecordSource,
} from '@/mcp-server/tools/formatting/full-record.js';
import type { AffectedProduct } from '@/services/nvd-cve/types.js';
import { at } from '../support/at.js';

/** The product and version lines only, without the section header. */
const body = (products: AffectedProduct[]) => formatAffectedProducts(products).slice(1);

describe('formatAffectedProducts', () => {
  it('renders nothing, not even a header, for a record with no statements', () => {
    expect(formatAffectedProducts([])).toEqual([]);
  });

  it('counts products in the header, set off from the section above', () => {
    expect(at(formatAffectedProducts([{ product: 'a' }, { product: 'b' }]))).toBe(
      '\n**Affected Products (CNA/ADP):** 2 product(s)',
    );
  });

  it.each<[string, AffectedProduct, string]>([
    ['vendor and product', { vendor: 'Apple', product: 'macOS' }, '  - Apple / macOS'],
    ['product alone', { product: 'macOS' }, '  - macOS'],
    ['source first', { source: 'CISA-ADP', product: 'macos' }, '  - [CISA-ADP] macos'],
    [
      'every scalar facet, labeled by field',
      {
        packageName: 'pkg',
        collectionURL: 'https://cpan.org/modules',
        packageURL: 'pkg:cpan/pkg',
        repo: 'https://github.com/o/r',
        defaultStatus: 'unaffected',
      },
      '  - packageName: pkg · collectionURL: https://cpan.org/modules · packageURL: pkg:cpan/pkg · repo: https://github.com/o/r · defaultStatus: unaffected',
    ],
    ['a named product with facets', { product: 'p', repo: 'r' }, '  - p · repo: r'],
    ['nothing that names it', {}, '  - product not named'],
  ])('heads a product line with %s', (_case, product, line) => {
    expect(body([product])).toEqual([line]);
  });

  it('puts each list field and the routine names on their own lines', () => {
    expect(
      body([
        {
          product: 'p',
          cpes: ['cpe:2.3:a:v:p:1:*:*:*:*:*:*:*'],
          modules: ['m1', 'm2'],
          programFiles: ['src/a.c'],
          platforms: ['iOS'],
          programRoutines: [{ name: 'parse' }, { name: 'free' }],
        },
      ]),
    ).toEqual([
      '  - p',
      `    - cpes: ${escapeMarkdownInline('cpe:2.3:a:v:p:1:*:*:*:*:*:*:*')}`,
      '    - modules: m1, m2',
      '    - programFiles: src/a.c',
      '    - platforms: iOS',
      '    - programRoutines: parse, free',
    ]);
  });

  it.each<[string, NonNullable<AffectedProduct['versions']>[number], string]>([
    ['a single version', { version: '2.4.1', status: 'affected' }, '2.4.1: affected'],
    [
      'an exclusive range',
      { version: '0', lessThan: '1.2.1.0', versionType: 'custom', status: 'affected' },
      '>= 0 < 1.2.1.0 (custom): affected',
    ],
    [
      'an inclusive range',
      { version: '1.0', lessThanOrEqual: '1.4', versionType: 'semver', status: 'affected' },
      '>= 1.0 <= 1.4 (semver): affected',
    ],
    [
      'both upper bounds, as sent',
      { version: '1', lessThan: '3', lessThanOrEqual: '2', status: 'affected' },
      '>= 1 < 3 <= 2: affected',
    ],
    ['an upper bound alone', { lessThan: '5', status: 'affected' }, '< 5: affected'],
    ['no status', { version: '1.0' }, '1.0: status not stated'],
    ['nothing at all', {}, 'version not stated: status not stated'],
  ])('renders %s without filling in what was not sent', (_case, version, line) => {
    expect(body([{ product: 'p', versions: [version] }])).toEqual(['  - p', `    - ${line}`]);
  });

  it('nests each status change under the range it belongs to, in order', () => {
    expect(
      body([
        {
          product: 'p',
          versions: [
            { version: '1.0', lessThan: '2.0', versionType: 'semver', status: 'affected' },
            { version: '3.0', lessThan: '4.0', versionType: 'semver', status: 'affected' },
          ],
          versionChanges: [
            { versionIndex: 1, at: '3.5', status: 'unaffected' },
            { versionIndex: 0, at: '1.5', status: 'unaffected' },
            { versionIndex: 1, at: '3.7', status: 'affected' },
          ],
        },
      ]),
    ).toEqual([
      '  - p',
      '    - >= 1.0 < 2.0 (semver): affected',
      '      - from 1.5: unaffected',
      '    - >= 3.0 < 4.0 (semver): affected',
      '      - from 3.5: unaffected',
      '      - from 3.7: affected',
    ]);
  });

  it('still shows a change whose index names no listed range', () => {
    expect(
      body([
        {
          product: 'p',
          versions: [{ version: '1.0', status: 'affected' }],
          versionChanges: [{ versionIndex: 4, at: '1.5', status: 'unaffected' }],
        },
      ]),
    ).toEqual([
      '  - p',
      '    - 1.0: affected',
      '    - change in unlisted range 4: from 1.5: unaffected',
    ]);
  });

  it('escapes every contributor string and keeps it on its own line', () => {
    const hostile = '**x**\n## CVE-2099-00000';
    const lines = body([
      {
        source: hostile,
        vendor: hostile,
        product: hostile,
        modules: [hostile],
        versions: [
          {
            version: hostile,
            lessThan: hostile,
            lessThanOrEqual: hostile,
            versionType: hostile,
            status: hostile,
          },
        ],
        versionChanges: [{ versionIndex: 0, at: hostile, status: hostile }],
      },
    ]);
    const escaped = escapeMarkdownInline(hostile);
    expect(lines).toEqual([
      `  - [${escaped}] ${escaped} / ${escaped}`,
      `    - modules: ${escaped}`,
      `    - >= ${escaped} < ${escaped} <= ${escaped} (${escaped}): ${escaped}`,
      `      - from ${escaped}: ${escaped}`,
    ]);
    for (const line of lines.join('\n').split('\n')) expect(line).not.toMatch(/^#/);
  });
});

describe('formatRecordSource', () => {
  it('adds nothing for a row with neither field', () => {
    expect(formatRecordSource({})).toBe('');
  });

  it('names the record source', () => {
    expect(formatRecordSource({ sourceIdentifier: 'CPANSec' })).toBe(' | **Source:** CPANSec');
  });

  it('lists each contributor’s tags, led by the contributor when NVD names one', () => {
    expect(
      formatRecordSource({
        sourceIdentifier: 'cve@mitre.org',
        cveTags: [
          { source: 'cve@mitre.org', tags: ['disputed'] },
          { tags: ['unsupported-when-assigned', 'exclusively-hosted-service'] },
        ],
      }),
    ).toBe(
      ' | **Source:** cve@mitre.org | **CVE Tags:** [cve@mitre.org] disputed; unsupported-when-assigned, exclusively-hosted-service',
    );
  });

  it('adds no tag segment for an empty tag list', () => {
    expect(formatRecordSource({ cveTags: [] })).toBe('');
  });
});

describe('formatCvssScore', () => {
  const score = { version: '3.1', sourceType: 'Secondary', baseScore: 9.8, severity: 'CRITICAL' };

  it('keeps the line a score without a source always had', () => {
    expect(formatCvssScore({ ...score, vectorString: 'CVSS:3.1/AV:N' })).toBe(
      'v3.1 (Secondary): 9.8 CRITICAL — CVSS:3.1/AV:N',
    );
  });

  it('names the scorer beside the Primary/Secondary label', () => {
    expect(formatCvssScore({ ...score, source: 'CISA-ADP' })).toBe(
      'v3.1 (Secondary) [CISA-ADP]: 9.8 CRITICAL',
    );
  });

  it('renders a 0.0 score rather than dropping it', () => {
    expect(formatCvssScore({ ...score, baseScore: 0, severity: 'LOW' })).toBe(
      'v3.1 (Secondary): 0 LOW',
    );
  });
});

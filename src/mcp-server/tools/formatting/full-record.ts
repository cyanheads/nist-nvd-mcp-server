/**
 * @fileoverview Shared renderers for the full-record sections that carry a contributor's own
 * statement — the CNA/ADP affected products, the record's source and tags, and each CVSS score's
 * scorer. Used by every tool that prints full CVE records, so the sections read identically.
 * @module src/mcp-server/tools/formatting/full-record
 */

import type { z } from '@cyanheads/mcp-ts-core';
import { escapeMarkdownInline } from '@cyanheads/mcp-ts-core/utils';
import type { CveRecordSchema } from '@/mcp-server/tools/schemas/full-cve.js';

type FullCve = z.infer<typeof CveRecordSchema>;
type AffectedProduct = FullCve['affectedProducts'][number];
type AffectedVersion = NonNullable<AffectedProduct['versions']>[number];

/** The `[source]` prefix both the affected-product lines and the tag segments lead with. */
function sourceTag(source: string | undefined): string {
  return source === undefined ? '' : `[${escapeMarkdownInline(source)}] `;
}

/**
 * The status-line segments for the record's source and tags, appended after the dates. Empty for
 * brief rows, which carry neither.
 */
export function formatRecordSource(cve: Pick<FullCve, 'sourceIdentifier' | 'cveTags'>): string {
  const source =
    cve.sourceIdentifier === undefined
      ? ''
      : ` | **Source:** ${escapeMarkdownInline(cve.sourceIdentifier)}`;
  const tags = cve.cveTags?.length
    ? ` | **CVE Tags:** ${cve.cveTags
        .map((t) => `${sourceTag(t.source)}${t.tags.map(escapeMarkdownInline).join(', ')}`)
        .join('; ')}`
    : '';
  return source + tags;
}

/** One CVSS score's line body: version, NVD's label, its scorer when named, score, and vector. */
export function formatCvssScore(score: FullCve['cvssScores'][number]): string {
  return (
    `v${escapeMarkdownInline(score.version)} (${escapeMarkdownInline(score.sourceType)})` +
    (score.source === undefined ? '' : ` [${escapeMarkdownInline(score.source)}]`) +
    `: ${score.baseScore} ${escapeMarkdownInline(score.severity)}` +
    (score.vectorString ? ` — ${escapeMarkdownInline(score.vectorString)}` : '')
  );
}

/**
 * One version entry: a single version, or a range as `>= version < lessThan` (or `<= lessThanOrEqual`)
 * with its scheme, then its status. A part the contributor left out is left out here too.
 */
function formatVersion(v: AffectedVersion): string {
  const upper = [
    v.lessThan !== undefined && `< ${escapeMarkdownInline(v.lessThan)}`,
    v.lessThanOrEqual !== undefined && `<= ${escapeMarkdownInline(v.lessThanOrEqual)}`,
  ].filter(Boolean);
  const version = v.version === undefined ? undefined : escapeMarkdownInline(v.version);
  const span =
    upper.length > 0 ? [version && `>= ${version}`, ...upper].filter(Boolean).join(' ') : version;
  return (
    `${span ?? 'version not stated'}` +
    (v.versionType === undefined ? '' : ` (${escapeMarkdownInline(v.versionType)})`) +
    `: ${v.status === undefined ? 'status not stated' : escapeMarkdownInline(v.status)}`
  );
}

/** One status change inside a range: the status that holds from `at` on. */
function formatChange(change: NonNullable<AffectedProduct['versionChanges']>[number]): string {
  return `from ${escapeMarkdownInline(change.at)}: ${escapeMarkdownInline(change.status)}`;
}

/** The labeled list fields of a product, each on its own line. */
const LIST_FIELDS = ['cpes', 'modules', 'programFiles', 'platforms'] as const;

/**
 * Render the CNA/ADP affected-product statements: one line per product led by its source, a line
 * per list field, a line per version, and each status change indented under the range it sits in
 * — so a fixed point inside an "affected" range never reads as affected. Empty when the record
 * carries none, matching the configurations section.
 */
export function formatAffectedProducts(products: AffectedProduct[]): string[] {
  if (products.length === 0) return [];
  const lines = [`\n**Affected Products (CNA/ADP):** ${products.length} product(s)`];
  for (const p of products) {
    const name = [p.vendor, p.product]
      .filter((part) => part !== undefined)
      .map(escapeMarkdownInline)
      .join(' / ');
    const facets = (
      [
        ['packageName', p.packageName],
        ['collectionURL', p.collectionURL],
        ['packageURL', p.packageURL],
        ['repo', p.repo],
        ['defaultStatus', p.defaultStatus],
      ] as const
    )
      .filter(([, value]) => value !== undefined)
      .map(([label, value]) => `${label}: ${escapeMarkdownInline(value as string)}`);
    const head = [name, ...facets].filter((part) => part !== '').join(' · ');
    lines.push(`  - ${sourceTag(p.source)}${head || 'product not named'}`);

    for (const field of LIST_FIELDS) {
      const values = p[field];
      if (values) lines.push(`    - ${field}: ${values.map(escapeMarkdownInline).join(', ')}`);
    }
    if (p.programRoutines) {
      lines.push(
        `    - programRoutines: ${p.programRoutines.map((r) => escapeMarkdownInline(r.name)).join(', ')}`,
      );
    }
    const versions = p.versions ?? [];
    const changes = p.versionChanges ?? [];
    for (const [index, version] of versions.entries()) {
      lines.push(`    - ${formatVersion(version)}`);
      for (const change of changes) {
        if (change.versionIndex === index) lines.push(`      - ${formatChange(change)}`);
      }
    }
    // The normalizer never emits one, but a change naming no listed range must still be shown.
    for (const change of changes) {
      if (change.versionIndex < 0 || change.versionIndex >= versions.length) {
        lines.push(
          `    - change in unlisted range ${change.versionIndex}: ${formatChange(change)}`,
        );
      }
    }
  }
  return lines;
}

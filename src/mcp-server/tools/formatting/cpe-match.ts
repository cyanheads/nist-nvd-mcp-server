/**
 * @fileoverview Shared renderer for a CVE's CPE match criteria, used by every tool that prints
 * affected-product configurations. Kept out of the definition files so the two consumers render
 * criteria identically instead of drifting into separate idioms.
 * @module src/mcp-server/tools/formatting/cpe-match
 */

/**
 * One CPE match criterion as it appears on a normalized CVE record's
 * `configurations[].nodes[].cpeMatch[]`.
 */
export interface CpeMatch {
  criteria: string;
  versionEndExcluding?: string | undefined;
  versionEndIncluding?: string | undefined;
  versionStartExcluding?: string | undefined;
  versionStartIncluding?: string | undefined;
  vulnerable: boolean;
}

/** One configuration group as it appears on a normalized CVE record's `configurations[]`. */
export interface CpeConfiguration {
  nodes: Array<{ operator?: string | undefined; cpeMatch: CpeMatch[] }>;
  operator?: string | undefined;
}

/**
 * Cap on CPE match criteria rendered per CVE. A dense record carries hundreds of criteria at
 * roughly 72 bytes a line — CVE-2021-44228 alone has 396, ~27.8KB rendered in full — and both
 * consumers return many records in one call, so the uncapped set would dominate the response.
 * Callers render this many and disclose the remainder.
 */
export const CPE_MATCH_CAP = 5;

/**
 * Render one CPE match as a single line: the criteria string, its version bounds, and the
 * operators that govern it. `nodeOperator` combines the matches inside a node; `groupOperator`
 * combines sibling nodes in the group, so an `AND` there marks conditions that hold together
 * (e.g. a firmware match and the hardware it runs on) rather than independent alternatives.
 */
export function formatCpeMatch(
  match: CpeMatch,
  groupOperator: string | undefined,
  nodeOperator: string | undefined,
): string {
  const bounds = [
    match.versionStartIncluding && `>= ${match.versionStartIncluding}`,
    match.versionStartExcluding && `> ${match.versionStartExcluding}`,
    match.versionEndIncluding && `<= ${match.versionEndIncluding}`,
    match.versionEndExcluding && `< ${match.versionEndExcluding}`,
  ].filter(Boolean);
  const notes = [
    nodeOperator,
    groupOperator && `${groupOperator} with sibling nodes`,
    match.vulnerable ? undefined : 'not the vulnerable component',
  ].filter(Boolean);
  return (
    `${match.criteria}` +
    (bounds.length > 0 ? ` (${bounds.join(', ')})` : '') +
    (notes.length > 0 ? ` [${notes.join('; ')}]` : '')
  );
}

/**
 * Flatten a record's configuration groups into rendered match lines, preserving the group and
 * node operators that qualify each criterion.
 */
export function flattenCpeMatches(configurations: CpeConfiguration[]): string[] {
  return configurations.flatMap((cfg) =>
    cfg.nodes.flatMap((node) =>
      node.cpeMatch.map((m) => formatCpeMatch(m, cfg.operator, node.operator)),
    ),
  );
}

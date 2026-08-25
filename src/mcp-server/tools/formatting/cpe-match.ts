/**
 * @fileoverview Shared renderer for a CVE's CPE match criteria, used by every tool that prints
 * affected-product configurations. Kept out of the definition files so the two consumers render
 * criteria identically instead of drifting into separate idioms.
 * @module src/mcp-server/tools/formatting/cpe-match
 */

/**
 * One CPE match criterion as it appears on a normalized CVE record's
 * `configurationNodes[].cpeMatch[]`.
 */
export interface CpeMatch {
  criteria: string;
  versionEndExcluding?: string | undefined;
  versionEndIncluding?: string | undefined;
  versionStartExcluding?: string | undefined;
  versionStartIncluding?: string | undefined;
  vulnerable: boolean;
}

/** One configuration node as it appears on a normalized CVE record's `configurationNodes[]`. */
export interface CpeConfigurationNode {
  cpeMatch: CpeMatch[];
  /** Index of the NVD configuration group this node came from; siblings share it. */
  groupIndex: number;
  /** Combines this node with its sibling nodes in the same group. */
  groupOperator?: string | undefined;
  /** Combines this node's own criteria. */
  nodeOperator?: string | undefined;
}

/**
 * Cap on CPE match criteria rendered per CVE. A dense record carries hundreds of criteria at
 * roughly 72 bytes a line — CVE-2021-44228 alone has 396, ~27.8KB rendered in full — and both
 * consumers return many records in one call, so the uncapped set would dominate the response.
 * Callers render this many and disclose the remainder.
 */
export const CPE_MATCH_CAP = 5;

/**
 * Render one CPE match as a single line: the criteria string, its version bounds, whether it is
 * the vulnerable component, and the logic that governs it. The two operators mean different
 * things — `nodeOperator` combines the criteria inside `node`, while `groupOperator` combines
 * `node` with its sibling nodes, so an `AND` there marks conditions that hold together (e.g. a
 * firmware node and the hardware it runs on) rather than independent alternatives. The group
 * index names which siblings those are.
 */
export function formatCpeMatch(match: CpeMatch, node: CpeConfigurationNode): string {
  const bounds = [
    match.versionStartIncluding && `>= ${match.versionStartIncluding}`,
    match.versionStartExcluding && `> ${match.versionStartExcluding}`,
    match.versionEndIncluding && `<= ${match.versionEndIncluding}`,
    match.versionEndExcluding && `< ${match.versionEndExcluding}`,
  ].filter(Boolean);
  const notes = [
    `group ${node.groupIndex}`,
    node.groupOperator && `${node.groupOperator} with sibling nodes`,
    node.nodeOperator && `${node.nodeOperator} within node`,
    match.vulnerable ? 'vulnerable component' : 'not the vulnerable component',
  ].filter(Boolean);
  return (
    `${match.criteria}` +
    (bounds.length > 0 ? ` (${bounds.join(', ')})` : '') +
    ` [${notes.join('; ')}]`
  );
}

/**
 * Flatten a record's configuration nodes into rendered match lines, preserving upstream order and
 * qualifying each criterion with the node and group it belongs to.
 */
export function flattenCpeMatches(nodes: CpeConfigurationNode[]): string[] {
  return nodes.flatMap((node) => node.cpeMatch.map((m) => formatCpeMatch(m, node)));
}

/**
 * The counts behind a record's `**Configurations:**` line. Groups are counted by distinct
 * `groupIndex` rather than by node, since hoisting the group level away leaves several nodes
 * pointing at the same group.
 */
export function summarizeCpeNodes(nodes: CpeConfigurationNode[]): string {
  const groups = new Set(nodes.map((node) => node.groupIndex)).size;
  const matches = nodes.reduce((total, node) => total + node.cpeMatch.length, 0);
  return `${groups} configuration group(s), ${nodes.length} node(s), ${matches} CPE match(es)`;
}

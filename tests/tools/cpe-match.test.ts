/**
 * @fileoverview Tests for the shared CPE match renderer and the configuration-node shape it
 * reads. `configurationNodes[]` carries what NVD nests under `configurations[].nodes[]` with the
 * group level hoisted away — one entry per node, tagged with its `groupIndex` — so these pin that
 * node boundaries survive, that group membership is recoverable, and that every qualifier
 * `structuredContent` carries also reaches `content[]`.
 * @module tests/tools/cpe-match.test
 */

import { describe, expect, it } from 'vitest';
import {
  CPE_MATCH_CAP,
  type CpeConfigurationNode,
  flattenCpeMatches,
  formatCpeMatch,
  summarizeCpeNodes,
} from '@/mcp-server/tools/formatting/cpe-match.js';
import { at } from '../support/at.js';

/** A node holding `matches`, with only the qualifiers a case actually exercises. */
function node(
  matches: CpeConfigurationNode['cpeMatch'],
  extra: Partial<Omit<CpeConfigurationNode, 'cpeMatch'>> = {},
): CpeConfigurationNode {
  return { groupIndex: 0, cpeMatch: matches, ...extra };
}

describe('formatCpeMatch', () => {
  it('names the group even when no operator qualifies the criterion', () => {
    const match = { criteria: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*', vulnerable: true };

    expect(formatCpeMatch(match, node([match]))).toBe(
      'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:* [group 0; vulnerable component]',
    );
  });

  it('renders all four version bounds in upper/lower, inclusive/exclusive order', () => {
    const match = {
      criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
      vulnerable: true,
      versionStartIncluding: '2.0',
      versionStartExcluding: '1.9',
      versionEndIncluding: '2.16.0',
      versionEndExcluding: '2.15.0',
    };

    expect(formatCpeMatch(match, node([match]))).toContain('(>= 2.0, > 1.9, <= 2.16.0, < 2.15.0)');
  });

  it('names the vulnerable flag on both branches so content[] carries what structuredContent does', () => {
    const base = { criteria: 'cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*' };

    expect(formatCpeMatch({ ...base, vulnerable: true }, node([]))).toContain(
      '[group 0; vulnerable component]',
    );
    expect(formatCpeMatch({ ...base, vulnerable: false }, node([]))).toContain(
      'not the vulnerable component',
    );
  });

  it('carries the group index, the group operator, and the node operator as separate qualifiers', () => {
    const match = {
      criteria: 'cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*',
      vulnerable: true,
    };
    const line = formatCpeMatch(
      match,
      node([match], { groupIndex: 2, groupOperator: 'AND', nodeOperator: 'OR' }),
    );

    // The group AND is what marks sibling nodes as jointly required rather than alternatives;
    // the node OR combines only the criteria inside this node.
    expect(line).toContain(
      '[group 2; AND with sibling nodes; OR within node; vulnerable component]',
    );
  });
});

describe('flattenCpeMatches', () => {
  it('returns nothing for a record with no configuration nodes', () => {
    expect(flattenCpeMatches([])).toEqual([]);
  });

  it('returns nothing for a node that carries no criteria', () => {
    expect(flattenCpeMatches([node([], { nodeOperator: 'OR' })])).toEqual([]);
  });

  it('keeps AND-combined sibling nodes separate while sharing their group', () => {
    const nodes: CpeConfigurationNode[] = [
      {
        groupIndex: 0,
        groupOperator: 'AND',
        nodeOperator: 'OR',
        cpeMatch: [
          { criteria: 'cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*', vulnerable: true },
          { criteria: 'cpe:2.3:o:netapp:a700s_firmware:9.0:*:*:*:*:*:*:*', vulnerable: true },
        ],
      },
      {
        groupIndex: 0,
        groupOperator: 'AND',
        nodeOperator: 'OR',
        cpeMatch: [{ criteria: 'cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*', vulnerable: false }],
      },
      {
        groupIndex: 1,
        cpeMatch: [{ criteria: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', vulnerable: true }],
      },
    ];

    const lines = flattenCpeMatches(nodes);

    expect(lines).toHaveLength(4);
    // The two firmware criteria are alternatives within one node; the hardware is a separate
    // conjunct of the same group — (firmware -, firmware 9.0) AND hardware.
    expect(at(lines, 0)).toContain('[group 0; AND with sibling nodes; OR within node');
    expect(at(lines, 1)).toContain('[group 0; AND with sibling nodes; OR within node');
    expect(at(lines, 2)).toContain('not the vulnerable component');
    // The second group's node must inherit neither the first group's AND nor its node operator.
    expect(at(lines, 3)).toBe(
      'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:* [group 1; vulnerable component]',
    );
  });

  it('flattens past the render cap so the caller can disclose what it dropped', () => {
    const nodes = [
      node(
        Array.from({ length: CPE_MATCH_CAP + 3 }, (_, i) => ({
          criteria: `cpe:2.3:o:fedoraproject:fedora:${30 + i}:*:*:*:*:*:*:*`,
          vulnerable: true,
        })),
      ),
    ];

    // The helper caps nothing itself — the count is what the caller's trailer is computed from.
    expect(flattenCpeMatches(nodes)).toHaveLength(CPE_MATCH_CAP + 3);
  });
});

describe('summarizeCpeNodes', () => {
  it('counts groups by distinct groupIndex, not by node', () => {
    const nodes: CpeConfigurationNode[] = [
      { groupIndex: 0, cpeMatch: [{ criteria: 'cpe:2.3:a:a:a:*', vulnerable: true }] },
      { groupIndex: 0, cpeMatch: [{ criteria: 'cpe:2.3:h:b:b:*', vulnerable: false }] },
      {
        groupIndex: 1,
        cpeMatch: [
          { criteria: 'cpe:2.3:a:c:c:*', vulnerable: true },
          { criteria: 'cpe:2.3:a:d:d:*', vulnerable: true },
        ],
      },
    ];

    expect(summarizeCpeNodes(nodes)).toBe('2 configuration group(s), 3 node(s), 4 CPE match(es)');
  });

  it('reports zeros for a record with no configuration nodes', () => {
    expect(summarizeCpeNodes([])).toBe('0 configuration group(s), 0 node(s), 0 CPE match(es)');
  });
});

/** @file Bundle cleanup must preserve runtime modules named skills. */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { AGENT_DOC_ENTRY, filterAgentDocEntries } from '../../scripts/clean-mcpb.js';

describe('dependency agent documentation cleanup', () => {
  it('removes package-root documentation while preserving runtime skills modules', () => {
    const docs = [
      'node_modules/pkg/skills/guide/SKILL.md',
      'node_modules/@scope/pkg/framework-skills/build/SKILL.md',
      'node_modules/pkg/.claude/settings.json',
      'node_modules/pkg/.agents/guide.md',
      'node_modules/pkg/SKILL.md',
      'node_modules/outer/node_modules/@scope/inner/skills/guide/SKILL.md',
    ];
    const runtime = [
      'node_modules/@modelcontextprotocol/server/dist/ext/skills/index.mjs',
      'node_modules/@modelcontextprotocol/core/dist/ext/skills/index.mjs',
      'node_modules/pkg/lib/skills/index.js',
      'node_modules/outer/node_modules/pkg/dist/skills/index.js',
      'skills/nist-nvd-guide/SKILL.md',
    ];
    expect(filterAgentDocEntries([...docs, ...runtime])).toEqual(docs);
    const linter = readFileSync(
      new URL('../../scripts/lint-packaging.ts', import.meta.url),
      'utf8',
    );
    expect(linter).toContain(`export const AGENT_DOC_ENTRY =\n  ${AGENT_DOC_ENTRY.toString()};`);
  });
});

/**
 * @fileoverview Render current SSVC assessments without flattening decision points.
 * @module mcp-server/tools/formatting/ssvc
 */

import type { z } from '@cyanheads/mcp-ts-core';
import { escapeMarkdownInline } from '@cyanheads/mcp-ts-core/utils';
import type { CveRecordSchema } from '@/mcp-server/tools/schemas/full-cve.js';

/** Preserve assessment and option order, including array-valued and repeated decision points. */
export function formatSsvc(
  assessments: NonNullable<z.infer<typeof CveRecordSchema>['ssvc']>,
): string[] {
  const lines = ['**SSVC:**'];
  for (const assessment of assessments) {
    lines.push(
      `- ${escapeMarkdownInline(assessment.source)} | ${escapeMarkdownInline(assessment.role)} | ${escapeMarkdownInline(assessment.version)}`,
    );
    if (assessment.timestamp !== undefined)
      lines.push(`  - Timestamp: ${escapeMarkdownInline(assessment.timestamp)}`);
    for (const option of assessment.decisionPoints) {
      for (const [key, value] of Object.entries(option)) {
        if (typeof value === 'string') {
          lines.push(`  - ${escapeMarkdownInline(key)}: ${escapeMarkdownInline(value)}`);
        } else {
          lines.push(`  - ${escapeMarkdownInline(key)}: ${value.length === 0 ? '[]' : ''}`);
          for (const item of value) lines.push(`    - ${escapeMarkdownInline(item)}`);
        }
      }
    }
  }
  return lines;
}

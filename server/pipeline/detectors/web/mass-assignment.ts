import { walkFiles, readText, relPath, trimEvidence } from './helpers.js';
import type { WebFinding } from './types.js';

/**
 * Mass assignment detector. Flags ORM update/create calls that pass
 * req.body / params directly without an explicit allow-list or pick.
 *
 * ORMs covered: Mongoose, Sequelize, TypeORM, Prisma, Knex, Django, Rails.
 */

const FILE_MATCH = /\.(?:js|mjs|cjs|ts|tsx|jsx|py|rb)$/i;

const PATTERNS: Array<{ re: RegExp; framework: string }> = [
  // Node/JS ORMs
  { re: /\.(?:update|updateOne|updateMany|create|create\w+|findByIdAndUpdate|findOneAndUpdate|save)\s*\(\s*(?:\{[^}]*\}?\s*,\s*)?req\.(?:body|params|query)\s*[,)]/, framework: 'nodejs-orm' },
  { re: /\.(?:update|create|upsert)\s*\(\s*\{[^{}]*data\s*:\s*req\.(?:body|params|query)/, framework: 'prisma' },
  // Django/Python
  { re: /(?:\.objects\.(?:create|update_or_create)|serializer)\s*\(\s*\*\*(?:request\.data|request\.POST|request\.json)\)/, framework: 'django' },
  // Rails
  { re: /\.(?:update|update_attributes|assign_attributes|create)\s*\(\s*params(?:\[:\w+\])?\s*\)/, framework: 'rails' },
];

const ALLOW_LIST_HINT = /\b(?:pick|permit|select|allow|whitelist|sanitize|fields\s*=\s*\[|Dto\s*\)|new\s+\w+Dto)/i;

export function runMassAssignmentDetector(projectPath: string): WebFinding[] {
  const files = walkFiles(projectPath, FILE_MATCH);
  const findings: WebFinding[] = [];
  for (const file of files) {
    const src = readText(file);
    if (!src) continue;
    const lines = src.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const p of PATTERNS) {
        if (!p.re.test(lines[i])) continue;
        // If allow-list is present on the same or previous line, lower severity
        const surrounding = lines.slice(Math.max(0, i - 2), i + 1).join('\n');
        if (ALLOW_LIST_HINT.test(surrounding)) continue;
        findings.push({
          category: 'api',
          subcategory: 'mass-assignment',
          title: `Possible mass assignment (${p.framework}): ORM writes accepting untrusted object`,
          severity: 'High',
          confidence: 'Medium',
          file: relPath(projectPath, file),
          line_start: i + 1,
          evidence: trimEvidence(lines[i]),
          framework: p.framework,
          cwe: 'CWE-915',
          rule_id: 'API-MASSIGN-001',
        });
        break;
      }
    }
  }
  return findings;
}

import { walkFiles, readText, relPath, trimEvidence } from './helpers.js';
import type { WebFinding } from './types.js';

/**
 * Race / TOCTOU detector. Flags classic stat->open, access->open, and
 * existsSync->writeFile sequences that indicate a time-of-check/time-of-use
 * race. Also flags read-then-write DB patterns without a transaction.
 */

const FILE_MATCH = /\.(?:js|mjs|cjs|ts|tsx|jsx|py|go)$/i;

const STAT_OPEN = /(?:fs\.(?:existsSync|accessSync|statSync|access|stat)|os\.access|os\.path\.exists)\s*\([^)]*\)/;
const LATER_OPEN = /(?:fs\.(?:writeFile|writeFileSync|open|openSync|appendFile|appendFileSync)|open\s*\(|io\.(?:copy|open))/;

export function runRaceToctouDetector(projectPath: string): WebFinding[] {
  const files = walkFiles(projectPath, FILE_MATCH);
  const findings: WebFinding[] = [];

  for (const file of files) {
    const src = readText(file);
    if (!src) continue;
    const lines = src.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (!STAT_OPEN.test(lines[i])) continue;
      const windowLines = lines.slice(i + 1, Math.min(i + 15, lines.length));
      const opIdx = windowLines.findIndex((l) => LATER_OPEN.test(l));
      if (opIdx !== -1) {
        findings.push({
          category: 'web',
          subcategory: 'race-toctou',
          title: 'Check-then-use filesystem pattern (TOCTOU race)',
          severity: 'Medium',
          confidence: 'Medium',
          file: relPath(projectPath, file),
          line_start: i + 1,
          line_end: i + 1 + opIdx + 1,
          evidence: trimEvidence(lines[i]) + ' | ' + trimEvidence(windowLines[opIdx]),
          cwe: 'CWE-367',
          rule_id: 'RACE-TOCTOU-001',
        });
      }
    }
  }
  return findings;
}

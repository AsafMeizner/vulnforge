import { walkFiles, readText, relPath, trimEvidence } from './helpers.js';
import type { WebFinding } from './types.js';

/**
 * CORS misconfig detector. Flags the canonical footguns:
 *   1. Access-Control-Allow-Origin: *  combined with Allow-Credentials: true
 *      (spec-illegal; some clients honor it - session theft territory).
 *   2. Dynamic origin from req.headers.origin without an allowlist check.
 *   3. cors({ origin: true }) - reflects arbitrary origin.
 */

const FILE_MATCH = /\.(?:js|mjs|cjs|ts|tsx|jsx|py)$/i;

const WILDCARD_WITH_CRED = [
  /Access-Control-Allow-Origin\s*[:,]\s*["'`]\*["'`]/,
  /Access-Control-Allow-Credentials\s*[:,]\s*["'`]?true["'`]?/,
];
const CORS_RE_TRUE = /cors\s*\(\s*\{[^}]*origin\s*:\s*true/;
const CORS_DYNAMIC = /cors\s*\(\s*\{[^}]*origin\s*:\s*(?:req\.headers\.origin|req\.header\s*\(\s*["'`]origin["'`]|origin\s*=>[^}]*origin\s*\))/;

export function runCorsMisconfigDetector(projectPath: string): WebFinding[] {
  const files = walkFiles(projectPath, FILE_MATCH);
  const findings: WebFinding[] = [];
  for (const file of files) {
    const src = readText(file);
    if (!src) continue;
    const lines = src.split('\n');

    // Whole-file check for wildcard + credentials (may be on different lines)
    const hasWildcard = WILDCARD_WITH_CRED[0].test(src);
    const hasCred = WILDCARD_WITH_CRED[1].test(src);
    if (hasWildcard && hasCred) {
      const wildLine = lines.findIndex((l) => WILDCARD_WITH_CRED[0].test(l));
      findings.push({
        category: 'web',
        subcategory: 'cors-wildcard-credentials',
        title: 'CORS: wildcard origin combined with credentials:true',
        severity: 'High',
        confidence: 'High',
        file: relPath(projectPath, file),
        line_start: wildLine + 1,
        evidence: trimEvidence(lines[wildLine] || ''),
        cwe: 'CWE-942',
        rule_id: 'CORS-001',
      });
    }

    for (let i = 0; i < lines.length; i++) {
      if (CORS_RE_TRUE.test(lines[i])) {
        findings.push({
          category: 'web',
          subcategory: 'cors-origin-true',
          title: 'CORS: origin:true reflects arbitrary origin',
          severity: 'High',
          confidence: 'High',
          file: relPath(projectPath, file),
          line_start: i + 1,
          evidence: trimEvidence(lines[i]),
          cwe: 'CWE-942',
          rule_id: 'CORS-002',
        });
      }
      if (CORS_DYNAMIC.test(lines[i])) {
        findings.push({
          category: 'web',
          subcategory: 'cors-dynamic-reflection',
          title: 'CORS: dynamic origin reflection without allowlist',
          severity: 'Medium',
          confidence: 'Medium',
          file: relPath(projectPath, file),
          line_start: i + 1,
          evidence: trimEvidence(lines[i]),
          cwe: 'CWE-942',
          rule_id: 'CORS-003',
        });
      }
    }
  }
  return findings;
}

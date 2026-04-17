import { findFilesByExt, readFileText, enumerateLines, snippet, relPath, findingId, looksTainted } from './helpers.js';
import type { InjectionFinding } from './types.js';

/**
 * Minimal LDAP injection detector. Flags filter strings concatenated with
 * what looks like user input in ldapjs, python-ldap, or ldap3.
 */
const FILTER_CONCAT = /(?:"|')\s*\(?[a-zA-Z_]+=\s*(?:\+\s*|\$\{|'\s*\+\s*)|\w+\s*=\s*["'](?:[^"']*(?:"|')\s*\+\s*\w+)/;
const LDAP_LIB_HINT = /\b(?:ldapjs|python-ldap|ldap3|\.search\s*\(|\.searchSync\s*\(|\.bind\s*\()/;

export function detectLdap(projectPath: string, maxFiles = 4000): InjectionFinding[] {
  const files = findFilesByExt(projectPath, ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.py'], maxFiles);
  const findings: InjectionFinding[] = [];
  for (const file of files) {
    const src = readFileText(file);
    if (!src) continue;
    if (!LDAP_LIB_HINT.test(src)) continue;
    for (const [lineNum, line] of enumerateLines(src)) {
      if (FILTER_CONCAT.test(line) && looksTainted(line)) {
        findings.push({
          id: findingId('ldap', file, lineNum, 'ldap_filter'),
          category: 'injection',
          subcategory: 'ldap',
          title: 'Possible LDAP injection via unsanitized filter construction',
          severity: 'High',
          file: relPath(projectPath, file),
          line_start: lineNum,
          sink_type: 'ldap_filter',
          source_confidence: 'possible',
          evidence: snippet(line),
          confidence: 'medium',
          cwe: 'CWE-90',
        });
      }
    }
  }
  return findings;
}

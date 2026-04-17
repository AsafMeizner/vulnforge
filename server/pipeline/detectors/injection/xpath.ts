import { findFilesByExt, readFileText, enumerateLines, snippet, relPath, findingId, looksTainted } from './helpers.js';
import type { InjectionFinding } from './types.js';

/**
 * Minimal XPath injection detector. Flags XPath expressions concatenated with
 * user input.
 */
const XPATH_CALL = /\b(?:evaluate|selectNodes|SelectNodes|selectSingleNode|SelectSingleNode|xpath)\s*\(\s*([^)]+)\)/;
const XPATH_CONCAT = /(?:"|')[/.]{1,2}[^"']*(?:"|')\s*\+\s*\w+|\bf?["'].*\$\{[^}]+\}.*(?:"|')/;

export function detectXpath(projectPath: string, maxFiles = 4000): InjectionFinding[] {
  const files = findFilesByExt(projectPath, ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.java', '.cs'], maxFiles);
  const findings: InjectionFinding[] = [];
  for (const file of files) {
    const src = readFileText(file);
    if (!src) continue;
    if (!/xpath|XPath|XPATH/.test(src)) continue;
    for (const [lineNum, line] of enumerateLines(src)) {
      if (!XPATH_CALL.test(line)) continue;
      if (XPATH_CONCAT.test(line) && looksTainted(line)) {
        findings.push({
          id: findingId('xpath', file, lineNum, 'xpath_query'),
          category: 'injection',
          subcategory: 'xpath',
          title: 'Possible XPath injection via string concatenation',
          severity: 'High',
          file: relPath(projectPath, file),
          line_start: lineNum,
          sink_type: 'xpath_query',
          source_confidence: 'possible',
          evidence: snippet(line),
          confidence: 'medium',
          cwe: 'CWE-643',
        });
      }
    }
  }
  return findings;
}

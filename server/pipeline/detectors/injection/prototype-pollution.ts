import { findFilesByExt, readFileText, enumerateLines, snippet, relPath, findingId, looksTainted } from './helpers.js';
import type { InjectionFinding } from './types.js';

/**
 * Prototype-pollution detector (JS/TS).
 */
const MERGE_JSON_PARSE = /(?:Object\.assign|_\.merge|_\.defaultsDeep|deepmerge|merge\-options)\s*\([^)]*JSON\.parse\s*\(/;
const COMPUTED_ASSIGN = /\b\w+\s*\[\s*(?:req\.(?:body|query|params)|user(?:Input|Key)|request\.[a-z]+|params\.[a-z]+)[^\]]*\]\s*=/;

type VersionCheck = { name: string; max: [number, number, number] };
const VULNERABLE_VERSIONS: VersionCheck[] = [
  { name: 'lodash.merge', max: [4, 17, 20] },
  { name: 'lodash.set', max: [4, 17, 19] },
  { name: 'minimist', max: [1, 2, 5] },
];

function parseSemverSafe(v: string | undefined | null): [number, number, number] | null {
  if (!v) return null;
  const m = v.match(/\d+\.\d+\.\d+/);
  if (!m) return null;
  const parts = m[0].split('.').map(Number) as [number, number, number];
  if (parts.some(Number.isNaN)) return null;
  return parts;
}

function cmp(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

export function detectPrototypePollution(projectPath: string, maxFiles = 4000): InjectionFinding[] {
  const findings: InjectionFinding[] = [];

  // Version-based findings from package.json
  const pjPath = projectPath.replace(/[\\/]+$/, '') + '/package.json';
  const pjText = readFileText(pjPath);
  if (pjText) {
    try {
      const pkg = JSON.parse(pjText);
      const all = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      for (const vc of VULNERABLE_VERSIONS) {
        const installed = all[vc.name];
        const parsed = parseSemverSafe(typeof installed === 'string' ? installed : null);
        if (parsed && cmp(parsed, vc.max) <= 0) {
          findings.push({
            id: findingId('proto', pjPath, 1, `vulnerable-${vc.name}`),
            category: 'injection',
            subcategory: 'proto',
            title: `Vulnerable ${vc.name}@${parsed.join('.')} (known prototype-pollution CVE)`,
            severity: 'High',
            file: pjPath.split('/').slice(-1)[0],
            line_start: 1,
            sink_type: 'vulnerable_library',
            source_confidence: 'definite',
            evidence: `${vc.name}: ${installed}`,
            confidence: 'high',
            cwe: 'CWE-1321',
          });
        }
      }
    } catch {
      // ignore malformed
    }
  }

  // Source-pattern findings
  const files = findFilesByExt(projectPath, ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'], maxFiles);
  for (const file of files) {
    const src = readFileText(file);
    if (!src) continue;
    for (const [lineNum, line] of enumerateLines(src)) {
      if (MERGE_JSON_PARSE.test(line) && looksTainted(line)) {
        findings.push({
          id: findingId('proto', file, lineNum, 'deep_merge'),
          category: 'injection',
          subcategory: 'proto',
          title: 'Deep merge from parsed user JSON - possible prototype pollution',
          severity: 'High',
          file: relPath(projectPath, file),
          line_start: lineNum,
          sink_type: 'deep_merge',
          source_confidence: 'likely',
          evidence: snippet(line),
          confidence: 'medium',
          cwe: 'CWE-1321',
        });
      }
      if (COMPUTED_ASSIGN.test(line)) {
        findings.push({
          id: findingId('proto', file, lineNum, 'computed_assign'),
          category: 'injection',
          subcategory: 'proto',
          title: 'Computed property assignment with user-controlled key',
          severity: 'Medium',
          file: relPath(projectPath, file),
          line_start: lineNum,
          sink_type: 'computed_assign',
          source_confidence: 'possible',
          evidence: snippet(line),
          confidence: 'medium',
          cwe: 'CWE-1321',
        });
      }
    }
  }
  return findings;
}

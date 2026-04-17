/**
 * J3 — Cross-finding deduplication.
 *
 * Groups multiple scanner findings that describe the same logical bug so
 * downstream AI verification runs once per group instead of once per raw
 * finding. This is where the bulk of the verify-stage cost is saved.
 *
 * Group key: `${cwe}|${normalized_title}|${function_sig}`.
 *   - CWE: the CWE identifier (fallback: 'unknown').
 *   - normalized_title: lowercased, stripped of file-specific words and numbers.
 *   - function_sig: name + arity extracted by lightweight per-language regex.
 *
 * The representative of each group is the finding with the most useful data —
 * preference order: higher severity > longer code_snippet > original index.
 */

// Structural subset — keeps this file free of DB coupling so tests can pass
// plain object fixtures.
export interface DedupFinding {
  id?: number;
  title: string;
  severity?: string;
  cwe?: string;
  file?: string;
  line_start?: number;
  line_end?: number;
  code_snippet?: string;
  description?: string;
  tool_name?: string;
  [key: string]: any;
}

import type { FindingGroup } from './types.js';

// ── Severity ranking (higher = worse) ──────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  moderate: 3,
  low: 2,
  info: 1,
  informational: 1,
  unknown: 0,
};

function severityScore(sev: string | undefined): number {
  if (!sev) return 0;
  return SEVERITY_RANK[String(sev).toLowerCase()] ?? 0;
}

// ── Title normalization ────────────────────────────────────────────────────

/**
 * Tokens that are very file/path/line-specific and should be stripped from
 * a title before comparison. Keep this conservative so we don't collide
 * genuinely-distinct bugs.
 */
const FILE_WORD_PATTERNS: RegExp[] = [
  /\.[a-z]{1,5}\b/gi,           // extensions like `.js`, `.tsx`, `.py`
  /\b[a-z0-9_-]+\/[a-z0-9_./-]+/gi, // path-like tokens `src/foo/bar`
  /\b[a-z0-9_-]+\.[a-z0-9_.-]+\b/gi, // `module.method` or `file.ext`
];

/**
 * Normalize a finding title for grouping.
 * - Lowercase
 * - Strip file-specific tokens (paths, extensions)
 * - Strip numbers (line numbers, counters)
 * - Collapse whitespace and punctuation
 * - Drop leading "finding:" / "issue:" / "warning:" noise
 */
export function normalizeTitle(title: string | undefined): string {
  if (!title) return '';
  let t = String(title).toLowerCase();

  // Strip leading issue-type labels.
  t = t.replace(/^(?:finding|issue|warning|alert|rule)\s*[:\-]\s*/, '');

  // Strip file-specific tokens.
  for (const re of FILE_WORD_PATTERNS) {
    t = t.replace(re, ' ');
  }

  // Strip all numbers (line numbers, counters).
  t = t.replace(/\d+/g, ' ');

  // Collapse any non-alphanumeric (except spaces) into spaces.
  t = t.replace(/[^a-z\s]/g, ' ');

  // Collapse whitespace.
  t = t.replace(/\s+/g, ' ').trim();

  return t;
}

// ── Function signature extraction ──────────────────────────────────────────

/**
 * Map a file extension to a best-guess language category.
 */
function detectLanguage(file: string | undefined): string {
  if (!file) return 'unknown';
  const lower = file.toLowerCase();
  if (/\.(py)$/.test(lower)) return 'python';
  if (/\.(js|mjs|cjs|jsx|ts|tsx)$/.test(lower)) return 'javascript';
  if (/\.(java|kt)$/.test(lower)) return 'java';
  if (/\.(go)$/.test(lower)) return 'go';
  if (/\.(rb)$/.test(lower)) return 'ruby';
  if (/\.(php)$/.test(lower)) return 'php';
  if (/\.(cs)$/.test(lower)) return 'csharp';
  if (/\.(c|cc|cpp|cxx|h|hpp)$/.test(lower)) return 'cfamily';
  if (/\.(rs)$/.test(lower)) return 'rust';
  return 'unknown';
}

/**
 * Regex table per language. Each entry matches function-ish declarations and
 * captures the function name (group 1). We then count `,` in the signature
 * to estimate arity.
 */
const FUNCTION_REGEX: Record<string, RegExp[]> = {
  python: [
    /def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/,
  ],
  javascript: [
    /function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>/,
    /([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*\{/,
    /([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?:async\s+)?(?:function\s*)?\(([^)]*)\)/,
  ],
  java: [
    /(?:public|private|protected|static|final|\s)*\s+[A-Za-z_<>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/,
  ],
  go: [
    /func\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/,
  ],
  ruby: [
    /def\s+([A-Za-z_][A-Za-z0-9_?!]*)(?:\(([^)]*)\))?/,
  ],
  php: [
    /function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/,
  ],
  csharp: [
    /(?:public|private|protected|internal|static|\s)*\s+[A-Za-z_<>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/,
  ],
  cfamily: [
    /[A-Za-z_][A-Za-z0-9_*\s]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{/,
  ],
  rust: [
    /fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^)]*)\)/,
  ],
  unknown: [
    /([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/,
  ],
};

/** Count arity from a comma-separated parameter list. Handles empty / ws-only. */
function paramsToArity(params: string): number {
  const trimmed = params.trim();
  if (!trimmed) return 0;
  // Simple comma split — good enough for grouping. We don't try to handle
  // nested generics; those would only produce a bigger-than-real arity which
  // still keeps semantically-different functions separate.
  return trimmed.split(',').filter(p => p.trim().length > 0).length;
}

/**
 * Extract a lightweight function signature (name + arity) from a code
 * snippet. Returns '' if nothing matched.
 *
 * Exported for unit tests.
 */
export function extractFunctionSignature(
  snippet: string | undefined,
  file: string | undefined,
): string {
  if (!snippet) return '';
  const lang = detectLanguage(file);
  const regexes = FUNCTION_REGEX[lang] || FUNCTION_REGEX.unknown;

  for (const re of regexes) {
    const m = snippet.match(re);
    if (m) {
      const name = m[1];
      const params = m[2] || '';
      const arity = paramsToArity(params);
      return `${name}/${arity}`;
    }
  }
  return '';
}

// ── Group key + representative picking ─────────────────────────────────────

/** Build the canonical grouping key for a finding. */
export function groupKey(finding: DedupFinding): string {
  const cwe = (finding.cwe || 'unknown').toUpperCase().trim() || 'unknown';
  const norm = normalizeTitle(finding.title);
  const sig = extractFunctionSignature(finding.code_snippet, finding.file);
  return `${cwe}|${norm}|${sig}`;
}

/**
 * Choose the best representative from a set of findings that landed in the
 * same group. Preference: higher severity > longer code snippet > original
 * order.
 */
function pickRepresentative<T extends DedupFinding>(findings: T[]): T {
  let best = findings[0];
  for (let i = 1; i < findings.length; i++) {
    const cand = findings[i];
    const bestSev = severityScore(best.severity);
    const candSev = severityScore(cand.severity);
    if (candSev > bestSev) {
      best = cand;
      continue;
    }
    if (candSev < bestSev) continue;
    const bestLen = (best.code_snippet || '').length;
    const candLen = (cand.code_snippet || '').length;
    if (candLen > bestLen) best = cand;
  }
  return best;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Group findings by `(cwe, normalized_title, function_sig)`. Returns one
 * `FindingGroup` per logical bug — callers should verify the representative
 * and then copy the verdict onto all `duplicates`.
 */
export function dedupFindings<T extends DedupFinding>(
  findings: T[],
): FindingGroup<T>[] {
  const groups = new Map<string, T[]>();
  for (const f of findings) {
    const key = groupKey(f);
    const existing = groups.get(key);
    if (existing) existing.push(f);
    else groups.set(key, [f]);
  }

  const result: FindingGroup<T>[] = [];
  for (const [key, members] of groups) {
    const representative = pickRepresentative(members);
    const duplicates = members.filter(m => m !== representative);
    result.push({
      key,
      representative,
      duplicates,
      count: members.length,
    });
  }

  // Stable-ish ordering: largest groups first, then by key.
  result.sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return a.key.localeCompare(b.key);
  });

  return result;
}

/**
 * Given a finished verification on a representative, build a list of
 * (finding, verdict) assignments to apply to every member of the group.
 * Exported as a helper for the integrator — not strictly required by the
 * spec but makes the integration one-liner safer.
 */
export function propagateVerdict<T extends DedupFinding, V>(
  group: FindingGroup<T>,
  verdict: V,
): Array<{ finding: T; verdict: V }> {
  const all = [group.representative, ...group.duplicates];
  return all.map(finding => ({ finding, verdict }));
}

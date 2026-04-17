/**
 * Triage Memory - history-aware auto-triage.
 *
 * Port of Parasoft's "reduce static analysis noise by grouping violations to
 * fix or ignore based on past triage actions" behavior.
 *
 * Idea: when a user accepts or rejects a finding, we record a small
 * "triage pattern" fingerprint. The next scan, before expensive AI verify,
 * we consult the pattern store: if this finding matches a strong pattern
 * that was rejected N times, auto-reject it. If it matches an accepted
 * pattern, boost confidence. Humans stay in the loop via an audit trail
 * and always-override default.
 *
 * Pattern fingerprint intentionally excludes line numbers and specific
 * variable names so the same class of issue in different commits collapses
 * into one pattern.
 */

import { getDb, persistDb } from '../db.js';
import type { ScanFinding } from '../db.js';

// Thin wrappers over the sql.js instance so this module stays portable
// even if server/db.ts swaps its internal query helpers.
function execRun(sql: string, params: any[] = []): void {
  const db = getDb();
  const stmt = db.prepare(sql);
  try {
    stmt.bind(params);
    stmt.step();
  } finally {
    stmt.free();
  }
}

function execQuery<T = any>(sql: string, params: any[] = []): T[] {
  const db = getDb();
  const stmt = db.prepare(sql);
  const out: T[] = [];
  try {
    stmt.bind(params);
    while (stmt.step()) out.push(stmt.getAsObject() as T);
  } finally {
    stmt.free();
  }
  return out;
}

// ──────────────────────────────────────────────────────────────────────────
//  Schema
// ──────────────────────────────────────────────────────────────────────────

/**
 * Ensure `triage_patterns` table exists. Idempotent; call at startup.
 *
 * Schema:
 *   pattern_hash    - SHA-ish key, see computePatternHash
 *   cwe             - CWE id (redundant with hash; kept for querying)
 *   normalized_title- lowercased, numbers-stripped title
 *   tool_name       - which detector produced this class
 *   accept_count    - times user accepted
 *   reject_count    - times user rejected
 *   ignore_count    - times user suppressed (distinct from reject - "valid but not worth fixing")
 *   last_decision   - 'accept' | 'reject' | 'ignore' - most recent
 *   last_seen       - ISO timestamp
 *   evidence_sample - one representative finding title, for humans
 */
export function ensureTriagePatternsTable(): void {
  execRun(`
    CREATE TABLE IF NOT EXISTS triage_patterns (
      pattern_hash TEXT PRIMARY KEY,
      cwe TEXT,
      normalized_title TEXT,
      tool_name TEXT,
      accept_count INTEGER DEFAULT 0,
      reject_count INTEGER DEFAULT 0,
      ignore_count INTEGER DEFAULT 0,
      last_decision TEXT,
      last_seen TEXT,
      evidence_sample TEXT
    )
  `);
  persistDb();
}

// ──────────────────────────────────────────────────────────────────────────
//  Pattern fingerprint
// ──────────────────────────────────────────────────────────────────────────

/**
 * Normalize a finding title to a stable form:
 *   - lowercase
 *   - strip file:line markers
 *   - strip identifiers (variable names that are obvious heuristically)
 *   - strip numbers
 *   - collapse whitespace
 */
export function normalizeTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/[a-z0-9_.\-/\\]+\.[a-z0-9]{1,5}\b/g, '<path>')  // file paths with ext
    .replace(/:\d+(?:-\d+)?/g, '')                            // :line or :line-line
    .replace(/["'`][^"'`]*["'`]/g, '<str>')                   // string literals
    .replace(/\b\d+\b/g, '<n>')                               // bare numbers
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Compute a stable SHA-256 of (cwe, normalized_title, tool_name, file_dir).
 * file_dir (directory portion only) keeps patterns module-local so a
 * "rejected in test/" pattern doesn't auto-reject "same title in src/".
 */
export function computePatternHash(finding: ScanFinding): string {
  const parts = [
    (finding.cwe || '').trim(),
    normalizeTitle(finding.title || ''),
    (finding.tool_name || '').trim(),
    (finding.file || '').split(/[\\/]/).slice(0, -1).join('/'), // dir
  ];
  // Lightweight hash (not cryptographic) - concat + djb2 is good enough
  // for a primary key, and avoids pulling crypto for a hot path.
  const s = parts.join('|');
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  // Encode to hex-like base36
  return (h >>> 0).toString(36) + ':' + parts[0] + ':' + parts[2];
}

// ──────────────────────────────────────────────────────────────────────────
//  Record decisions
// ──────────────────────────────────────────────────────────────────────────

export type TriageDecision = 'accept' | 'reject' | 'ignore';

export function recordTriageDecision(
  finding: ScanFinding,
  decision: TriageDecision
): void {
  ensureTriagePatternsTable();
  const hash = computePatternHash(finding);
  const now = new Date().toISOString();

  const existing = execQuery(
    'SELECT * FROM triage_patterns WHERE pattern_hash = ?',
    [hash]
  ) as Array<{
    pattern_hash: string;
    accept_count: number;
    reject_count: number;
    ignore_count: number;
  }>;

  if (existing.length === 0) {
    execRun(
      `INSERT INTO triage_patterns
        (pattern_hash, cwe, normalized_title, tool_name,
         accept_count, reject_count, ignore_count,
         last_decision, last_seen, evidence_sample)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        hash,
        finding.cwe || '',
        normalizeTitle(finding.title || ''),
        finding.tool_name || '',
        decision === 'accept' ? 1 : 0,
        decision === 'reject' ? 1 : 0,
        decision === 'ignore' ? 1 : 0,
        decision,
        now,
        finding.title || '',
      ]
    );
  } else {
    const col =
      decision === 'accept' ? 'accept_count' :
      decision === 'reject' ? 'reject_count' : 'ignore_count';
    execRun(
      `UPDATE triage_patterns
         SET ${col} = ${col} + 1,
             last_decision = ?,
             last_seen = ?
       WHERE pattern_hash = ?`,
      [decision, now, hash]
    );
  }
  persistDb();
}

// ──────────────────────────────────────────────────────────────────────────
//  Apply memory
// ──────────────────────────────────────────────────────────────────────────

export interface TriageSuggestion {
  decision: TriageDecision | 'unknown';
  confidence: number; // 0..1
  basis: {
    accept: number;
    reject: number;
    ignore: number;
    last_seen: string | null;
  };
  reason: string;
}

/**
 * Given a new finding, look up its pattern in history. Returns a suggestion
 * you can either auto-apply (high-confidence reject) or surface as a hint.
 *
 * Rule of thumb:
 *   - ≥3 same-decision votes and ≥70% agreement -> 'high confidence' (auto)
 *   - 1-2 votes or <70% agreement -> 'hint only' (show to user, don't apply)
 *   - 0 votes -> 'unknown'
 */
export function applyTriageMemory(finding: ScanFinding): TriageSuggestion {
  ensureTriagePatternsTable();
  const hash = computePatternHash(finding);
  const rows = execQuery(
    `SELECT accept_count, reject_count, ignore_count, last_seen
       FROM triage_patterns
      WHERE pattern_hash = ?`,
    [hash]
  ) as Array<{
    accept_count: number;
    reject_count: number;
    ignore_count: number;
    last_seen: string;
  }>;

  if (rows.length === 0) {
    return {
      decision: 'unknown',
      confidence: 0,
      basis: { accept: 0, reject: 0, ignore: 0, last_seen: null },
      reason: 'no_history',
    };
  }

  const r = rows[0];
  const total = r.accept_count + r.reject_count + r.ignore_count;
  const basis = {
    accept: r.accept_count,
    reject: r.reject_count,
    ignore: r.ignore_count,
    last_seen: r.last_seen,
  };

  if (total === 0) {
    return { decision: 'unknown', confidence: 0, basis, reason: 'empty_record' };
  }

  // Majority decision with agreement ratio
  const counts: Array<[TriageDecision, number]> = [
    ['accept', r.accept_count],
    ['reject', r.reject_count],
    ['ignore', r.ignore_count],
  ];
  counts.sort((a, b) => b[1] - a[1]);
  const [topDecision, topCount] = counts[0];
  const agreement = topCount / total;

  // Confidence scales with (count, agreement). Cap at 0.95 — never 1.0
  // because humans reserve the right to disagree.
  let confidence = 0;
  if (total >= 3 && agreement >= 0.7) {
    confidence = Math.min(0.95, 0.6 + 0.1 * total + (agreement - 0.7) * 0.5);
  } else if (total >= 1) {
    confidence = Math.min(0.5, 0.2 + 0.1 * total);
  }

  return {
    decision: topDecision,
    confidence,
    basis,
    reason:
      confidence >= 0.7
        ? 'strong_history_match'
        : confidence >= 0.3
          ? 'weak_history_hint'
          : 'insufficient_history',
  };
}

/**
 * Bulk-apply triage memory to a list of findings. Returns the findings
 * mutated in-place with a `triage_memory` property (non-persistent hint).
 * For CONFIDENT reject/ignore suggestions, also sets status='auto_rejected'
 * with rejection_reason populated so the smart-filter stage passes them
 * through as already-triaged.
 */
export function applyTriageMemoryToBatch(
  findings: ScanFinding[],
  autoApplyThreshold = 0.7
): { applied: number; hinted: number } {
  let applied = 0;
  let hinted = 0;
  for (const f of findings) {
    const s = applyTriageMemory(f);
    if (s.decision === 'unknown') continue;
    (f as any).triage_memory = s;
    if (
      s.confidence >= autoApplyThreshold &&
      (s.decision === 'reject' || s.decision === 'ignore') &&
      f.status === 'pending'
    ) {
      f.status = 'auto_rejected';
      f.rejection_reason = `triage_memory: ${s.decision} ${s.basis.reject}/${s.basis.accept + s.basis.reject + s.basis.ignore} (conf ${s.confidence.toFixed(2)})`;
      f.ai_filter_reason = `Auto-${s.decision}ed by triage memory (${Math.round(s.confidence * 100)}% confidence from history).`;
      applied++;
    } else {
      hinted++;
    }
  }
  return { applied, hinted };
}

// ──────────────────────────────────────────────────────────────────────────
//  Query helpers
// ──────────────────────────────────────────────────────────────────────────

export interface TriagePatternRow {
  pattern_hash: string;
  cwe: string;
  normalized_title: string;
  tool_name: string;
  accept_count: number;
  reject_count: number;
  ignore_count: number;
  last_decision: string;
  last_seen: string;
  evidence_sample: string;
}

export function listTriagePatterns(opts: {
  minTotal?: number;
  decision?: TriageDecision;
  limit?: number;
} = {}): TriagePatternRow[] {
  ensureTriagePatternsTable();
  const { minTotal = 1, decision, limit = 100 } = opts;
  const where: string[] = [];
  const params: any[] = [];
  if (decision) {
    where.push('last_decision = ?');
    params.push(decision);
  }
  where.push('(accept_count + reject_count + ignore_count) >= ?');
  params.push(minTotal);
  const sql = `
    SELECT * FROM triage_patterns
    WHERE ${where.join(' AND ')}
    ORDER BY (accept_count + reject_count + ignore_count) DESC,
             last_seen DESC
    LIMIT ?
  `;
  params.push(limit);
  return execQuery(sql, params) as TriagePatternRow[];
}

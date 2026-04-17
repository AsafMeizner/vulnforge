/**
 * J5 — Confidence calibration.
 *
 * Maintains a running confusion-matrix tally per (provider, task) pair so we
 * can adjust raw AI confidence against the provider's real-world track
 * record. Bootstraps with a Beta(1,1) prior so unseen pairs start at 0.5 —
 * this avoids the cold-start problem where one bad call tanks a provider.
 *
 * Table schema:
 *   CREATE TABLE IF NOT EXISTS ai_calibration (
 *     provider TEXT,
 *     task TEXT,
 *     true_positive INT,
 *     false_positive INT,
 *     true_negative INT,
 *     false_negative INT,
 *     updated_at TEXT
 *   )
 *
 * We don't modify `db.ts` (per track rules). Instead we talk to the DB
 * directly via the exported `getDb()` + `persistDb()` helpers and implement
 * our own `execRun` / `execQuery` shims locally.
 */

import { getDb, persistDb } from '../../db.js';
import type { CalibrationRow, HumanVerdict } from './types.js';

// ── Local exec helpers (db.ts does not export these) ───────────────────────

function execQuery(sql: string, params: any[] = []): Record<string, any>[] {
  const db: any = getDb();
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const out: Record<string, any>[] = [];
  while (stmt.step()) out.push(stmt.getAsObject());
  stmt.free();
  return out;
}

function execRun(sql: string, params: any[] = []): void {
  const db: any = getDb();
  db.run(sql, params);
  persistDb();
}

// ── Migration ──────────────────────────────────────────────────────────────

let migrated = false;

/**
 * Idempotent migration — creates the table if missing.
 * Called lazily from the public API so no boot-time changes are required.
 */
export function ensureCalibrationTable(): void {
  if (migrated) return;
  execRun(`
    CREATE TABLE IF NOT EXISTS ai_calibration (
      provider TEXT,
      task TEXT,
      true_positive INTEGER DEFAULT 0,
      false_positive INTEGER DEFAULT 0,
      true_negative INTEGER DEFAULT 0,
      false_negative INTEGER DEFAULT 0,
      updated_at TEXT,
      PRIMARY KEY (provider, task)
    )
  `);
  migrated = true;
}

/** Test hook — force migration to re-run (e.g. after DB reset). */
export function _resetMigrationForTests(): void {
  migrated = false;
}

// ── CRUD ───────────────────────────────────────────────────────────────────

function normKey(provider: string, task: string): { provider: string; task: string } {
  return {
    provider: (provider || 'unknown').toLowerCase().trim() || 'unknown',
    task: (task || 'unknown').toLowerCase().trim() || 'unknown',
  };
}

/** Fetch raw stats for (provider, task), or zero-filled defaults if unseen. */
export function getCalibrationRow(
  provider: string,
  task: string,
): CalibrationRow {
  ensureCalibrationTable();
  const key = normKey(provider, task);
  const rows = execQuery(
    'SELECT provider, task, true_positive, false_positive, true_negative, false_negative, updated_at FROM ai_calibration WHERE provider = ? AND task = ?',
    [key.provider, key.task],
  );
  if (rows.length === 0) {
    return {
      provider: key.provider,
      task: key.task,
      true_positive: 0,
      false_positive: 0,
      true_negative: 0,
      false_negative: 0,
    };
  }
  const r = rows[0];
  return {
    provider: String(r.provider),
    task: String(r.task),
    true_positive: Number(r.true_positive) || 0,
    false_positive: Number(r.false_positive) || 0,
    true_negative: Number(r.true_negative) || 0,
    false_negative: Number(r.false_negative) || 0,
    updated_at: r.updated_at ? String(r.updated_at) : undefined,
  };
}

/** List every recorded (provider, task) row. Handy for dashboards. */
export function listCalibrationRows(): CalibrationRow[] {
  ensureCalibrationTable();
  return execQuery(
    'SELECT provider, task, true_positive, false_positive, true_negative, false_negative, updated_at FROM ai_calibration ORDER BY provider, task',
  ).map(r => ({
    provider: String(r.provider),
    task: String(r.task),
    true_positive: Number(r.true_positive) || 0,
    false_positive: Number(r.false_positive) || 0,
    true_negative: Number(r.true_negative) || 0,
    false_negative: Number(r.false_negative) || 0,
    updated_at: r.updated_at ? String(r.updated_at) : undefined,
  }));
}

// ── Recording outcomes ─────────────────────────────────────────────────────

/**
 * Classify (ai_confidence, human_verdict) into TP/FP/TN/FN.
 *
 * Semantics:
 *   - `ai_confidence >= 0.5` means AI said "verified" (true).
 *   - `human_verdict === 'confirmed'` means the human agreed the finding was real.
 *   - `human_verdict === 'rejected'` means the human rejected the finding.
 *
 * Exported for unit-test coverage.
 */
export function classifyOutcome(
  ai_confidence: number,
  human_verdict: HumanVerdict,
): keyof Pick<
  CalibrationRow,
  'true_positive' | 'false_positive' | 'true_negative' | 'false_negative'
> {
  const aiSaidYes = ai_confidence >= 0.5;
  const humanSaidYes = human_verdict === 'confirmed';
  if (aiSaidYes && humanSaidYes) return 'true_positive';
  if (aiSaidYes && !humanSaidYes) return 'false_positive';
  if (!aiSaidYes && !humanSaidYes) return 'true_negative';
  return 'false_negative'; // AI said no, human said yes
}

/**
 * Record one review outcome and update the running tally.
 *
 * `finding_id` is accepted for auditability and forward-compat (future: log
 * per-finding outcomes in a sibling table). For now we only roll it into
 * aggregate stats.
 */
export function recordReviewOutcome(
  finding_id: number,
  ai_confidence: number,
  human_verdict: HumanVerdict,
  provider = 'unknown',
  task = 'verify',
): CalibrationRow {
  ensureCalibrationTable();
  const bucket = classifyOutcome(ai_confidence, human_verdict);
  const key = normKey(provider, task);
  const now = new Date().toISOString();

  // Upsert: try UPDATE first, INSERT if no row existed.
  const existing = execQuery(
    'SELECT 1 FROM ai_calibration WHERE provider = ? AND task = ?',
    [key.provider, key.task],
  );
  if (existing.length === 0) {
    const row: CalibrationRow = {
      provider: key.provider,
      task: key.task,
      true_positive: 0,
      false_positive: 0,
      true_negative: 0,
      false_negative: 0,
    };
    row[bucket] = 1;
    execRun(
      'INSERT INTO ai_calibration (provider, task, true_positive, false_positive, true_negative, false_negative, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [
        row.provider,
        row.task,
        row.true_positive,
        row.false_positive,
        row.true_negative,
        row.false_negative,
        now,
      ],
    );
  } else {
    execRun(
      `UPDATE ai_calibration SET ${bucket} = ${bucket} + 1, updated_at = ? WHERE provider = ? AND task = ?`,
      [now, key.provider, key.task],
    );
  }

  // finding_id kept in scope for future use; suppress unused-var lint.
  void finding_id;

  return getCalibrationRow(provider, task);
}

// ── Calibrated confidence ──────────────────────────────────────────────────

/**
 * Beta(1,1) posterior mean for "AI is right when it says yes" = precision.
 *   precision = (TP + 1) / (TP + FP + 2)
 * Likewise for "AI is right when it says no" = negative predictive value.
 *   npv       = (TN + 1) / (TN + FN + 2)
 *
 * Exported to let the UI show precision/NPV bars if desired.
 */
export function computePrecisionAndNpv(row: CalibrationRow): {
  precision: number;
  npv: number;
} {
  const precision = (row.true_positive + 1) / (row.true_positive + row.false_positive + 2);
  const npv = (row.true_negative + 1) / (row.true_negative + row.false_negative + 2);
  return { precision, npv };
}

/**
 * Adjust a raw AI confidence using the provider's track record.
 *
 * Mapping:
 *   - If raw >= 0.5 → `calibrated = raw * precision + (1 - raw) * (1 - npv)`
 *     equivalent to P(real | AI says yes, confidence=raw) under a simple
 *     linear-mixture model. When precision = 1, calibrated = raw; when
 *     precision = 0, calibrated is flipped through (1-raw)*(1-npv).
 *   - If raw < 0.5 → symmetric: `calibrated = raw * (1 - npv) + (1 - raw) * (1 - precision)`
 *     … wait. We want: lower raw + high npv → near 0; lower raw + low npv →
 *     drift towards 0.5. Use the same formula but swap precision↔npv for the
 *     negative branch.
 *
 * In practice for Beta(1,1) priors with no data, precision = npv = 0.5, so
 * calibrated = 0.5 regardless of raw — we preserve raw confidence by
 * blending instead of replacing.
 */
export function getCalibratedConfidence(
  raw_confidence: number,
  provider: string,
  task: string,
): number {
  const raw = Math.max(0, Math.min(1, Number(raw_confidence) || 0));
  const row = getCalibrationRow(provider, task);
  const { precision, npv } = computePrecisionAndNpv(row);
  const totalObservations =
    row.true_positive + row.false_positive + row.true_negative + row.false_negative;

  // Blend weight: how much we trust the track record. Pure Beta(1,1) prior
  // (no data) → blend = 0, returns raw. Plenty of data → blend → 1.
  // Smooth logistic: w = n / (n + 10).
  const w = totalObservations / (totalObservations + 10);

  // Reliability score: precision if AI said yes, npv if AI said no.
  const aiSaidYes = raw >= 0.5;
  const reliability = aiSaidYes ? precision : npv;

  // Direction-aware adjustment: if AI said yes and its precision is low, pull
  // calibrated DOWN; if npv is low when AI said no, pull calibrated UP.
  let calibrated: number;
  if (aiSaidYes) {
    // Scale raw towards reliability. `raw` stays at 1 when reliability=1, moves
    // toward 0.5 (uninformative) as reliability→0.5, and below 0.5 as
    // reliability→0.
    calibrated = raw * reliability + (1 - raw) * (1 - reliability);
  } else {
    // Symmetric for "no" branch: high npv keeps calibrated low; low npv pulls
    // it up toward 0.5 or above.
    calibrated = raw * (1 - reliability) + (1 - raw) * reliability;
    // Flip framing: this returns P(real). Invert:
    calibrated = 1 - calibrated;
  }

  // Weighted blend between raw and calibrated.
  return (1 - w) * raw + w * calibrated;
}

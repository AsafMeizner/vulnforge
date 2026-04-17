/**
 * Pipeline metrics — per-pipeline stage tracking.
 *
 * Records:
 *  - Per-stage durations (stage = any of the 6+ pipeline stages; we
 *    don't enforce a fixed enum so new stages can be added without
 *    migrations).
 *  - Finding counts at each filter tier (raw → dedup → regex-filter →
 *    AI-filter → verified).
 *  - AI token usage per pipeline (prompt / completion / total, and an
 *    optional cost estimate if pricing is supplied).
 *
 * Storage: additive SQLite tables `pipeline_metrics` (stage events)
 * and `pipeline_ai_usage` (token usage rollups).  Migrations are
 * `CREATE TABLE IF NOT EXISTS`.
 */
import { getDb, persistDb } from '../db.js';

// ── Types ──────────────────────────────────────────────────────────────────

export type PipelineTier = 'raw' | 'dedup' | 'regex_filter' | 'ai_filter' | 'verified';

export interface StageArtifactCounts {
  /** Findings in this tier, keyed by tier name; or any other numeric artifact. */
  [key: string]: number;
}

export interface StageEvent {
  pipeline_id: string;
  stage: string;
  duration_ms: number;
  artifact_counts: StageArtifactCounts;
  recorded_at: string;
}

export interface AIUsageDelta {
  pipeline_id: string;
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
  /** Optional — caller-supplied cost estimate in USD. */
  cost_usd?: number;
  provider?: string;
  model?: string;
}

export interface PipelineRollup {
  pipeline_id: string;
  stages: Array<{
    stage: string;
    duration_ms: number;
    artifact_counts: StageArtifactCounts;
    recorded_at: string;
  }>;
  tier_counts: Partial<Record<PipelineTier, number>>;
  ai_usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
    cost_usd: number;
    calls: number;
  };
  total_duration_ms: number;
}

// ── Migration ──────────────────────────────────────────────────────────────

let _migrated = false;

function ensureSchema(): void {
  if (_migrated) return;
  const db = getDb();
  db.run(`
    CREATE TABLE IF NOT EXISTS pipeline_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pipeline_id TEXT NOT NULL,
      stage TEXT NOT NULL,
      duration_ms INTEGER NOT NULL DEFAULT 0,
      artifact_counts TEXT NOT NULL DEFAULT '{}',
      recorded_at INTEGER NOT NULL
    )
  `);
  db.run(
    `CREATE INDEX IF NOT EXISTS idx_pipeline_metrics_pid ON pipeline_metrics(pipeline_id)`,
  );
  db.run(
    `CREATE INDEX IF NOT EXISTS idx_pipeline_metrics_time ON pipeline_metrics(recorded_at)`,
  );

  db.run(`
    CREATE TABLE IF NOT EXISTS pipeline_ai_usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pipeline_id TEXT NOT NULL,
      prompt_tokens INTEGER NOT NULL DEFAULT 0,
      completion_tokens INTEGER NOT NULL DEFAULT 0,
      total_tokens INTEGER NOT NULL DEFAULT 0,
      cost_usd REAL NOT NULL DEFAULT 0,
      provider TEXT,
      model TEXT,
      recorded_at INTEGER NOT NULL
    )
  `);
  db.run(
    `CREATE INDEX IF NOT EXISTS idx_pipeline_ai_usage_pid ON pipeline_ai_usage(pipeline_id)`,
  );

  _migrated = true;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Record the completion of a pipeline stage.  `artifact_counts` is a
 * free-form map — callers pass tier names (`raw`, `dedup`, ...) or
 * other numeric metadata relevant to that stage.
 */
export function recordStageComplete(
  pipeline_id: string,
  stage: string,
  duration_ms: number,
  artifact_counts: StageArtifactCounts = {},
): void {
  ensureSchema();
  const db = getDb();
  db.run(
    `INSERT INTO pipeline_metrics (pipeline_id, stage, duration_ms, artifact_counts, recorded_at)
     VALUES (?, ?, ?, ?, ?)`,
    [
      pipeline_id,
      stage,
      Math.max(0, Math.round(duration_ms || 0)),
      JSON.stringify(artifact_counts || {}),
      Date.now(),
    ],
  );
  persistDb();
}

/** Record AI token usage against a pipeline (additive per call). */
export function recordAIUsage(usage: AIUsageDelta): void {
  ensureSchema();
  const db = getDb();
  const prompt = Math.max(0, Math.round(usage.prompt_tokens || 0));
  const completion = Math.max(0, Math.round(usage.completion_tokens || 0));
  const total = Math.max(
    0,
    Math.round(usage.total_tokens ?? prompt + completion),
  );
  db.run(
    `INSERT INTO pipeline_ai_usage (pipeline_id, prompt_tokens, completion_tokens, total_tokens, cost_usd, provider, model, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      usage.pipeline_id,
      prompt,
      completion,
      total,
      Number.isFinite(usage.cost_usd) ? (usage.cost_usd as number) : 0,
      usage.provider || null,
      usage.model || null,
      Date.now(),
    ],
  );
  persistDb();
}

/** Fetch all stage events + AI usage for a pipeline as a rollup. */
export function getPipelineMetrics(pipeline_id: string): PipelineRollup {
  ensureSchema();
  const db = getDb();

  const stageStmt = db.prepare(
    `SELECT stage, duration_ms, artifact_counts, recorded_at
     FROM pipeline_metrics
     WHERE pipeline_id = ?
     ORDER BY recorded_at ASC`,
  );
  stageStmt.bind([pipeline_id]);
  const stages: PipelineRollup['stages'] = [];
  const tierCounts: Partial<Record<PipelineTier, number>> = {};
  let totalDuration = 0;
  while (stageStmt.step()) {
    const row = stageStmt.get();
    const stage = String(row[0]);
    const duration = Number(row[1] || 0);
    const artifactJson = String(row[2] || '{}');
    const recordedAt = Number(row[3] || 0);
    let parsed: StageArtifactCounts = {};
    try {
      const obj = JSON.parse(artifactJson);
      if (obj && typeof obj === 'object') parsed = obj as StageArtifactCounts;
    } catch { /* keep empty */ }

    totalDuration += duration;
    stages.push({
      stage,
      duration_ms: duration,
      artifact_counts: parsed,
      recorded_at: recordedAt ? new Date(recordedAt).toISOString() : '',
    });

    // Merge known tier counts; last-write-wins per tier so the latest
    // stage's numbers dominate (e.g. if AI filter reports a new
    // "ai_filter" tier count, that replaces any earlier one).
    for (const key of Object.keys(parsed)) {
      if (isTier(key)) {
        tierCounts[key as PipelineTier] = parsed[key];
      }
    }
  }
  stageStmt.free();

  const usageStmt = db.prepare(
    `SELECT prompt_tokens, completion_tokens, total_tokens, cost_usd
     FROM pipeline_ai_usage
     WHERE pipeline_id = ?`,
  );
  usageStmt.bind([pipeline_id]);
  let pTok = 0;
  let cTok = 0;
  let tTok = 0;
  let cost = 0;
  let calls = 0;
  while (usageStmt.step()) {
    const row = usageStmt.get();
    pTok += Number(row[0] || 0);
    cTok += Number(row[1] || 0);
    tTok += Number(row[2] || 0);
    cost += Number(row[3] || 0);
    calls++;
  }
  usageStmt.free();

  return {
    pipeline_id,
    stages,
    tier_counts: tierCounts,
    ai_usage: {
      prompt_tokens: pTok,
      completion_tokens: cTok,
      total_tokens: tTok,
      cost_usd: roundTo(cost, 4),
      calls,
    },
    total_duration_ms: totalDuration,
  };
}

/** List pipeline IDs with recorded metrics, newest-first. */
export function listPipelineMetricIds(limit = 50): string[] {
  ensureSchema();
  const db = getDb();
  const stmt = db.prepare(
    `SELECT pipeline_id, MAX(recorded_at) as last
     FROM pipeline_metrics
     GROUP BY pipeline_id
     ORDER BY last DESC
     LIMIT ?`,
  );
  stmt.bind([Math.max(1, Math.min(500, limit))]);
  const ids: string[] = [];
  while (stmt.step()) {
    const row = stmt.get();
    ids.push(String(row[0]));
  }
  stmt.free();
  return ids;
}

/** Reset migration state — tests only. */
export function __resetPipelineMetricsSchema(): void {
  _migrated = false;
}

// ── Helpers ────────────────────────────────────────────────────────────────

const TIERS: ReadonlyArray<PipelineTier> = [
  'raw',
  'dedup',
  'regex_filter',
  'ai_filter',
  'verified',
];

function isTier(key: string): boolean {
  return (TIERS as readonly string[]).includes(key);
}

function roundTo(n: number, decimals: number): number {
  const mul = Math.pow(10, decimals);
  return Math.round(n * mul) / mul;
}

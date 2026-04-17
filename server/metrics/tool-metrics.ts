/**
 * Per-tool metrics — records the outcome of each tool run and exposes
 * a rollup (mean / p95 latency, finding counts, rejection ratio, error
 * rate) over rolling 24h + all-time windows.
 *
 * Storage: additive SQLite table `tool_metrics` (CREATE TABLE IF NOT
 * EXISTS migration runs on first call) plus an in-memory ring buffer
 * of recent entries for fast summaries without hitting disk.
 *
 * This module does NOT wrap `scanner/runner.ts` — the lead integrator
 * is responsible for calling {@link recordToolRun} around each spawn.
 */
import { getDb, persistDb } from '../db.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ToolRunMetrics {
  tool: string;
  duration_ms: number;
  finding_count: number;
  rejected_count?: number;
  error?: string | null;
  /** Optional override for the run timestamp (defaults to `Date.now()`). */
  at?: number;
}

export interface ToolRollup {
  tool: string;
  runs: number;
  mean_latency_ms: number;
  p95_latency_ms: number;
  total_findings: number;
  total_rejected: number;
  auto_rejected_ratio: number;
  error_rate: number;
  last_run_at: string | null;
}

export interface ToolMetricsSummary {
  window: 'all_time' | 'rolling_24h';
  tools: ToolRollup[];
  total_runs: number;
}

// ── Migration ──────────────────────────────────────────────────────────────

let _migrated = false;

function ensureSchema(): void {
  if (_migrated) return;
  const db = getDb();
  db.run(`
    CREATE TABLE IF NOT EXISTS tool_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tool TEXT NOT NULL,
      duration_ms INTEGER NOT NULL DEFAULT 0,
      finding_count INTEGER NOT NULL DEFAULT 0,
      rejected_count INTEGER NOT NULL DEFAULT 0,
      error TEXT,
      recorded_at INTEGER NOT NULL
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tool_metrics_tool ON tool_metrics(tool)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_tool_metrics_time ON tool_metrics(recorded_at)`);
  _migrated = true;
}

// ── In-memory cache ────────────────────────────────────────────────────────

/** Keep the last N entries in memory for fast summaries. */
const MEM_CAP = 2_000;
const _mem: Array<ToolRunMetrics & { recorded_at: number }> = [];

function pushMem(entry: ToolRunMetrics & { recorded_at: number }): void {
  _mem.push(entry);
  if (_mem.length > MEM_CAP) _mem.splice(0, _mem.length - MEM_CAP);
}

// ── Public API ─────────────────────────────────────────────────────────────

/** Record the outcome of a single tool run. */
export function recordToolRun(m: ToolRunMetrics): void {
  ensureSchema();
  const at = m.at ?? Date.now();
  const db = getDb();
  db.run(
    `INSERT INTO tool_metrics (tool, duration_ms, finding_count, rejected_count, error, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      m.tool,
      Math.max(0, Math.round(m.duration_ms || 0)),
      Math.max(0, Math.round(m.finding_count || 0)),
      Math.max(0, Math.round(m.rejected_count || 0)),
      m.error || null,
      at,
    ],
  );
  persistDb();
  pushMem({ ...m, recorded_at: at });
}

/**
 * Compute per-tool rollups across all historical runs in the table.
 * When `windowMs` is supplied, only runs inside `[now - windowMs, now]`
 * are considered.
 */
export function getToolMetrics(windowMs?: number): ToolMetricsSummary {
  ensureSchema();
  const db = getDb();
  const now = Date.now();
  const from = typeof windowMs === 'number' ? now - windowMs : 0;

  const stmt = db.prepare(
    `SELECT tool, duration_ms, finding_count, rejected_count, error, recorded_at
     FROM tool_metrics
     WHERE recorded_at >= ?
     ORDER BY recorded_at ASC`,
  );
  stmt.bind([from]);

  const byTool = new Map<string, Array<{ d: number; f: number; r: number; e: string | null; at: number }>>();
  while (stmt.step()) {
    const row = stmt.get();
    const tool = String(row[0]);
    const arr = byTool.get(tool) || [];
    arr.push({
      d: Number(row[1] || 0),
      f: Number(row[2] || 0),
      r: Number(row[3] || 0),
      e: row[4] ? String(row[4]) : null,
      at: Number(row[5] || 0),
    });
    byTool.set(tool, arr);
  }
  stmt.free();

  const rollups: ToolRollup[] = [];
  let totalRuns = 0;
  for (const [tool, entries] of byTool) {
    totalRuns += entries.length;
    rollups.push(rollup(tool, entries));
  }
  rollups.sort((a, b) => b.runs - a.runs);

  return {
    window: typeof windowMs === 'number' ? 'rolling_24h' : 'all_time',
    tools: rollups,
    total_runs: totalRuns,
  };
}

/** Convenience wrapper: rolling 24h window. */
export function getToolMetrics24h(): ToolMetricsSummary {
  return getToolMetrics(24 * 60 * 60 * 1_000);
}

/** Return both all-time and 24h snapshots in one call. */
export function getToolMetricsBothWindows(): {
  all_time: ToolMetricsSummary;
  rolling_24h: ToolMetricsSummary;
} {
  return {
    all_time: getToolMetrics(),
    rolling_24h: getToolMetrics24h(),
  };
}

/** Wipe the in-memory cache (tests only). */
export function __resetToolMetricsMemoryCache(): void {
  _mem.length = 0;
}

/** Force migration to run again on next call (tests only). */
export function __resetToolMetricsSchema(): void {
  _migrated = false;
}

/** Inspect the in-memory cache (tests/dashboards). */
export function getRecentToolRuns(limit = 100): Array<ToolRunMetrics & { recorded_at: number }> {
  if (limit <= 0) return [];
  return _mem.slice(-limit).map((e) => ({ ...e }));
}

// ── Helpers ────────────────────────────────────────────────────────────────

function rollup(
  tool: string,
  entries: Array<{ d: number; f: number; r: number; e: string | null; at: number }>,
): ToolRollup {
  const runs = entries.length;
  if (runs === 0) {
    return {
      tool,
      runs: 0,
      mean_latency_ms: 0,
      p95_latency_ms: 0,
      total_findings: 0,
      total_rejected: 0,
      auto_rejected_ratio: 0,
      error_rate: 0,
      last_run_at: null,
    };
  }

  let sumD = 0;
  let sumF = 0;
  let sumR = 0;
  let errs = 0;
  let lastAt = 0;
  const latencies: number[] = [];

  for (const e of entries) {
    sumD += e.d;
    sumF += e.f;
    sumR += e.r;
    if (e.e) errs++;
    if (e.at > lastAt) lastAt = e.at;
    latencies.push(e.d);
  }

  latencies.sort((a, b) => a - b);
  const meanLatency = sumD / runs;
  const p95 = percentile(latencies, 0.95);
  const autoRejectedRatio = sumF > 0 ? sumR / sumF : 0;
  const errorRate = runs > 0 ? errs / runs : 0;

  return {
    tool,
    runs,
    mean_latency_ms: roundTo(meanLatency, 2),
    p95_latency_ms: roundTo(p95, 2),
    total_findings: sumF,
    total_rejected: sumR,
    auto_rejected_ratio: roundTo(autoRejectedRatio, 4),
    error_rate: roundTo(errorRate, 4),
    last_run_at: lastAt ? new Date(lastAt).toISOString() : null,
  };
}

function percentile(sortedAsc: number[], p: number): number {
  if (sortedAsc.length === 0) return 0;
  if (sortedAsc.length === 1) return sortedAsc[0];
  // Nearest-rank method — matches common dashboards.
  const rank = Math.ceil(p * sortedAsc.length) - 1;
  const idx = Math.max(0, Math.min(sortedAsc.length - 1, rank));
  return sortedAsc[idx];
}

function roundTo(n: number, decimals: number): number {
  const mul = Math.pow(10, decimals);
  return Math.round(n * mul) / mul;
}

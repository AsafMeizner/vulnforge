/**
 * Finding metrics — read-only aggregate queries over the existing
 * `scan_findings` and `vulnerabilities` tables.
 *
 * Produces rollups by severity, CWE, tool, and auto-rejection reason,
 * plus daily time series for new findings, rejections, and
 * verifications.  This module does NOT create new tables or write to
 * existing tables — it is pure read-side analytics.
 */
import { getDb } from '../db.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface CountBy<T extends string> {
  key: T;
  count: number;
}

export interface FindingAggregateStats {
  total: number;
  by_severity: CountBy<string>[];
  by_cwe: CountBy<string>[];
  by_tool: CountBy<string>[];
  by_status: CountBy<string>[];
  by_rejection_reason: CountBy<string>[];
  verified_count: number;
  pending_count: number;
  auto_rejected_count: number;
}

export interface DailyPoint {
  /** Local YYYY-MM-DD. */
  date: string;
  count: number;
}

export interface FindingTimeSeries {
  new_findings: DailyPoint[];
  rejections: DailyPoint[];
  verifications: DailyPoint[];
  window_days: number;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Produce the full aggregate rollup.  All top-N limits default to 25
 * to keep payloads small; pass `{ limit }` to override.
 */
export function getFindingMetrics(options: { limit?: number } = {}): FindingAggregateStats {
  const limit = clamp(options.limit ?? 25, 1, 500);
  const db = getDb();

  if (!tableExists(db, 'scan_findings')) {
    return {
      total: 0,
      by_severity: [],
      by_cwe: [],
      by_tool: [],
      by_status: [],
      by_rejection_reason: [],
      verified_count: 0,
      pending_count: 0,
      auto_rejected_count: 0,
    };
  }

  const total = countRows(db, `SELECT COUNT(*) AS c FROM scan_findings`);
  const by_severity = groupCount(db, `SELECT COALESCE(severity, '') AS k, COUNT(*) AS c FROM scan_findings GROUP BY COALESCE(severity, '') ORDER BY c DESC LIMIT ?`, [limit]);
  const by_cwe = groupCount(db, `SELECT COALESCE(cwe, '') AS k, COUNT(*) AS c FROM scan_findings WHERE COALESCE(cwe, '') != '' GROUP BY cwe ORDER BY c DESC LIMIT ?`, [limit]);
  const by_tool = groupCount(db, `SELECT COALESCE(tool_name, '') AS k, COUNT(*) AS c FROM scan_findings GROUP BY COALESCE(tool_name, '') ORDER BY c DESC LIMIT ?`, [limit]);
  const by_status = groupCount(db, `SELECT COALESCE(status, '') AS k, COUNT(*) AS c FROM scan_findings GROUP BY COALESCE(status, '') ORDER BY c DESC LIMIT ?`, [limit]);
  const by_rejection_reason = groupCount(db, `SELECT COALESCE(rejection_reason, '') AS k, COUNT(*) AS c FROM scan_findings WHERE COALESCE(rejection_reason, '') != '' GROUP BY rejection_reason ORDER BY c DESC LIMIT ?`, [limit]);

  const verified_count = countRows(db, `SELECT COUNT(*) AS c FROM scan_findings WHERE status = 'accepted'`);
  const pending_count = countRows(db, `SELECT COUNT(*) AS c FROM scan_findings WHERE status = 'pending'`);
  const auto_rejected_count = countRows(db, `SELECT COUNT(*) AS c FROM scan_findings WHERE status = 'auto_rejected'`);

  return {
    total,
    by_severity,
    by_cwe,
    by_tool,
    by_status,
    by_rejection_reason,
    verified_count,
    pending_count,
    auto_rejected_count,
  };
}

/**
 * Build daily time-series for the trailing `windowDays` days.
 * `new_findings` is bucketed by `scan_findings.created_at`.
 * `rejections` by `scan_findings.created_at` WHERE status in
 * ('auto_rejected','rejected').  `verifications` by
 * `vulnerabilities.found_at` (the canonical table for triaged +
 * verified findings).
 */
export function getFindingTimeSeries(windowDays = 30): FindingTimeSeries {
  const days = clamp(windowDays, 1, 365);
  const db = getDb();
  const startIso = dateNDaysAgoIso(days);

  const newFindings = tableExists(db, 'scan_findings')
    ? dailySeries(db, `SELECT SUBSTR(created_at, 1, 10) AS d, COUNT(*) AS c
                      FROM scan_findings
                      WHERE created_at IS NOT NULL AND created_at >= ?
                      GROUP BY d ORDER BY d ASC`, [startIso], days)
    : emptyDays(days);

  const rejections = tableExists(db, 'scan_findings')
    ? dailySeries(db, `SELECT SUBSTR(created_at, 1, 10) AS d, COUNT(*) AS c
                      FROM scan_findings
                      WHERE created_at IS NOT NULL AND created_at >= ?
                        AND status IN ('auto_rejected', 'rejected')
                      GROUP BY d ORDER BY d ASC`, [startIso], days)
    : emptyDays(days);

  const verifications = tableExists(db, 'vulnerabilities')
    ? dailySeries(db, `SELECT SUBSTR(COALESCE(found_at, ''), 1, 10) AS d, COUNT(*) AS c
                      FROM vulnerabilities
                      WHERE COALESCE(found_at, '') >= ? AND verified = 1
                      GROUP BY d ORDER BY d ASC`, [startIso], days)
    : emptyDays(days);

  return {
    new_findings: newFindings,
    rejections,
    verifications,
    window_days: days,
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────

function tableExists(db: any, name: string): boolean {
  try {
    const stmt = db.prepare(`SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?`);
    stmt.bind([name]);
    const exists = stmt.step();
    stmt.free();
    return Boolean(exists);
  } catch {
    return false;
  }
}

function countRows(db: any, sql: string, params: any[] = []): number {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  let n = 0;
  if (stmt.step()) {
    const row = stmt.get();
    n = Number(row[0] || 0);
  }
  stmt.free();
  return n;
}

function groupCount(db: any, sql: string, params: any[] = []): CountBy<string>[] {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const out: CountBy<string>[] = [];
  while (stmt.step()) {
    const row = stmt.get();
    const k = row[0] == null ? '' : String(row[0]);
    out.push({ key: k, count: Number(row[1] || 0) });
  }
  stmt.free();
  return out;
}

function dailySeries(
  db: any,
  sql: string,
  params: any[],
  windowDays: number,
): DailyPoint[] {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const map = new Map<string, number>();
  while (stmt.step()) {
    const row = stmt.get();
    const d = row[0] ? String(row[0]) : '';
    if (!d) continue;
    map.set(d, Number(row[1] || 0));
  }
  stmt.free();

  // Fill in zero-buckets for missing days so the series is continuous.
  const series: DailyPoint[] = [];
  const now = new Date();
  for (let i = windowDays - 1; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1_000);
    const iso = d.toISOString().slice(0, 10);
    series.push({ date: iso, count: map.get(iso) ?? 0 });
  }
  return series;
}

function emptyDays(windowDays: number): DailyPoint[] {
  const now = new Date();
  const out: DailyPoint[] = [];
  for (let i = windowDays - 1; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1_000);
    out.push({ date: d.toISOString().slice(0, 10), count: 0 });
  }
  return out;
}

function dateNDaysAgoIso(days: number): string {
  const d = new Date(Date.now() - days * 24 * 60 * 60 * 1_000);
  return d.toISOString();
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

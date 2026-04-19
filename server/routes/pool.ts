/**
 * Pool-scope routes - opt-in, anonymized, cross-organization findings pool.
 *
 * Pool data flows through THIS endpoint, not regular sync. Rows are
 * anonymized SERVER-SIDE via anonymizeForPool() in sync/model.ts before
 * insertion - the client cannot bypass the anonymizer by crafting a
 * direct insert path, because there isn't one.
 *
 *   POST /api/pool/push         - anonymize + insert into pool_<table>
 *   GET  /api/pool/snapshot     - read current pool contents (1h cache)
 *
 * Pool tables are separate per syncable table (pool_projects,
 * pool_vulnerabilities, pool_scan_findings, pool_notes). Created lazily.
 */
import { Router, type Request, type Response, NextFunction } from 'express';

import { assertPermission } from '../auth/permissions.js';
import { getDb, persistDb } from '../db.js';
import {
  SYNCABLE_TABLES,
  isSyncable,
  anonymizeForPool,
} from '../sync/model.js';

const router = Router();

// Lazy-create pool_<table> shadow tables on first push.
const ensuredPoolTables = new Set<string>();

function ensurePoolTable(table: string): void {
  if (ensuredPoolTables.has(table)) return;
  const db = getDb();
  const poolName = `pool_${table}`;
  // Simple generic shape - we store rows as JSON blobs keyed by the
  // source row's sync_id. Avoids mirroring every column and keeps the
  // pool schema evolution-proof.
  db.run(
    `CREATE TABLE IF NOT EXISTS ${poolName} (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       sync_id TEXT UNIQUE,
       submitted_at INTEGER,
       submitted_by_org TEXT DEFAULT '',
       data_json TEXT NOT NULL
     )`,
  );
  db.run(`CREATE INDEX IF NOT EXISTS idx_${poolName}_submitted ON ${poolName}(submitted_at)`);
  ensuredPoolTables.add(table);
}

// Simple in-memory 1h snapshot cache per table.
const snapshotCache = new Map<string, { at: number; rows: any[] }>();
const SNAPSHOT_TTL_MS = 60 * 60 * 1000;

router.post('/push', (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'not authenticated' });
    if (!assertPermission(req, 'findings', 'write', res)) return;
    const { table, rows } = req.body ?? {};
    if (!isSyncable(table)) return res.status(400).json({ error: `invalid table: ${table}` });
    if (!Array.isArray(rows)) return res.status(400).json({ error: 'rows must be an array' });
    if (rows.length > 500) return res.status(413).json({ error: 'batch too large; max 500' });

    ensurePoolTable(table);
    const db = getDb();
    const poolName = `pool_${table}`;
    const now = Date.now();

    let accepted = 0;
    let skipped = 0;
    for (const raw of rows) {
      if (!raw || typeof raw !== 'object') { skipped++; continue; }
      if (!raw.sync_id) { skipped++; continue; }
      if (raw.sync_scope !== 'pool') { skipped++; continue; } // pool-only endpoint
      const anonymized = anonymizeForPool(table, raw);
      try {
        db.run(
          `INSERT OR REPLACE INTO ${poolName} (sync_id, submitted_at, data_json) VALUES (?, ?, ?)`,
          [String(anonymized.sync_id), now, JSON.stringify(anonymized)],
        );
        accepted++;
      } catch { skipped++; }
    }
    if (accepted > 0) {
      persistDb();
      snapshotCache.delete(table); // invalidate cache
    }
    res.json({ accepted, skipped });
  } catch (err: any) {
    next(err);
  }
});

router.get('/snapshot', (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'not authenticated' });
    if (!assertPermission(req, 'findings', 'read', res)) return;
    const table = String(req.query.table || '');
    if (!isSyncable(table)) return res.status(400).json({ error: `invalid table: ${table}` });

    const cached = snapshotCache.get(table);
    if (cached && Date.now() - cached.at < SNAPSHOT_TTL_MS) {
      return res.json({ rows: cached.rows, cached_at: cached.at });
    }

    ensurePoolTable(table);
    const db = getDb();
    const poolName = `pool_${table}`;
    const stmt = db.prepare(`SELECT sync_id, submitted_at, data_json FROM ${poolName} ORDER BY submitted_at DESC LIMIT 1000`);
    const rows: any[] = [];
    while (stmt.step()) {
      const vals = stmt.get();
      try {
        const data = JSON.parse(String(vals[2] ?? '{}'));
        rows.push({ sync_id: vals[0], submitted_at: vals[1], ...data });
      } catch { /* skip malformed */ }
    }
    stmt.free();
    snapshotCache.set(table, { at: Date.now(), rows });
    res.json({ rows, cached_at: Date.now() });
  } catch (err: any) {
    next(err);
  }
});

router.get('/tables', (_req: Request, res: Response) => {
  res.json({ tables: SYNCABLE_TABLES });
});

export default router;

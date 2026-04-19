/**
 * Sync REST routes - fallback + primary transport when WebSocket is down.
 *
 * Mounted at /api/sync/*. Protected by auth middleware.
 *
 *   GET  /api/sync/pull?table=X&since=N&limit=N   - batch pull
 *   POST /api/sync/push                            - batch push
 *   GET  /api/sync/cursors                         - current per-table cursors
 *   POST /api/sync/gc                              - admin tombstone sweep
 */
import { Router, type Request, type Response, NextFunction } from 'express';

import { assertPermission } from '../auth/permissions.js';
import {
  pullTable,
  pushRows,
  allCursors,
  gcTombstones,
} from '../sync/repo.js';
import { SYNCABLE_TABLES, isSyncable, type SyncableTable } from '../sync/model.js';

const router = Router();

function requireUser(req: Request, res: Response): { user_id: number; role: string } | null {
  if (!req.user) {
    res.status(401).json({ error: 'not authenticated' });
    return null;
  }
  return { user_id: req.user.id, role: req.user.role };
}

router.get('/tables', (_req: Request, res: Response, next: NextFunction) => {
  res.json({ tables: SYNCABLE_TABLES });
});

router.get('/cursors', (req: Request, res: Response, next: NextFunction) => {
  const user = requireUser(req, res);
  if (!user) return;
  res.json({ cursors: allCursors(0, user) });
});

router.get('/pull', (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = requireUser(req, res);
    if (!user) return;
    const table = String(req.query.table || '');
    const since = Number(req.query.since ?? 0);
    const limit = Math.max(1, Math.min(500, Number(req.query.limit ?? 200)));
    if (!isSyncable(table)) {
      return res.status(400).json({ error: `invalid table: ${table}` });
    }
    if (!assertPermission(req, toResource(table), 'read', res)) return;
    const result = pullTable({ table: table as SyncableTable, since, limit, user });
    res.json(result);
  } catch (err: any) {
    next(err);
  }
});

router.post('/push', (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = requireUser(req, res);
    if (!user) return;
    const { table, rows } = req.body ?? {};
    if (!isSyncable(table)) {
      return res.status(400).json({ error: `invalid table: ${table}` });
    }
    if (!Array.isArray(rows)) {
      return res.status(400).json({ error: 'rows must be an array' });
    }
    if (rows.length === 0) {
      return res.json({ accepted: [], merged: [], rejected: [] });
    }
    if (rows.length > 500) {
      return res.status(413).json({ error: 'batch too large; max 500 rows' });
    }
    if (!assertPermission(req, toResource(table), 'write', res)) return;
    const outcome = pushRows({ table: table as SyncableTable, rows, user });
    res.json(outcome);
  } catch (err: any) {
    next(err);
  }
});

router.post('/gc', (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  if (!assertPermission(req, 'settings', 'admin', res)) return;
  const retainDays = Math.max(1, Number(req.body?.retain_days ?? 30));
  const deleted = gcTombstones(retainDays);
  res.json({ deleted });
});

/** Map a syncable table to its RBAC resource name. */
function toResource(table: string): string {
  switch (table) {
    case 'projects': return 'projects';
    case 'vulnerabilities':
    case 'scan_findings':
    case 'reports':
      return 'findings';
    case 'scans':
    case 'pipeline_runs':
      return 'pipelines';
    case 'notes':
      return 'notes';
    case 'checklists':
    case 'checklist_items':
      return 'findings';
    case 'session_state':
      return 'findings';
    default:
      return 'findings';
  }
}

export default router;

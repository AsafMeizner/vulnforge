/**
 * Sync repository — DB access for the sync protocol.
 *
 * All queries here operate only on SYNCABLE_TABLES. Anything else
 * is rejected via isSyncable() guard — never let a caller sync
 * refresh_tokens or ai_providers by accident.
 *
 * Pull: paginated, cursor-based, per-table.
 * Push: per-row conflict resolution via resolveConflict().
 */
import { getDb, persistDb } from '../db.js';
import {
  SYNCABLE_TABLES,
  isSyncable,
  resolveConflict,
  stampForServerAccept,
  userCanSeeRow,
  isTeamSyncScope,
  type SyncableTable,
  type SyncableRow,
} from './model.js';

export interface PullArgs {
  table: SyncableTable;
  since: number;              // ms epoch; return rows where server_updated_at_ms > since
  limit?: number;              // default 200
  user: { user_id: number; role: string };
}

export interface PullResult {
  rows: SyncableRow[];
  next_cursor: number;         // max(server_updated_at_ms) in this batch, or `since` if empty
  done: boolean;                // true when fewer than `limit` rows returned
}

export function pullTable(args: PullArgs): PullResult {
  if (!isSyncable(args.table)) {
    throw new Error(`pullTable: ${args.table} is not syncable`);
  }
  const db = getDb();
  const limit = args.limit ?? 200;
  const stmt = db.prepare(
    `SELECT * FROM ${args.table}
     WHERE COALESCE(server_updated_at_ms, 0) > ?
       AND sync_scope IN ('team')
     ORDER BY server_updated_at_ms ASC
     LIMIT ?`,
  );
  stmt.bind([args.since, limit + 1]); // +1 to peek if more remain
  const cols = stmt.getColumnNames();
  const rows: SyncableRow[] = [];
  while (stmt.step()) {
    const vals = stmt.get();
    const obj: Record<string, any> = {};
    cols.forEach((c: string, i: number) => { obj[c] = vals[i]; });
    rows.push(obj as SyncableRow);
  }
  stmt.free();

  const hasMore = rows.length > limit;
  const batch = hasMore ? rows.slice(0, limit) : rows;

  // Defense in depth — filter via scope-aware check even though WHERE already excluded non-team
  const visible = batch.filter(r => userCanSeeRow(r, args.user));

  const cursor = visible.length
    ? Math.max(...visible.map(r => r.server_updated_at_ms ?? args.since))
    : args.since;

  return { rows: visible, next_cursor: cursor, done: !hasMore };
}

export interface PushArgs {
  table: SyncableTable;
  rows: Partial<SyncableRow>[];
  user: { user_id: number; role: string };
  now?: number;
}

export interface PushOutcome {
  accepted: Array<{ sync_id: string; server_updated_at_ms: number }>;
  merged: Array<{ sync_id: string; server_updated_at_ms: number }>;
  rejected: Array<{ sync_id: string; current: SyncableRow }>;
}

export function pushRows(args: PushArgs): PushOutcome {
  if (!isSyncable(args.table)) {
    throw new Error(`pushRows: ${args.table} is not syncable`);
  }
  const db = getDb();
  const serverClock = args.now ?? Date.now();
  const outcome: PushOutcome = { accepted: [], merged: [], rejected: [] };

  for (const incoming of args.rows) {
    if (!incoming.sync_id) continue; // skip malformed
    if (incoming.sync_scope && !isTeamSyncScope(incoming.sync_scope as any)) {
      // Private/pool rows should not come through team sync push.
      continue;
    }

    // Find current row by sync_id
    const findStmt = db.prepare(`SELECT * FROM ${args.table} WHERE sync_id = ? LIMIT 1`);
    findStmt.bind([incoming.sync_id]);
    let current: SyncableRow | null = null;
    if (findStmt.step()) {
      const vals = findStmt.get();
      const cols = findStmt.getColumnNames();
      const obj: Record<string, any> = {};
      cols.forEach((c: string, i: number) => { obj[c] = vals[i]; });
      current = obj as SyncableRow;
    }
    findStmt.free();

    const resolution = resolveConflict(args.table, incoming as SyncableRow, current);

    if (resolution.kind === 'reject') {
      outcome.rejected.push({ sync_id: incoming.sync_id, current: resolution.current });
      continue;
    }

    const rowToWrite = stampForServerAccept(
      resolution.kind === 'accept-incoming' ? resolution.row : resolution.merged,
      serverClock,
    );

    if (current) {
      // UPDATE
      const keys = Object.keys(rowToWrite).filter(k => k !== 'id' && k !== 'rowid');
      const sets = keys.map(k => `${k} = ?`).join(', ');
      const values = keys.map(k => rowToWrite[k]);
      db.run(
        `UPDATE ${args.table} SET ${sets} WHERE sync_id = ?`,
        [...values, rowToWrite.sync_id],
      );
    } else {
      // INSERT — drop id so AUTOINCREMENT assigns
      const insertRow: Record<string, any> = { ...rowToWrite };
      delete insertRow.id;
      const keys = Object.keys(insertRow);
      const placeholders = keys.map(() => '?').join(', ');
      const values = keys.map(k => insertRow[k]);
      db.run(
        `INSERT INTO ${args.table} (${keys.join(', ')}) VALUES (${placeholders})`,
        values,
      );
    }

    const record = { sync_id: rowToWrite.sync_id, server_updated_at_ms: rowToWrite.server_updated_at_ms ?? serverClock };
    if (resolution.kind === 'field-merge') outcome.merged.push(record);
    else outcome.accepted.push(record);
  }

  persistDb();
  return outcome;
}

/** Map of cursor values across every syncable table. */
export function allCursors(since = 0, user: { user_id: number; role: string }): Record<string, number> {
  const db = getDb();
  const result: Record<string, number> = {};
  for (const table of SYNCABLE_TABLES) {
    try {
      const stmt = db.prepare(`SELECT MAX(COALESCE(server_updated_at_ms, 0)) AS max FROM ${table} WHERE sync_scope = 'team'`);
      if (stmt.step()) {
        const vals = stmt.get();
        result[table] = (vals[0] as number) ?? since;
      } else {
        result[table] = since;
      }
      stmt.free();
    } catch {
      result[table] = since;
    }
  }
  // Touch user ref to silence unused-param warning — may be used later for per-user cursors
  void user;
  return result;
}

/** Apply a tombstone sweep — hard-delete rows tombstoned > retainDays ago. */
export function gcTombstones(retainDays: number = 30): number {
  const cutoff = Date.now() - retainDays * 24 * 60 * 60 * 1000;
  const db = getDb();
  let total = 0;
  for (const table of SYNCABLE_TABLES) {
    try {
      const before = countRows(table);
      db.run(`DELETE FROM ${table} WHERE tombstone = 1 AND COALESCE(server_updated_at_ms, 0) < ?`, [cutoff]);
      const after = countRows(table);
      total += (before - after);
    } catch { /* skip */ }
  }
  if (total > 0) persistDb();
  return total;
}

function countRows(table: string): number {
  const db = getDb();
  const stmt = db.prepare(`SELECT COUNT(*) FROM ${table}`);
  stmt.step();
  const vals = stmt.get();
  stmt.free();
  return (vals[0] as number) ?? 0;
}

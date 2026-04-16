import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

// Each test run gets a fresh DB file.
const tmpDir = mkdtempSync(path.join(tmpdir(), 'vulnforge-test-'));
const dbPath = path.join(tmpDir, 'sync-repo.db');
process.env.VULNFORGE_DB_PATH = dbPath;

let initDb: typeof import('../../server/db')['initDb'];
let getDb: typeof import('../../server/db')['getDb'];
let pullTable: typeof import('../../server/sync/repo')['pullTable'];
let pushRows: typeof import('../../server/sync/repo')['pushRows'];
let allCursors: typeof import('../../server/sync/repo')['allCursors'];
let stampForLocalWrite: typeof import('../../server/sync/model')['stampForLocalWrite'];
let ulid: typeof import('../../server/utils/ulid')['ulid'];

beforeAll(async () => {
  const dbModule = await import('../../server/db');
  const repoModule = await import('../../server/sync/repo');
  const modelModule = await import('../../server/sync/model');
  const ulidModule = await import('../../server/utils/ulid');
  initDb = dbModule.initDb;
  getDb = dbModule.getDb;
  pullTable = repoModule.pullTable;
  pushRows = repoModule.pushRows;
  allCursors = repoModule.allCursors;
  stampForLocalWrite = modelModule.stampForLocalWrite;
  ulid = ulidModule.ulid;
  await initDb();
});

afterAll(() => {
  try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('sync-repo integration', () => {
  const user = { user_id: 1, role: 'admin' };

  it('empty pull returns done=true with 0 rows', () => {
    const out = pullTable({ table: 'notes', since: 0, limit: 10, user });
    expect(out.rows).toHaveLength(0);
    expect(out.done).toBe(true);
  });

  it('push then pull a team note', () => {
    const row = stampForLocalWrite({
      provider: 'local',
      external_id: 'int-test-1',
      title: 'Integration test note',
      type: 'note',
      tags: '[]',
      finding_ids: '[]',
      file_refs: '[]',
    }, { sync_scope: 'team', owner_user_id: 1 });

    const outcome = pushRows({ table: 'notes', user, rows: [row] });
    expect(outcome.accepted.length).toBe(1);
    expect(outcome.rejected.length).toBe(0);

    const pulled = pullTable({ table: 'notes', since: 0, limit: 10, user });
    expect(pulled.rows.length).toBeGreaterThanOrEqual(1);
    const found = pulled.rows.find(r => r.external_id === 'int-test-1');
    expect(found).toBeTruthy();
    expect(found!.title).toBe('Integration test note');
  });

  it('rejects stale-clock overwrite', () => {
    // First establish a row at high clock
    const row = stampForLocalWrite({
      provider: 'local', external_id: 'int-test-stale', title: 'original',
      type: 'note', tags: '[]', finding_ids: '[]', file_refs: '[]',
    }, { sync_scope: 'team', owner_user_id: 1 });
    pushRows({ table: 'notes', user, rows: [row] });

    // Now push the same sync_id with an older updated_at_ms — must reject
    const stale = { ...row, updated_at_ms: row.updated_at_ms - 1_000_000, title: 'stale' };
    const outcome = pushRows({ table: 'notes', user, rows: [stale] });
    expect(outcome.rejected.length).toBe(1);
    expect(outcome.accepted.length).toBe(0);
  });

  it('silently skips private + pool scope pushes', () => {
    const privateRow = { ...stampForLocalWrite({ title: 'x', type: 'note', tags: '[]', finding_ids: '[]', file_refs: '[]' }, { sync_scope: 'private', owner_user_id: 1 }) };
    const poolRow = { ...stampForLocalWrite({ title: 'y', type: 'note', tags: '[]', finding_ids: '[]', file_refs: '[]' }, { sync_scope: 'pool', owner_user_id: 1 }) };
    const outcome = pushRows({ table: 'notes', user, rows: [privateRow, poolRow] });
    expect(outcome.accepted.length).toBe(0);
    expect(outcome.rejected.length).toBe(0);
  });

  it('tombstone propagates via pull', () => {
    const row = stampForLocalWrite({
      provider: 'local', external_id: 'int-test-tomb', title: 'tomb',
      type: 'note', tags: '[]', finding_ids: '[]', file_refs: '[]',
    }, { sync_scope: 'team', owner_user_id: 1 });
    pushRows({ table: 'notes', user, rows: [row] });

    const tombRow = { ...row, tombstone: 1 as const, updated_at_ms: row.updated_at_ms + 1_000 };
    const outcome = pushRows({ table: 'notes', user, rows: [tombRow] });
    expect(outcome.accepted.length).toBe(1);

    const pulled = pullTable({ table: 'notes', since: 0, limit: 100, user });
    const tomb = pulled.rows.find(r => r.sync_id === row.sync_id);
    expect(tomb?.tombstone).toBe(1);
  });

  it('cursors advance after pushes', () => {
    const before = allCursors(0, user).notes;
    const row = stampForLocalWrite({
      provider: 'local', external_id: 'cursor-test-' + ulid(), title: 'cursor',
      type: 'note', tags: '[]', finding_ids: '[]', file_refs: '[]',
    }, { sync_scope: 'team', owner_user_id: 1 });
    pushRows({ table: 'notes', user, rows: [row] });
    const after = allCursors(0, user).notes;
    expect(after).toBeGreaterThanOrEqual(before);
  });

  it('rejects unknown table with throw', () => {
    expect(() => pullTable({ table: 'refresh_tokens' as any, since: 0, user })).toThrow();
    expect(() => pushRows({ table: 'refresh_tokens' as any, rows: [], user })).toThrow();
  });
});

import { describe, it, expect } from 'vitest';
import {
  SYNCABLE_TABLES,
  UNSYNCABLE_TABLES,
  CAPABILITY_TABLES,
  SCOPE_VALUES,
  isSyncable,
  isUnsyncable,
  isCapabilityTable,
  isValidScope,
  isTeamSyncScope,
  stampForLocalWrite,
  stampForServerAccept,
  stampForClientApply,
  stampForTombstone,
  resolveConflict,
  anonymizeForPool,
  userCanSeeRow,
  type SyncableRow,
} from '../../server/sync/model';

describe('category predicates', () => {
  it('isSyncable matches SYNCABLE_TABLES', () => {
    for (const t of SYNCABLE_TABLES) expect(isSyncable(t)).toBe(true);
    expect(isSyncable('refresh_tokens')).toBe(false);
    expect(isSyncable('ai_providers')).toBe(false);
    expect(isSyncable('not-a-table')).toBe(false);
  });

  it('isUnsyncable matches UNSYNCABLE_TABLES', () => {
    for (const t of UNSYNCABLE_TABLES) expect(isUnsyncable(t)).toBe(true);
    expect(isUnsyncable('projects')).toBe(false);
  });

  it('isCapabilityTable only matches ai_providers + integrations', () => {
    expect(isCapabilityTable('ai_providers')).toBe(true);
    expect(isCapabilityTable('integrations')).toBe(true);
    expect(isCapabilityTable('projects')).toBe(false);
  });

  it('syncable + unsyncable lists are disjoint', () => {
    for (const s of SYNCABLE_TABLES) expect(UNSYNCABLE_TABLES).not.toContain(s);
    for (const u of UNSYNCABLE_TABLES) expect(SYNCABLE_TABLES as readonly string[]).not.toContain(u);
  });
});

describe('scope helpers', () => {
  it('isValidScope matches SCOPE_VALUES', () => {
    for (const s of SCOPE_VALUES) expect(isValidScope(s)).toBe(true);
    expect(isValidScope('nope')).toBe(false);
    expect(isValidScope(null)).toBe(false);
  });

  it('isTeamSyncScope only accepts team', () => {
    expect(isTeamSyncScope('team')).toBe(true);
    expect(isTeamSyncScope('private' as any)).toBe(false);
    expect(isTeamSyncScope('pool' as any)).toBe(false);
  });
});

describe('stampForLocalWrite', () => {
  it('mints sync_id if absent, stamps pending', () => {
    const r = stampForLocalWrite({ title: 'x' }, { owner_user_id: 7 });
    expect(r.sync_id).toHaveLength(26);
    expect(r.sync_scope).toBe('private');
    expect(r.owner_user_id).toBe(7);
    expect(r.sync_status).toBe('pending');
    expect(r.tombstone).toBe(0);
    expect(r.updated_at_ms).toBeGreaterThan(0);
  });

  it('preserves existing sync_id', () => {
    const existing = 'preexistingsyncidsentinel0';
    const r = stampForLocalWrite({ sync_id: existing });
    expect(r.sync_id).toBe(existing);
  });

  it('honors defaults.sync_scope', () => {
    const r = stampForLocalWrite({}, { sync_scope: 'team' });
    expect(r.sync_scope).toBe('team');
  });
});

describe('stampForServerAccept', () => {
  it('sets server_updated_at_ms and marks synced', () => {
    const r = stampForServerAccept({ sync_id: 'X', updated_at_ms: 100 }, 200);
    expect(r.server_updated_at_ms).toBe(200);
    expect(r.sync_status).toBe('synced');
  });
});

describe('stampForClientApply / stampForTombstone', () => {
  it('client-apply marks synced, preserves server clock', () => {
    const r = stampForClientApply({ sync_id: 'X', server_updated_at_ms: 500 });
    expect(r.sync_status).toBe('synced');
    expect(r.server_updated_at_ms).toBe(500);
  });

  it('tombstone sets tombstone=1 and pending', () => {
    const r = stampForTombstone({ sync_id: 'X' });
    expect(r.tombstone).toBe(1);
    expect(r.sync_status).toBe('pending');
  });
});

describe('resolveConflict', () => {
  const base = (ms: number, extras: any = {}): SyncableRow => ({
    sync_id: 'X',
    sync_scope: 'team',
    owner_user_id: 1,
    updated_at_ms: ms,
    server_updated_at_ms: ms,
    tombstone: 0,
    sync_status: 'synced',
    ...extras,
  });

  it('accepts when no current row exists', () => {
    const out = resolveConflict('projects', base(100), null);
    expect(out.kind).toBe('accept-incoming');
  });

  it('accepts newer incoming for non-mergeable table', () => {
    const current = base(100);
    const incoming = { ...base(200), title: 'new' };
    const out = resolveConflict('projects', incoming, current);
    expect(out.kind).toBe('accept-incoming');
  });

  it('rejects older incoming for non-mergeable table', () => {
    const current = base(200);
    const incoming = base(100);
    const out = resolveConflict('projects', incoming, current);
    expect(out.kind).toBe('reject');
  });

  it('field-merges scan_findings.notes (concat)', () => {
    const current = base(100, { notes: 'alice' });
    const incoming = base(200, { notes: 'bob' });
    const out = resolveConflict('scan_findings', incoming, current);
    expect(out.kind).toBe('field-merge');
    if (out.kind === 'field-merge') {
      expect(out.merged.notes).toContain('alice');
      expect(out.merged.notes).toContain('bob');
    }
  });

  it('field-merges scan_findings.merged_tools (union)', () => {
    const current = base(100, { merged_tools: '["semgrep"]' });
    const incoming = base(200, { merged_tools: '["trivy","semgrep"]' });
    const out = resolveConflict('scan_findings', incoming, current);
    if (out.kind !== 'field-merge') throw new Error('expected field-merge');
    const tools = JSON.parse(String(out.merged.merged_tools));
    expect(tools).toContain('semgrep');
    expect(tools).toContain('trivy');
    expect(tools.length).toBe(2);
  });

  it('field-merges vulnerabilities.status with rank-max', () => {
    const current = base(100, { status: 'open' });
    const incoming = base(200, { status: 'confirmed' });
    const out = resolveConflict('vulnerabilities', incoming, current);
    if (out.kind !== 'field-merge') throw new Error('expected field-merge');
    expect(out.merged.status).toBe('confirmed');

    const other = resolveConflict('vulnerabilities',
      { ...base(200), status: 'open' },
      { ...base(100), status: 'accepted' });
    if (other.kind !== 'field-merge') throw new Error('expected field-merge');
    expect(other.merged.status).toBe('accepted');
  });

  it('field-merges checklist_items.checked with OR', () => {
    const current = base(100, { checked: 0 });
    const incoming = base(200, { checked: 1 });
    const out = resolveConflict('checklist_items', incoming, current);
    if (out.kind !== 'field-merge') throw new Error('expected field-merge');
    expect(out.merged.checked).toBe(1);
  });
});

describe('anonymizeForPool', () => {
  it('strips owner_user_id', () => {
    const r = anonymizeForPool('projects', { sync_id: 'X', owner_user_id: 42, name: 'proj' });
    expect(r).not.toHaveProperty('owner_user_id');
    expect(r.name).toBe('proj');
  });

  it('redacts URLs to scheme+host+path', () => {
    const r = anonymizeForPool('projects', {
      sync_id: 'X',
      repo_url: 'https://user:pass@github.com/a/b?token=secret#x',
    });
    expect(r.repo_url).toBe('https://github.com/a/b');
  });

  it('redacts paths to basename', () => {
    const r = anonymizeForPool('projects', {
      sync_id: 'X',
      path: '/Users/alice/secret/code/openssh',
    });
    expect(r.path).toBe('openssh');
  });

  it('no-op for tables not in POOL_ANONYMIZE', () => {
    const r = anonymizeForPool('checklists', { sync_id: 'X', foo: 'bar' });
    expect(r.foo).toBe('bar');
  });
});

describe('userCanSeeRow', () => {
  const row = (scope: 'private' | 'team' | 'pool', owner = 1): SyncableRow => ({
    sync_id: 'X', sync_scope: scope, owner_user_id: owner,
    updated_at_ms: 0, server_updated_at_ms: 0, tombstone: 0, sync_status: 'synced',
  });

  it('team rows visible to everyone', () => {
    expect(userCanSeeRow(row('team'), { user_id: 99, role: 'viewer' })).toBe(true);
  });

  it('private rows only visible to owner', () => {
    expect(userCanSeeRow(row('private', 1), { user_id: 1, role: 'admin' })).toBe(true);
    expect(userCanSeeRow(row('private', 1), { user_id: 2, role: 'admin' })).toBe(false);
  });

  it('pool rows not visible via regular sync', () => {
    expect(userCanSeeRow(row('pool'), { user_id: 1, role: 'admin' })).toBe(false);
  });
});

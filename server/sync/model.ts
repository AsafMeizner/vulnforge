/**
 * Sync model - single source of truth for multi-device sync behavior.
 *
 * Every cross-cutting decision about what syncs, how rows are tagged,
 * and how conflicts / pool anonymization work lives here as pure data.
 *
 * Keep SYNCABLE_TABLES in lockstep with SYNC_ENABLED_TABLES in server/db.ts.
 *
 * Design reference: docs/superpowers/specs/2026-04-16-deployment-topology-design.md
 */
import { ulid } from '../utils/ulid.js';

// ── Which tables participate in which sync category ─────────────────────────

/** Category A - rows have the 7 sync columns and can be pushed/pulled. */
export const SYNCABLE_TABLES = [
  'projects',
  'vulnerabilities',
  'scan_findings',
  'pipeline_runs',
  'notes',
  'session_state',
  'reports',
  'checklists',
  'checklist_items',
  'scans',
] as const;

export type SyncableTable = typeof SYNCABLE_TABLES[number];

/**
 * Category B - strictly per-machine. Never push, never pull, never expose
 * via the sync REST/WS endpoints even to an authenticated admin.
 * These hold local filesystem paths, API keys, refresh tokens, UI prefs, or
 * binaries that have no meaning on another machine.
 */
export const UNSYNCABLE_TABLES = [
  'plugins',                 // on-disk binaries / paths
  'notes_providers',         // holds vault paths, OAuth tokens
  'ai_providers',            // local API keys (Category C on server - see CAPABILITY_TABLES)
  'integrations',            // local OAuth tokens (Category C on server)
  'api_tokens',              // long-lived tokens for MCP clients
  'refresh_tokens',          // auth refresh tokens - NEVER leave the device they were issued to
  'sync_outbox',             // client-only outbox
  'sync_cursors',            // client-only per-table cursor state
  'audit_log',               // server-only; desktop writes go to local file
  'sandbox_snapshots',       // local VM/container state
] as const;

/**
 * Category C - exists on BOTH desktop and server with independent rows.
 * Server version is exposed to clients via the capability manifest
 * (names + capabilities only, never secrets). Clients invoke server-side
 * versions through the proxy endpoints.
 */
export const CAPABILITY_TABLES = ['ai_providers', 'integrations'] as const;

export function isSyncable(table: string): table is SyncableTable {
  return (SYNCABLE_TABLES as readonly string[]).includes(table);
}

export function isUnsyncable(table: string): boolean {
  return (UNSYNCABLE_TABLES as readonly string[]).includes(table);
}

export function isCapabilityTable(table: string): boolean {
  return (CAPABILITY_TABLES as readonly string[]).includes(table);
}

// ── Scope model ─────────────────────────────────────────────────────────────

export const SCOPE_VALUES = ['private', 'team', 'pool'] as const;
export type SyncScope = typeof SCOPE_VALUES[number];

export function isValidScope(v: unknown): v is SyncScope {
  return typeof v === 'string' && (SCOPE_VALUES as readonly string[]).includes(v);
}

// ── Sync status enum ────────────────────────────────────────────────────────

export const SYNC_STATUS_VALUES = ['local', 'pending', 'synced', 'conflict'] as const;
export type SyncStatus = typeof SYNC_STATUS_VALUES[number];

// ── Row shape (lowest common denominator) ───────────────────────────────────

/**
 * Minimal shape every syncable row satisfies. Concrete tables have many
 * more columns - this is just the sync contract.
 */
export interface SyncableRow {
  sync_id: string;
  sync_scope: SyncScope;
  owner_user_id: number | null;
  updated_at_ms: number;
  server_updated_at_ms: number | null;
  tombstone: 0 | 1;
  sync_status: SyncStatus;
  [otherColumns: string]: any;
}

// ── Helpers - stamping & filtering ──────────────────────────────────────────

/**
 * Prepare a row for a local write. Assigns a fresh sync_id if absent,
 * bumps updated_at_ms to now, and marks the row as pending push.
 */
export function stampForLocalWrite<T extends Partial<SyncableRow>>(
  row: T,
  defaults: { owner_user_id?: number | null; sync_scope?: SyncScope } = {},
): T & SyncableRow {
  const now = Date.now();
  return {
    ...row,
    sync_id: row.sync_id && row.sync_id.length ? row.sync_id : ulid(now),
    sync_scope: row.sync_scope ?? defaults.sync_scope ?? 'private',
    owner_user_id: row.owner_user_id ?? defaults.owner_user_id ?? null,
    updated_at_ms: now,
    server_updated_at_ms: row.server_updated_at_ms ?? null,
    tombstone: (row.tombstone ?? 0) as 0 | 1,
    sync_status: 'pending',
  } as T & SyncableRow;
}

/**
 * Called server-side when an incoming push is accepted.
 * Sets server_updated_at_ms to the server's monotonic clock and marks synced.
 */
export function stampForServerAccept<T extends Partial<SyncableRow>>(
  row: T,
  serverClockMs: number = Date.now(),
): T & SyncableRow {
  return {
    ...row,
    sync_id: row.sync_id || ulid(serverClockMs),
    sync_scope: row.sync_scope ?? 'private',
    owner_user_id: row.owner_user_id ?? null,
    updated_at_ms: row.updated_at_ms ?? serverClockMs,
    server_updated_at_ms: serverClockMs,
    tombstone: (row.tombstone ?? 0) as 0 | 1,
    sync_status: 'synced',
  } as T & SyncableRow;
}

/**
 * Called client-side when a server batch arrives. Flips sync_status to
 * 'synced' and adopts the server's clock as authoritative.
 */
export function stampForClientApply<T extends Partial<SyncableRow>>(
  row: T,
): T & SyncableRow {
  return {
    ...row,
    sync_id: row.sync_id!,
    sync_scope: row.sync_scope ?? 'private',
    owner_user_id: row.owner_user_id ?? null,
    updated_at_ms: row.updated_at_ms ?? row.server_updated_at_ms ?? Date.now(),
    server_updated_at_ms: row.server_updated_at_ms ?? null,
    tombstone: (row.tombstone ?? 0) as 0 | 1,
    sync_status: 'synced',
  } as T & SyncableRow;
}

/**
 * Mark a row tombstoned. Used for soft-delete; the row stays in the table
 * so the deletion propagates through sync, and is GC'd after 30 days.
 */
export function stampForTombstone<T extends Partial<SyncableRow>>(
  row: T,
): T & SyncableRow {
  return stampForLocalWrite({ ...row, tombstone: 1 as const });
}

// ── Conflict resolution ─────────────────────────────────────────────────────

export type ConflictOutcome =
  | { kind: 'accept-incoming'; row: SyncableRow }
  | { kind: 'reject'; current: SyncableRow }
  | { kind: 'field-merge'; merged: SyncableRow };

/**
 * Field-level merge whitelist - tables + columns where concurrent edits
 * compose instead of clobbering. Applied server-side BEFORE row-level LWW.
 *
 * Strategy per field:
 *   'concat'       - concatenate strings with '\n\n---\n\n' separator
 *   'status-max'   - keep the higher-ranked status
 *   'or-boolean'   - logical OR of 0/1 values
 *   'union-array'  - unique-union parsed JSON arrays
 */
export const FIELD_MERGE: Record<string, Record<string, 'concat' | 'status-max' | 'or-boolean' | 'union-array'>> = {
  scan_findings: {
    notes: 'concat',
    merged_tools: 'union-array',
  },
  vulnerabilities: {
    status: 'status-max',
  },
  checklist_items: {
    checked: 'or-boolean',
  },
};

const STATUS_RANK: Record<string, number> = {
  open: 0,
  triaging: 1,
  investigating: 2,
  verifying: 3,
  confirmed: 4,
  accepted: 5,
  disclosed: 6,
  resolved: 7,
  rejected: -1,
  false_positive: -1,
};

function mergeField(
  strategy: 'concat' | 'status-max' | 'or-boolean' | 'union-array',
  currentVal: any,
  incomingVal: any,
): any {
  if (currentVal == null) return incomingVal;
  if (incomingVal == null) return currentVal;
  switch (strategy) {
    case 'concat': {
      const a = String(currentVal);
      const b = String(incomingVal);
      return a.includes(b) ? a : `${a}\n\n---\n\n${b}`;
    }
    case 'status-max': {
      const ra = STATUS_RANK[String(currentVal)] ?? 0;
      const rb = STATUS_RANK[String(incomingVal)] ?? 0;
      return rb > ra ? incomingVal : currentVal;
    }
    case 'or-boolean':
      return Number(currentVal) || Number(incomingVal) ? 1 : 0;
    case 'union-array': {
      try {
        const a = Array.isArray(currentVal) ? currentVal : JSON.parse(currentVal || '[]');
        const b = Array.isArray(incomingVal) ? incomingVal : JSON.parse(incomingVal || '[]');
        const merged = Array.from(new Set([...a, ...b]));
        return typeof currentVal === 'string' ? JSON.stringify(merged) : merged;
      } catch {
        return currentVal;
      }
    }
  }
}

/**
 * Decide how to integrate an incoming push against a current row.
 * Callers use the outcome to produce an UPDATE statement or a conflict signal.
 */
export function resolveConflict(
  table: string,
  incoming: SyncableRow,
  current: SyncableRow | null,
): ConflictOutcome {
  if (!current) return { kind: 'accept-incoming', row: incoming };

  const incomingClock = incoming.updated_at_ms ?? 0;
  const currentServerClock = current.server_updated_at_ms ?? current.updated_at_ms ?? 0;

  const mergeableFields = FIELD_MERGE[table];

  if (mergeableFields) {
    // Build a merged row starting from the newer row.
    const base = incomingClock > currentServerClock ? incoming : current;
    const merged: SyncableRow = { ...base };
    for (const [field, strategy] of Object.entries(mergeableFields)) {
      merged[field] = mergeField(strategy, current[field], incoming[field]);
    }
    return { kind: 'field-merge', merged };
  }

  if (incomingClock > currentServerClock) {
    return { kind: 'accept-incoming', row: incoming };
  }

  return { kind: 'reject', current };
}

// ── Pool anonymization ──────────────────────────────────────────────────────

/**
 * Per-table anonymization rules applied before a `scope='pool'` row is
 * accepted into the shared pool dataset. Runs server-side on POST /api/pool/push.
 *
 * Each rule is either:
 *   'strip'          - delete the column entirely
 *   'redact-url'     - keep scheme + host + path, strip user/query/fragment
 *   'redact-path'    - keep basename only if it looks like OSS; else generic
 *   (fn)             - custom transform (value) => newValue
 */
export type AnonymizeAction =
  | 'strip'
  | 'redact-url'
  | 'redact-path'
  | ((v: any) => any);

export const POOL_ANONYMIZE: Record<string, Record<string, AnonymizeAction>> = {
  projects: {
    owner_user_id: 'strip',
    path: 'redact-path',
    repo_url: 'redact-url',
  },
  vulnerabilities: {
    owner_user_id: 'strip',
    advisory_url: 'redact-url',
    email_chain_url: 'strip',
    issue_url: 'redact-url',
    submit_email: 'strip',
  },
  scan_findings: {
    owner_user_id: 'strip',
    file: 'redact-path',
  },
  notes: {
    owner_user_id: 'strip',
  },
};

function redactUrl(raw: any): string | null {
  if (typeof raw !== 'string' || !raw) return null;
  try {
    const u = new URL(raw);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch { return null; }
}

function redactPath(raw: any): string {
  if (typeof raw !== 'string') return '';
  // Keep just the basename + extension; further locality stripped.
  const parts = raw.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || '';
}

/** Apply POOL_ANONYMIZE to a row. Returns a NEW row - never mutates. */
export function anonymizeForPool(table: string, row: Record<string, any>): Record<string, any> {
  const rules = POOL_ANONYMIZE[table];
  if (!rules) return { ...row };
  const out: Record<string, any> = { ...row };
  for (const [field, action] of Object.entries(rules)) {
    if (!(field in out)) continue;
    if (action === 'strip') {
      delete out[field];
    } else if (action === 'redact-url') {
      out[field] = redactUrl(out[field]);
    } else if (action === 'redact-path') {
      out[field] = redactPath(out[field]);
    } else if (typeof action === 'function') {
      out[field] = action(out[field]);
    }
  }
  return out;
}

// ── Transport filtering ─────────────────────────────────────────────────────

/**
 * Server-side filter: given a table + user context, which rows may flow
 * back out to this client. Applied in sync REST pull and WS batch streams.
 */
export function userCanSeeRow(
  row: SyncableRow,
  ctx: { user_id: number; role: string },
): boolean {
  switch (row.sync_scope) {
    case 'private':
      // Private rows only sync back to their owner on the SAME device.
      // In team mode, private rows never leave the device, so this is
      // effectively dead code server-side - but keep the check as defense
      // in depth in case a buggy client pushes a private row.
      return row.owner_user_id === ctx.user_id;
    case 'team':
      // All authenticated team members see all team rows.
      return true;
    case 'pool':
      // Pool rows are fetched via /api/pool/*, not via regular sync.
      return false;
    default:
      return false;
  }
}

/**
 * Which scope should never be pushed over the team-sync channel at all.
 * Private rows stay on-device; pool rows go through a dedicated endpoint.
 */
export function isTeamSyncScope(scope: SyncScope): boolean {
  return scope === 'team';
}

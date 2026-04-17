/**
 * Client-side sync engine - mirrors server/sync/repo.ts from the desktop's
 * perspective. Talks to the team server over WebSocket (primary) with REST
 * fallback.
 *
 * Shape:
 *   - Singleton `SyncClient` managed by React app shell.
 *   - On team-mode boot, calls .connect() with {serverUrl, accessToken}.
 *   - Outgoing writes append to the outbox; .flush() pushes the batch.
 *   - Incoming WS messages (sync:batch, sync:upsert, sync:delete, sync:conflict)
 *     fan out to registered table-level listeners.
 *   - Reconnect uses exponential backoff (1s → 30s).
 *
 * Persistence: outbox + cursors stored via localStorage. The actual row
 * data lives in the desktop's own SQLite - this engine only moves deltas
 * across the wire. Keeping it storage-agnostic means the same file works
 * in Electron renderer AND in a plain web build.
 */

// ── Types ───────────────────────────────────────────────────────────────────

export type SyncScope = 'private' | 'team' | 'pool';

export interface SyncableRow {
  sync_id: string;
  sync_scope: SyncScope;
  owner_user_id: number | null;
  updated_at_ms: number;
  server_updated_at_ms: number | null;
  tombstone: 0 | 1;
  sync_status: 'local' | 'pending' | 'synced' | 'conflict';
  [col: string]: any;
}

export interface CapabilityManifest {
  ai: Array<{ name: string; task_tags: string[]; provider_type: string; available: boolean }>;
  integrations: Array<{ name: string; type: string; actions: string[] }>;
  mode: 'server' | 'desktop';
}

export type TableName =
  | 'projects' | 'vulnerabilities' | 'scan_findings' | 'pipeline_runs'
  | 'notes' | 'session_state' | 'reports' | 'checklists'
  | 'checklist_items' | 'scans';

export interface OutboxEntry {
  id: string;
  table: TableName;
  row: Partial<SyncableRow>;
  attempts: number;
  last_error?: string;
  created_at: number;
}

export interface ConflictEvent {
  table: TableName;
  sync_id: string;
  current: SyncableRow;
}

export interface UpsertEvent { table: TableName; row: SyncableRow; }
export interface DeleteEvent { table: TableName; sync_id: string; }

type Listener<E> = (event: E) => void;

// ── Storage ─────────────────────────────────────────────────────────────────

interface Storage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

function defaultStorage(): Storage {
  if (typeof localStorage !== 'undefined') return localStorage;
  const fake = new Map<string, string>();
  return {
    getItem: (k) => fake.get(k) ?? null,
    setItem: (k, v) => { fake.set(k, v); },
    removeItem: (k) => { fake.delete(k); },
  };
}

const STORAGE_PREFIX = 'vulnforge.sync.';

// ── Connection state ────────────────────────────────────────────────────────

export type ConnectionStatus =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'backfilling'
  | 'live'
  | 'error';

// ── SyncClient ──────────────────────────────────────────────────────────────

export interface SyncClientOptions {
  serverUrl: string;
  accessToken: string;
  storage?: Storage;
  onStatusChange?: (s: ConnectionStatus) => void;
  onCapabilities?: (m: CapabilityManifest) => void;
  /** Called when a server delta arrives; desktop upserts the row locally. */
  onUpsert?: Listener<UpsertEvent>;
  onDelete?: Listener<DeleteEvent>;
  onConflict?: Listener<ConflictEvent>;
  /** Supplies cursors on connect. Caller reads from local SQLite. */
  getCursors: () => Record<string, number>;
  /** Called after each successful table batch so caller can bump its cursors. */
  onBatchApplied?: (table: TableName, rows: SyncableRow[], next_cursor: number) => void;
}

const BACKOFF_BASE_MS = 1000;
const BACKOFF_MAX_MS = 30000;

export class SyncClient {
  private ws: WebSocket | null = null;
  private readonly opts: SyncClientOptions;
  private status: ConnectionStatus = 'disconnected';
  private outbox: OutboxEntry[] = [];
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private stopped = false;
  private readonly storage: Storage;

  constructor(opts: SyncClientOptions) {
    this.opts = opts;
    this.storage = opts.storage ?? defaultStorage();
    this.outbox = this.loadOutbox();
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────

  connect(): void {
    if (this.stopped) return;
    if (this.ws && this.ws.readyState <= WebSocket.OPEN) return;
    this.setStatus('connecting');
    try {
      const base = this.opts.serverUrl.replace(/^http/, 'ws');
      const url = `${base.replace(/\/$/, '')}/sync?token=${encodeURIComponent(this.opts.accessToken)}`;
      this.ws = new WebSocket(url);
    } catch (e: any) {
      this.setStatus('error');
      this.scheduleReconnect();
      return;
    }
    this.ws.onopen = () => this.onOpen();
    this.ws.onmessage = (e: MessageEvent) => this.onMessage(e);
    this.ws.onclose = () => this.onClose();
    this.ws.onerror = () => this.setStatus('error');
  }

  disconnect(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    try { this.ws?.close(); } catch { /* noop */ }
    this.ws = null;
    this.setStatus('disconnected');
  }

  // ── Event handlers ───────────────────────────────────────────────────────

  private onOpen(): void {
    this.reconnectAttempts = 0;
    this.setStatus('connected');
    this.heartbeatTimer = setInterval(() => this.send({ type: 'ping' }), 30000);
    // Kick off backfill
    this.setStatus('backfilling');
    this.send({ type: 'sync:hello', cursors: this.opts.getCursors() });
    // Flush any queued outbox immediately
    this.flushOutbox();
  }

  private onClose(): void {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
    this.ws = null;
    if (this.stopped) { this.setStatus('disconnected'); return; }
    this.setStatus('disconnected');
    this.scheduleReconnect();
  }

  private onMessage(e: MessageEvent): void {
    let msg: any;
    try { msg = JSON.parse(String(e.data)); } catch { return; }
    if (!msg || typeof msg.type !== 'string') return;
    switch (msg.type) {
      case 'capabilities':
        this.opts.onCapabilities?.(msg as CapabilityManifest);
        break;
      case 'sync:batch':
        this.opts.onBatchApplied?.(msg.table, msg.rows ?? [], msg.next_cursor ?? 0);
        if (msg.done) {
          // Check whether all tables report done; switch to 'live' once so.
          // For simplicity we flip to live on any batch done=true - caller
          // that wants a tighter signal can inspect its own cursors.
          this.setStatus('live');
        }
        break;
      case 'sync:upsert':
        this.opts.onUpsert?.({ table: msg.table, row: msg.row });
        break;
      case 'sync:delete':
        this.opts.onDelete?.({ table: msg.table, sync_id: msg.sync_id });
        break;
      case 'sync:accept': {
        const ids: string[] = msg.sync_ids ?? [];
        this.removeFromOutbox(ids);
        break;
      }
      case 'sync:conflict':
        this.opts.onConflict?.({ table: msg.table, sync_id: msg.sync_id, current: msg.current });
        this.markOutboxConflict(msg.sync_id, 'server rejected');
        break;
      case 'pong':
        // heartbeat ack - nothing to do
        break;
      case 'error':
        console.warn('[sync] server error:', msg.error);
        break;
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    if (this.reconnectTimer) return;
    const delay = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * Math.pow(2, this.reconnectAttempts));
    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private send(msg: object): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    try { this.ws.send(JSON.stringify(msg)); return true; } catch { return false; }
  }

  private setStatus(s: ConnectionStatus): void {
    if (this.status === s) return;
    this.status = s;
    this.opts.onStatusChange?.(s);
  }

  getStatus(): ConnectionStatus { return this.status; }

  // ── Outbox API ───────────────────────────────────────────────────────────

  /** Queue a row for push. Caller should have already stamped it locally. */
  enqueue(table: TableName, row: Partial<SyncableRow>): void {
    if (!row.sync_id) throw new Error('enqueue: sync_id required');
    if (row.sync_scope !== 'team') return; // private + pool don't go through standard sync
    this.outbox.push({
      id: `${table}::${row.sync_id}`,
      table,
      row,
      attempts: 0,
      created_at: Date.now(),
    });
    this.saveOutbox();
    this.flushOutbox();
  }

  flushOutbox(): void {
    if (this.outbox.length === 0) return;
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    // Group by table, batch up to 500 each
    const byTable = new Map<TableName, OutboxEntry[]>();
    for (const e of this.outbox) {
      const list = byTable.get(e.table) ?? [];
      list.push(e);
      byTable.set(e.table, list);
    }
    for (const [table, entries] of byTable) {
      const rows = entries.slice(0, 500).map(e => ({ ...e.row }));
      const ok = this.send({ type: 'sync:push', table, rows });
      if (ok) {
        for (const e of entries.slice(0, 500)) e.attempts += 1;
        this.saveOutbox();
      }
    }
  }

  private removeFromOutbox(accepted: string[]): void {
    if (accepted.length === 0) return;
    const set = new Set(accepted);
    this.outbox = this.outbox.filter(e => !set.has(e.row.sync_id ?? ''));
    this.saveOutbox();
  }

  private markOutboxConflict(sync_id: string, why: string): void {
    for (const e of this.outbox) {
      if (e.row.sync_id === sync_id) { e.last_error = why; e.attempts += 1; }
    }
    this.saveOutbox();
  }

  private loadOutbox(): OutboxEntry[] {
    const raw = this.storage.getItem(STORAGE_PREFIX + 'outbox');
    if (!raw) return [];
    try { const v = JSON.parse(raw); return Array.isArray(v) ? v : []; }
    catch { return []; }
  }

  private saveOutbox(): void {
    this.storage.setItem(STORAGE_PREFIX + 'outbox', JSON.stringify(this.outbox));
  }

  /** For diagnostics UI. */
  getOutboxSize(): number { return this.outbox.length; }
  getOutboxErrors(): OutboxEntry[] { return this.outbox.filter(e => e.last_error); }
}

// ── REST fallback ───────────────────────────────────────────────────────────

export async function restPull(
  serverUrl: string,
  accessToken: string,
  table: TableName,
  since: number,
  limit = 200,
): Promise<{ rows: SyncableRow[]; next_cursor: number; done: boolean }> {
  const u = `${serverUrl.replace(/\/$/, '')}/api/sync/pull?table=${encodeURIComponent(table)}&since=${since}&limit=${limit}`;
  const resp = await fetch(u, { headers: { authorization: `Bearer ${accessToken}` } });
  if (!resp.ok) throw new Error(`pull ${resp.status}`);
  return await resp.json();
}

export async function restPush(
  serverUrl: string,
  accessToken: string,
  table: TableName,
  rows: Partial<SyncableRow>[],
): Promise<{ accepted: Array<{ sync_id: string }>; merged: Array<{ sync_id: string }>; rejected: Array<{ sync_id: string; current: SyncableRow }> }> {
  const u = `${serverUrl.replace(/\/$/, '')}/api/sync/push`;
  const resp = await fetch(u, {
    method: 'POST',
    headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ table, rows }),
  });
  if (!resp.ok) throw new Error(`push ${resp.status}`);
  return await resp.json();
}

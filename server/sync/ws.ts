/**
 * Sync WebSocket channel — live transport for team-mode deltas.
 *
 * Separate WS server at /sync (the existing /ws remains for pipeline
 * progress events). JWT access token carried in ?token=... query param
 * because browser WebSocket API cannot set request headers.
 *
 * Inbound messages (client → server):
 *   {type:'sync:hello', cursors:{table:ms, ...}}
 *   {type:'sync:push', table, rows}
 *   {type:'sync:ack', table, cursor}
 *   {type:'ping'}
 *
 * Outbound messages (server → client):
 *   {type:'capabilities', ai:[...], integrations:[...]}
 *   {type:'sync:batch', table, rows, next_cursor, done}
 *   {type:'sync:upsert', table, row}          (live broadcast)
 *   {type:'sync:delete', table, sync_id}      (live broadcast of tombstone)
 *   {type:'sync:accept', table, sync_ids: [...], server_updated_at_ms}
 *   {type:'sync:conflict', table, sync_id, current}
 *   {type:'pong', ts}
 *   {type:'error', error, code?}
 */
import { WebSocketServer, WebSocket } from 'ws';
import type { Server, IncomingMessage } from 'http';

import { verifyAccessToken, type AccessTokenClaims } from '../auth/jwt.js';
import { pullTable, pushRows } from './repo.js';
import { isSyncable, type SyncableTable } from './model.js';
import { getServerCapabilityManifest } from './capabilities.js';

interface AuthedWs extends WebSocket {
  user?: { user_id: number; role: string; device_id: string };
}

let syncWss: WebSocketServer | null = null;
const syncClients = new Set<AuthedWs>();

function extractToken(req: IncomingMessage): string | null {
  try {
    const url = new URL(req.url || '', 'http://localhost');
    const q = url.searchParams.get('token');
    if (q) return q;
    // Fallback: Sec-WebSocket-Protocol subprotocol
    const proto = req.headers['sec-websocket-protocol'];
    if (typeof proto === 'string' && proto.startsWith('bearer,')) {
      return proto.slice('bearer,'.length).trim();
    }
  } catch { /* fall through */ }
  return null;
}

export function getSyncWsServer(): WebSocketServer | null { return syncWss; }

export function initSyncWebSocket(server: Server): WebSocketServer {
  // noServer — server/index.ts dispatches /ws + /sync through one upgrade handler.
  syncWss = new WebSocketServer({ noServer: true });
  void server;

  syncWss.on('connection', async (ws: AuthedWs, req: IncomingMessage) => {
    const token = extractToken(req);
    if (!token) {
      ws.send(JSON.stringify({ type: 'error', error: 'missing token', code: 'NO_TOKEN' }));
      ws.close(4401, 'missing token');
      return;
    }
    const verify = verifyAccessToken(token);
    if (!verify.ok || !verify.claims) {
      ws.send(JSON.stringify({ type: 'error', error: `bad token: ${verify.error}`, code: 'BAD_TOKEN' }));
      ws.close(4401, 'bad token');
      return;
    }
    const claims = verify.claims as AccessTokenClaims;
    ws.user = { user_id: claims.sub, role: claims.role, device_id: claims.device_id };
    syncClients.add(ws);
    console.log(`[Sync WS] connected user=${claims.sub} device=${claims.device_id} (total ${syncClients.size})`);

    // Send capability manifest
    try {
      const manifest = getServerCapabilityManifest({ user_id: claims.sub, role: claims.role });
      ws.send(JSON.stringify({ type: 'capabilities', ...manifest }));
    } catch (e: any) {
      ws.send(JSON.stringify({ type: 'error', error: `manifest error: ${e.message}` }));
    }

    ws.on('message', async (data: Buffer) => {
      let msg: any;
      try { msg = JSON.parse(data.toString()); } catch { return; }
      if (!msg || typeof msg.type !== 'string' || !ws.user) return;

      try {
        switch (msg.type) {
          case 'ping':
            ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
            break;

          case 'sync:hello': {
            const cursors: Record<string, number> = msg.cursors || {};
            for (const [table, since] of Object.entries(cursors)) {
              if (!isSyncable(table)) continue;
              let cursor = Number(since) || 0;
              let done = false;
              // Stream in batches of 200 until caught up.
              while (!done) {
                const batch = pullTable({
                  table: table as SyncableTable,
                  since: cursor,
                  limit: 200,
                  user: { user_id: ws.user.user_id, role: ws.user.role },
                });
                ws.send(JSON.stringify({
                  type: 'sync:batch',
                  table,
                  rows: batch.rows,
                  next_cursor: batch.next_cursor,
                  done: batch.done,
                }));
                cursor = batch.next_cursor;
                done = batch.done;
                // Let the event loop breathe on big backlogs.
                await new Promise(r => setImmediate(r));
              }
            }
            break;
          }

          case 'sync:push': {
            const { table, rows } = msg;
            if (!isSyncable(table) || !Array.isArray(rows)) {
              ws.send(JSON.stringify({ type: 'error', error: 'invalid push', code: 'BAD_PUSH' }));
              break;
            }
            const outcome = pushRows({
              table,
              rows,
              user: { user_id: ws.user.user_id, role: ws.user.role },
            });
            // ACK to submitter
            ws.send(JSON.stringify({
              type: 'sync:accept',
              table,
              sync_ids: [...outcome.accepted, ...outcome.merged].map(r => r.sync_id),
              server_updated_at_ms: Date.now(),
            }));
            for (const conflict of outcome.rejected) {
              ws.send(JSON.stringify({
                type: 'sync:conflict',
                table,
                sync_id: conflict.sync_id,
                current: conflict.current,
              }));
            }
            // Broadcast to OTHER clients
            const accepted = [...outcome.accepted, ...outcome.merged].map(r => r.sync_id);
            if (accepted.length > 0) {
              broadcastSyncDelta(table, accepted, rows, ws);
            }
            break;
          }

          case 'sync:ack':
            // Client acknowledging a batch. No-op server-side for now.
            break;

          default:
            ws.send(JSON.stringify({ type: 'error', error: `unknown type: ${msg.type}` }));
        }
      } catch (err: any) {
        ws.send(JSON.stringify({ type: 'error', error: err.message }));
      }
    });

    ws.on('close', () => {
      syncClients.delete(ws);
      console.log(`[Sync WS] disconnected (remaining ${syncClients.size})`);
    });
    ws.on('error', (err: Error) => {
      console.error('[Sync WS] client error:', err.message);
      syncClients.delete(ws);
    });
  });

  syncWss.on('error', (err: Error) => {
    console.error('[Sync WS] server error:', err.message);
  });

  return syncWss;
}

/** Broadcast sync upserts (or tombstone deletes) to all connected clients except the origin. */
export function broadcastSyncDelta(
  table: string,
  acceptedSyncIds: string[],
  originalRows: Array<Partial<{ sync_id: string; tombstone: number }>>,
  exclude?: AuthedWs,
): void {
  const accepted = new Set(acceptedSyncIds);
  for (const row of originalRows) {
    if (!row.sync_id || !accepted.has(row.sync_id)) continue;
    const msgType = row.tombstone === 1 ? 'sync:delete' : 'sync:upsert';
    const payload = msgType === 'sync:delete'
      ? { type: msgType, table, sync_id: row.sync_id }
      : { type: msgType, table, row };
    const str = JSON.stringify(payload);
    for (const client of syncClients) {
      if (client === exclude) continue;
      if (client.readyState !== WebSocket.OPEN) continue;
      try { client.send(str); } catch { /* best-effort */ }
    }
  }
}

/** Exposed for REST push to echo into the WS fabric. */
export function broadcastServerSideWrite(
  table: string,
  row: Partial<{ sync_id: string; tombstone: number }> & Record<string, any>,
): void {
  if (!row.sync_id) return;
  broadcastSyncDelta(table, [row.sync_id], [row]);
}

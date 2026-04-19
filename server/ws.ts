import { WebSocketServer, WebSocket } from 'ws';
import type { IncomingMessage, Server } from 'http';
import { verifyAccessToken } from './auth/jwt.js';

let wss: WebSocketServer | null = null;

/**
 * Per-connection metadata. Attached to each WebSocket on connect so
 * ownership checks in the subscribe handler don't need to re-parse the
 * upgrade request.
 */
interface WsMeta {
  /** JWT-authenticated user id. null = unauthenticated desktop connection. */
  user_id: number | null;
  /** Role, if known (admin/editor/viewer/etc). */
  role: string | null;
  /** Whether the process is in desktop mode - allows bypass of ownership checks. */
  desktop: boolean;
}

const wsMeta = new WeakMap<WebSocket, WsMeta>();

// All connected clients
const clients = new Set<WebSocket>();

// Per-job subscription map: jobId → set of subscribed WebSocket connections
const subscriptions = new Map<string, Set<WebSocket>>();

// ── Init ───────────────────────────────────────────────────────────────────

export function initWebSocket(server: Server): WebSocketServer {
  // noServer: true so we don't fight server/sync/ws.ts over /sync upgrades.
  // server/index.ts dispatches /ws + /sync through a single upgrade handler.
  wss = new WebSocketServer({ noServer: true });
  void server; // signature kept for backward compatibility

  wss.on('connection', (ws: WebSocket, req?: IncomingMessage) => {
    clients.add(ws);
    wsMeta.set(ws, extractAuth(req));
    console.log(`[WS] Client connected (total: ${clients.size})`);

    ws.send(JSON.stringify({ type: 'connected', message: 'VulnForge WS ready' }));

    ws.on('close', () => {
      clients.delete(ws);
      wsMeta.delete(ws);
      // Remove from all job subscriptions
      for (const [jobId, subs] of subscriptions.entries()) {
        subs.delete(ws);
        if (subs.size === 0) subscriptions.delete(jobId);
      }
      console.log(`[WS] Client disconnected (total: ${clients.size})`);
    });

    ws.on('error', (err: Error) => {
      console.error('[WS] Client error:', err.message);
      clients.delete(ws);
      wsMeta.delete(ws);
    });

    ws.on('message', (data: Buffer) => {
      try {
        const msg = JSON.parse(data.toString());

        switch (msg.type) {
          case 'ping':
            ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
            break;

          case 'subscribe': {
            // Client subscribes to output for a specific job
            // Message: { type: 'subscribe', jobId: string }
            const { jobId } = msg;
            if (typeof jobId !== 'string' || !jobId) break;

            // CR-audit ownership gate: in server mode a logged-in user
            // can enumerate predictable jobIds and subscribe to other
            // users' pipeline progress. Look the job up; require read
            // permission before attaching to its subscriber set.
            // Desktop mode bypasses (solo user = owner).
            const meta = wsMeta.get(ws);
            const allowed = meta?.desktop
              ? true
              : canSubscribeToJob(jobId, meta ?? null);
            if (!allowed) {
              ws.send(JSON.stringify({
                type: 'subscribe_denied',
                jobId,
                reason: 'forbidden',
              }));
              break;
            }

            if (!subscriptions.has(jobId)) {
              subscriptions.set(jobId, new Set());
            }
            subscriptions.get(jobId)!.add(ws);
            ws.send(JSON.stringify({ type: 'subscribed', jobId }));
            break;
          }

          case 'unsubscribe': {
            const { jobId } = msg;
            if (typeof jobId === 'string') {
              subscriptions.get(jobId)?.delete(ws);
            }
            break;
          }

          default:
            // Ignore unknown message types
            break;
        }
      } catch {
        // Ignore malformed messages
      }
    });
  });

  wss.on('error', (err: Error) => {
    console.error('[WS] Server error:', err.message);
  });

  return wss;
}

// ── Authentication extraction ──────────────────────────────────────────────

/**
 * Pull whatever identity signal we can off the upgrade request. Prefers
 * the Authorization header (standard bearer), falls back to an
 * `?access_token=` query param (for browsers that can't set auth headers
 * on WebSocket upgrades). Desktop mode is detected via the parent
 * server's own mode helper; the flag is read once here and trusted for
 * the lifetime of the connection so the fast-path stays synchronous.
 */
function extractAuth(req?: IncomingMessage): WsMeta {
  const desktop = process.env.VULNFORGE_MODE === 'desktop'
    || (process.versions as any).electron !== undefined
    || process.env.ELECTRON_RUN_AS_NODE === '1';

  if (!req) return { user_id: null, role: null, desktop };

  // Try Authorization header first.
  let token: string | null = null;
  const hdr = req.headers['authorization'];
  if (typeof hdr === 'string' && hdr.startsWith('Bearer ')) {
    token = hdr.slice(7).trim();
  }
  // Fall back to ?access_token= on the upgrade URL.
  if (!token && req.url) {
    try {
      const u = new URL(req.url, 'http://localhost');
      const qp = u.searchParams.get('access_token');
      if (qp) token = qp;
    } catch {
      /* malformed URL - treat as no token */
    }
  }

  if (!token) return { user_id: null, role: null, desktop };
  const r = verifyAccessToken(token);
  if (r.ok && r.claims) {
    return { user_id: r.claims.sub, role: r.claims.role, desktop };
  }
  return { user_id: null, role: null, desktop };
}

/**
 * Can this (possibly-anonymous) WS client subscribe to this job?
 * We only know about pipeline_runs today; treat anything else as
 * allowed (plugin installs, etc. are non-user-sensitive) unless we
 * find a row with an explicit owner.
 *
 * Synchronous, uses the sync DB handle so we don't have to plumb async
 * through the ws.on('message') handler.
 */
function canSubscribeToJob(jobId: string, meta: WsMeta | null): boolean {
  if (!meta || meta.user_id === null) {
    // Anonymous connections in server mode may only subscribe to
    // global categories (plugin install, system events). Those use
    // non-pipeline ids so we just refuse anything that looks like a
    // ULID/uuid (pipeline_runs use ULIDs).
    return !/^[0-9A-HJKMNP-TV-Z]{26}$/i.test(jobId);
  }
  // Admins see everything.
  if (meta.role === 'admin') return true;

  try {
    // Lazy require the DB so test environments that don't initialize
    // sql.js still pass the module load.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { getPipelineRun } = require('./db.js');
    const run = getPipelineRun?.(jobId);
    if (!run) {
      // Non-pipeline job - allow. We don't have per-job ACLs for
      // plugin-install et al, and those aren't user-sensitive.
      return true;
    }
    // Pipeline rows carry owner_user_id. Allow if it matches or is null.
    if (!run.owner_user_id) return true;
    return Number(run.owner_user_id) === meta.user_id;
  } catch {
    // If we can't resolve the owner, fail closed in server mode.
    return false;
  }
}

// ── Broadcast helpers ──────────────────────────────────────────────────────

/** Send a message to every connected client. */
export function getWsServer(): WebSocketServer | null { return wss; }

export function broadcast(msg: object): void {
  const payload = JSON.stringify(msg);
  for (const ws of clients) {
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(payload);
      }
    } catch {
      clients.delete(ws);
    }
  }
}

/**
 * Send a message only to clients subscribed to the given jobId.
 *
 * Security CR-13: no-subscriber fallback removed. Previously, if
 * nothing was subscribed to a job, we broadcast the event to EVERY
 * connected client - which leaked per-job details (project id, file
 * names, finding ids, error text) to clients that never asked for
 * them, including cross-origin listeners. If a client wants an event
 * for a job, it must explicitly subscribe.
 */
export function broadcastToJob(jobId: string, msg: object): void {
  const subs = subscriptions.get(jobId);
  if (!subs || subs.size === 0) return;

  const payload = JSON.stringify(msg);
  for (const ws of subs) {
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(payload);
      } else {
        subs.delete(ws);
      }
    } catch {
      subs.delete(ws);
      clients.delete(ws);
    }
  }
}

/**
 * Broadcast a progress update for plugin installs, scans, or AI operations.
 *
 * `scope`:
 *   - 'job'    - route through broadcastToJob(id). Only subscribers
 *                see the event. Use for user-owned jobs (pipeline_runs,
 *                scan_findings belonging to a pipeline, etc.) - the
 *                scope prevents cross-user info leak when many users
 *                share one server.
 *   - 'global' - fan out to every connected client. Use for
 *                system-wide events (plugin install progress, CVE sync
 *                heartbeat) where the payload is not user-sensitive.
 *
 * Default is 'global' for backwards compatibility with the original
 * callers (plugin manager, scan queue). The pipeline orchestrator
 * passes `scope: 'job'` explicitly to restrict per-run events.
 */
export function broadcastProgress(
  category: string,
  id: string,
  data: {
    step: string;
    detail?: string;
    progress?: number;  // 0-100
    status?: 'running' | 'complete' | 'error';
  },
  opts: { scope?: 'job' | 'global' } = {},
): void {
  const msg = {
    type: 'progress',
    category,
    id,
    ...data,
    timestamp: new Date().toISOString(),
  };
  if (opts.scope === 'job') {
    broadcastToJob(id, msg);
  } else {
    broadcast(msg);
  }
}

// ── Accessors ──────────────────────────────────────────────────────────────

export function getWsClients(): Set<WebSocket> {
  return clients;
}

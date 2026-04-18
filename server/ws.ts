import { WebSocketServer, WebSocket } from 'ws';
import type { Server } from 'http';

let wss: WebSocketServer | null = null;

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

  wss.on('connection', (ws: WebSocket) => {
    clients.add(ws);
    console.log(`[WS] Client connected (total: ${clients.size})`);

    ws.send(JSON.stringify({ type: 'connected', message: 'VulnForge WS ready' }));

    ws.on('close', () => {
      clients.delete(ws);
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
            if (typeof jobId === 'string' && jobId) {
              if (!subscriptions.has(jobId)) {
                subscriptions.set(jobId, new Set());
              }
              subscriptions.get(jobId)!.add(ws);
              ws.send(JSON.stringify({ type: 'subscribed', jobId }));
            }
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
 */
export function broadcastProgress(category: string, id: string, data: {
  step: string;
  detail?: string;
  progress?: number;  // 0-100
  status?: 'running' | 'complete' | 'error';
}): void {
  broadcast({
    type: 'progress',
    category,
    id,
    ...data,
    timestamp: new Date().toISOString(),
  });
}

// ── Accessors ──────────────────────────────────────────────────────────────

export function getWsClients(): Set<WebSocket> {
  return clients;
}

export function getWss(): WebSocketServer | null {
  return wss;
}

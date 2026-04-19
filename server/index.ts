import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { fileURLToPath } from 'url';
import path from 'path';
import { writeFileSync } from 'fs';

import { initDb } from './db.js';
import { initWebSocket, getWsServer } from './ws.js';
import { initSyncWebSocket, getSyncWsServer } from './sync/ws.js';

// Routes
import vulnerabilitiesRouter from './routes/vulnerabilities.js';
import projectsRouter from './routes/projects.js';
import scansRouter from './routes/scans.js';
import toolsRouter from './routes/tools.js';
import statsRouter from './routes/stats.js';
import pluginsRouter from './routes/plugins.js';
import checklistsRouter from './routes/checklists.js';

// Reports
import reportsRouter from './routes/reports.js';
import scanFindingsRouter from './routes/scan-findings.js';

// Pipeline
import pipelineRouter from './routes/pipeline.js';

// Research Workspace (Theme 1)
import notesRouter from './routes/notes.js';
import sessionRouter from './routes/session.js';

// Runtime Analysis (Theme 3)
import runtimeRouter from './routes/runtime.js';

// Historical Intelligence (Theme 4)
import historyRouter from './routes/history.js';

// Exploit Development (Theme 2)
import exploitsRouter from './routes/exploits.js';

// AI Copilot Upgrade (Theme 8)
import aiInvestigateRouter from './routes/ai-investigate.js';

// Parasoft-inspired AI workflows (Track P)
import aiWorkflowRouter from './routes/ai-workflow.js';

// Auth + RBAC (Phase 14)
import authRouter from './routes/auth.js';
import authSessionRouter from './routes/auth-session.js';
import authOidcRouter from './routes/auth-oidc.js';
import syncRouter from './routes/sync.js';
import serverProxyRouter from './routes/server-proxy.js';
import jobsRouter from './routes/jobs.js';
import poolRouter from './routes/pool.js';
import { startWorkerPool } from './workers/pool.js';
import { authMiddleware } from './auth/auth.js';

// Teach Mode + Pattern Mining (Phase 15)
import teachRouter from './routes/teach.js';

// External Service Integrations
import integrationsRouter from './routes/integrations.js';

// Disclosure & Bounty Ops (Theme 5)
import disclosureRouter from './routes/disclosure.js';

// Export + Audit (Themes 7+9)
import exportRouter from './routes/export.js';
import systemRouter from './routes/system.js';

// AI routes (moved out of server/index.ts inline definitions)
import aiRouter from './routes/ai.js';

// MCP
import { setupMcpServer } from './mcp/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// VULNFORGE_PORT takes precedence over PORT (matches docker-compose + install scripts).
const PORT = process.env.VULNFORGE_PORT
  ? parseInt(process.env.VULNFORGE_PORT)
  : process.env.PORT
  ? parseInt(process.env.PORT)
  : 3001;
const HEADLESS = process.env.VULNFORGE_HEADLESS === '1' || process.argv.includes('--headless');

/**
 * Redact sensitive query-string params from a URL before logging it.
 * OIDC `code` + `state`, password-reset `token`, API-key-in-query
 * `key` + `api_key` + `secret` are all known-secret names that
 * callers sometimes put in the URL. Request bodies are never logged,
 * but the URL travels through the error wrapper + any reverse proxy.
 */
function redactSensitiveQuery(url: string): string {
  if (!url || !url.includes('?')) return url;
  try {
    const u = new URL(url, 'http://_unused');
    const REDACT = new Set(['code', 'state', 'id_token', 'access_token', 'token', 'key', 'api_key', 'secret', 'password']);
    for (const k of Array.from(u.searchParams.keys())) {
      if (REDACT.has(k.toLowerCase())) {
        u.searchParams.set(k, '[redacted]');
      }
    }
    return u.pathname + (u.search || '');
  } catch {
    // Malformed URL - drop the query string entirely.
    return url.split('?')[0] + '?[unparseable]';
  }
}

async function main(): Promise<void> {
  // Init database
  console.log('[DB] Initializing SQLite database...');
  await initDb();
  console.log('[DB] Database ready');

  // Boot-time reconciliation: any pipeline_runs row still in a
  // non-terminal status was orphaned by a previous crash/restart (the
  // worker only lives in memory). Flip them to failed so the UI stops
  // polling ghosts and users can start fresh runs on the same project.
  try {
    const { reconcileOrphanPipelines } = await import('./pipeline/orchestrator.js');
    reconcileOrphanPipelines();
  } catch (err: any) {
    console.warn('[Pipeline] reconcileOrphanPipelines failed:', err.message);
  }

  // Load routing rules from database
  try {
    const { initRoutingFromDb } = await import('./ai/routing.js');
    await initRoutingFromDb();
  } catch (err: any) {
    console.warn('[Routing] Failed to init routing from DB:', err.message);
  }

  // Load checklist definitions from JSON files on first run
  try {
    const { loadAllChecklists } = await import('./checklists/loader.js');
    const inserted = await loadAllChecklists();
    if (inserted > 0) {
      console.log(`[Checklists] Loaded ${inserted} new checklist(s) from /checklists/`);
    }
  } catch (err: any) {
    console.warn('[Checklists] Failed to load checklists on startup:', err.message);
  }

  // Auto-register the 10 built-in plugin integrations on first boot so a
  // fresh user sees them on the Plugins page instead of an empty list.
  // They land as `enabled=1` (the backend will still gate each run on
  // whether the binary/package is actually installed on the host).
  try {
    const { getAllPlugins, createPlugin } = await import('./db.js');
    const installed = getAllPlugins();
    if (installed.length === 0) {
      const { PLUGIN_CATALOG } = await import('./plugins/registry.js');
      for (const entry of PLUGIN_CATALOG) {
        try {
          createPlugin({
            name: entry.name,
            type: entry.type,
            source_url: entry.source_url,
            version: entry.version,
            manifest: JSON.stringify(entry),
            enabled: 1,
          } as any);
        } catch {
          /* skip duplicates */
        }
      }
      console.log(
        `[Plugins] Auto-registered ${PLUGIN_CATALOG.length} built-in plugin(s). ` +
        `Enable/disable from the Plugins page; each will still be gated on ` +
        `whether its binary is available.`
      );
    }
  } catch (err: any) {
    console.warn('[Plugins] Auto-register failed:', err.message);
  }

  // Auto-seed tools on first boot if the tools table is empty AND
  // VULNFORGE_TOOLS_DIR (or its default) points at an existing directory.
  // Without this, a fresh install shows an empty Tools page with no hint
  // that the user needs to configure a scanner directory.
  try {
    const { getAllTools, upsertTool } = await import('./db.js');
    const existingTools = getAllTools();
    if (existingTools.length === 0) {
      const fs = await import('fs');
      // Default to ./tools relative to the process cwd. An earlier
      // release had a drive-letter hardcoded here that only worked
      // on the original dev's machine; the empty-table hint still
      // referenced it. Replaced with a portable default.
      const pathMod = await import('path');
      const toolsDir =
        process.env.VULNFORGE_TOOLS_DIR || pathMod.join(process.cwd(), 'tools');
      if (fs.existsSync(toolsDir)) {
        const files = fs
          .readdirSync(toolsDir)
          .filter((f) => f.endsWith('.py') && !f.startsWith('_'));
        if (files.length > 0) {
          for (const file of files) {
            const name = file.replace(/\.py$/, '');
            try {
              const body = fs.readFileSync(
                `${toolsDir}/${file}`,
                'utf8'
              );
              const docMatch = body.match(/"""([\s\S]*?)"""/);
              const doc = (docMatch?.[1] || '').trim();
              const firstLine = doc.split('\n')[0]?.trim() || '';
              upsertTool({
                name,
                path: `${toolsDir}/${file}`,
                description: firstLine || `${name} analyzer`,
                docs: doc || undefined,
                category: 'static',
                enabled: 1,
              } as any);
            } catch {
              /* skip unreadable */
            }
          }
          console.log(`[Tools] Auto-seeded ${files.length} tool(s) from ${toolsDir}`);
        }
      } else {
        console.log(
          `[Tools] Tools table is empty and ${toolsDir} does not exist. ` +
          `Set VULNFORGE_TOOLS_DIR env var to point at your scanner directory.`
        );
      }
    }
  } catch (err: any) {
    console.warn('[Tools] Auto-seed failed:', err.message);
  }

  // Express app
  const app = express();

  // ── Middleware ────────────────────────────────────────────────────────
  // CORS: explicit allowlist required. Wildcard `*` is REFUSED when
  // `credentials: true` because that combination echoes back whatever
  // Origin the client sends AND carries cookies/auth - which is a CSRF
  // vector (any malicious page can talk to the API with the user's
  // credentials). We take the strict-secure-default approach:
  //
  //   - no env set         -> DEFAULT_ORIGINS below (loopback dev only)
  //   - env is a comma list -> that list wins
  //   - env is literal `*`  -> refuse in any mode; log and clamp to defaults
  //
  // If you truly need a wildcard (e.g. a local proxy), drop
  // `credentials: true` explicitly and add a separate allowlist.
  const DEFAULT_ORIGINS = [
    'http://localhost:5173',
    'http://localhost:3000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:3000',
    // Electron renderer. Desktop-mode callers only; server mode binds
    // to 0.0.0.0 so there is no `app://` renderer hitting it.
    'app://vulnforge',
  ];
  let corsOrigins: string[];
  const envCors = process.env.VULNFORGE_CORS_ORIGIN?.trim();
  if (!envCors) {
    corsOrigins = DEFAULT_ORIGINS;
  } else if (envCors === '*') {
    console.warn(
      '[cors] refusing VULNFORGE_CORS_ORIGIN=* with credentials: true ' +
      '(CSRF risk). Falling back to default loopback allowlist. ' +
      'Set an explicit comma-separated origin list instead.',
    );
    corsOrigins = DEFAULT_ORIGINS;
  } else {
    corsOrigins = envCors.split(',').map(s => s.trim()).filter(Boolean);
  }
  app.use(cors({
    origin: corsOrigins,
    credentials: true,
  }));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Request logging
  app.use((req, _res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
  });

  // ── Auth routes (BEFORE middleware - they handle their own auth) ────
  app.use('/api/auth', authRouter);
  // Subsystem B - JWT session flow (coexists with legacy API-token auth above)
  app.use('/api/session', authSessionRouter);
  app.use('/api/auth/oidc', authOidcRouter);

  // Install the DB-backed RBAC checker once db is ready.
  try {
    const { installPermissionChecker } = await import('./auth/permissions.js');
    const { hasPermissionInDb } = await import('./db.js');
    installPermissionChecker(hasPermissionInDb);
  } catch (e) {
    console.warn('[auth] RBAC checker install failed:', e);
  }

  // Health check + config (no auth needed)
  app.get('/api/health', (_req, res) => res.json({ status: 'ok', uptime: process.uptime() }));
  app.get('/api/config', (_req, res) => res.json({
    version: '1.0.0',
    mode: HEADLESS ? 'headless' : 'full',
    features: {
      auth: true,
      mcp: true,
      websocket: true,
      sandbox: true,
      integrations: true,
    },
  }));

  // Apply auth middleware to ALL /api/* routes EXCEPT /api/auth
  app.use('/api', authMiddleware as any);

  // Global default: viewers are read-only across the whole API surface.
  // Individual routers can still call assertPermission() for finer
  // rules (editor vs admin on specific resources), but this catch-all
  // closes the audit finding that ~21 write routers never checked
  // RBAC at all. Safe methods pass; anything else for viewer-role
  // returns 403 immediately.
  //
  // Desktop mode (solo user = admin) is unaffected because the
  // synthetic `local` user is already 'admin'.
  app.use('/api', (req: any, res: any, next: any) => {
    if (!req.user) return next();
    const safeMethod = req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS';
    if (safeMethod) return next();
    if (req.user.role === 'viewer') {
      res.status(403).json({
        error: 'forbidden',
        reason: 'viewer role has read-only access',
        method: req.method,
        path: req.path,
      });
      return;
    }
    return next();
  });

  // ── API Routes (all protected by auth middleware above) ──────────────
  app.use('/api/vulnerabilities', vulnerabilitiesRouter);
  app.use('/api/projects', projectsRouter);
  app.use('/api/scans', scansRouter);
  app.use('/api/tools', toolsRouter);
  app.use('/api/stats', statsRouter);
  app.use('/api/plugins', pluginsRouter);
  app.use('/api/checklists', checklistsRouter);
  app.use('/api/reports', reportsRouter);
  app.use('/api/scan-findings', scanFindingsRouter);
  app.use('/api/pipeline', pipelineRouter);
  app.use('/api/notes', notesRouter);
  app.use('/api/session', sessionRouter);
  app.use('/api/runtime', runtimeRouter);
  app.use('/api/history', historyRouter);
  app.use('/api/exploits', exploitsRouter);
  app.use('/api/ai-investigate', aiInvestigateRouter);
  app.use('/api/ai-workflow', aiWorkflowRouter);
  app.use('/api/teach', teachRouter);
  app.use('/api/integrations', integrationsRouter);
  app.use('/api/disclosure', disclosureRouter);
  app.use('/api/sync', syncRouter);
  app.use('/api/server', serverProxyRouter);
  app.use('/api/jobs', jobsRouter);
  app.use('/api/system', systemRouter);
  app.use('/api/pool', poolRouter);

  // Start the worker pool - no-op in desktop mode.
  try { startWorkerPool(); } catch (e: any) {
    console.warn('[pool] startup failed:', e.message);
  }
  app.use('/api/export', exportRouter);

  // Runtime executors init (after DB ready)
  try {
    const { runtimeJobRunner } = await import('./pipeline/runtime/job-runner.js');
    await runtimeJobRunner.registerAllExecutors();
    console.log('[Runtime] Job runner ready');
  } catch (err: any) {
    console.warn('[Runtime] Failed to init runner:', err.message);
  }

  // /api/ai/* routes - moved out of this file in the post-CR-14 cleanup.
  // The new router applies: permission gates (viewer can't write),
  // CR-14 prompt-injection fences on every system prompt + interpolated
  // field, mass-assignment allowlist on provider CRUD, agent max_steps
  // clamp, and the CR-11 error wrapper via next(err).
  // (Former inline block removed - see server/routes/ai.ts)
  app.use('/api/ai', aiRouter);


  // CR-11: global error-wrapper. Handlers that either throw or call
  // `next(err)` now funnel through here instead of each one calling
  // `res.status(500).json({ error: err.message })` and leaking SQL
  // messages, file paths, stack frames, etc. to the client.
  //
  // Development mode keeps full detail to debug locally; production
  // returns a generic message + request id. `req.requestId` is
  // stamped by the dev middleware above (if present) or generated
  // here as a fallback.
  app.use((err: any, req: any, res: any, _next: any) => {
    const requestId = req.requestId
      || `rq-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const status = Number(err?.status) >= 400 && Number(err?.status) < 600
      ? Number(err.status)
      : 500;
    const isProd = process.env.NODE_ENV === 'production';
    // Redact known-secret query params before logging. OIDC callback
    // URLs carry `code` + `state` which are single-use but still
    // secret within the ~10-minute TTL; password-reset flows carry
    // `token`; API-key-in-URL style endpoints carry `key`. Dropping
    // those before the console.error keeps them out of logs,
    // journalctl, and any log-aggregator pipeline behind the server.
    const safeUrl = redactSensitiveQuery(req.originalUrl || req.url || '');
    console.error(`[err ${requestId}]`, req.method, safeUrl, err?.stack || err);
    if (res.headersSent) return;
    if (isProd) {
      res.status(status).json({ error: 'Internal server error', request_id: requestId });
    } else {
      res.status(status).json({
        error: err?.message || 'Internal server error',
        request_id: requestId,
        ...(err?.stack ? { stack: String(err.stack).split('\n').slice(0, 8) } : {}),
      });
    }
  });

  // ── HTTP server ───────────────────────────────────────────────────────
  const server = createServer(app);

  // ── WebSocket ─────────────────────────────────────────────────────────
  initWebSocket(server);
  initSyncWebSocket(server);

  // Single upgrade-handler dispatches by path - avoids the ws library's
  // "first WSS grabs every upgrade" conflict when two WSS instances share
  // one HTTP server.
  server.on('upgrade', (req, socket, head) => {
    const { pathname } = new URL(req.url || '', 'http://localhost');
    const wss = pathname === '/ws' ? getWsServer()
              : pathname === '/sync' ? getSyncWsServer()
              : null;
    if (!wss) {
      socket.destroy();
      return;
    }
    // CR-13: reject cross-origin upgrades. Browsers send Origin on
    // the upgrade request; a missing / mismatching origin means it's
    // either a non-browser client (acceptable - we auth below via
    // query token) or a cross-origin browser page trying to tap
    // somebody else's VulnForge over the LAN.
    const origin = req.headers.origin;
    if (origin) {
      const envAllow = (process.env.VULNFORGE_CORS_ORIGIN || '').split(',')
        .map((s) => s.trim()).filter(Boolean);
      const allow = envAllow.length && !envAllow.includes('*')
        ? new Set(envAllow)
        : new Set<string>([
          'http://localhost:5173', 'http://localhost:3000',
          'http://127.0.0.1:5173', 'http://127.0.0.1:3000',
          'app://vulnforge',  // Electron custom protocol
        ]);
      if (!envAllow.includes('*') && !allow.has(origin)) {
        console.warn(`[WS] refusing upgrade from origin ${origin}`);
        socket.destroy();
        return;
      }
    }
    wss.handleUpgrade(req, socket as any, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  });
  console.log('[WS] Upgrade dispatcher registered for /ws + /sync');
  console.log('[WS] WebSocket server initialized at /ws');

  // ── MCP server via SSE at /mcp ────────────────────────────────────────
  // Security CR-03: gate /mcp behind the same authMiddleware as /api.
  // MCP exposes 101 DB-mutating tools (create_vulnerability,
  // start_pipeline, run_tool, set_ai_routing, etc.). Previously it
  // was registered outside /api so every request reached it anonymously,
  // which combined with CR-05 (command injection via run_tool) meant
  // remote code execution.
  app.use('/mcp', authMiddleware as any);
  setupMcpServer(app);
  console.log('[MCP] MCP server initialized at /mcp (auth-gated)');

  // ── Start ─────────────────────────────────────────────────────────────
  // Security CR-07: default to loopback. Binding 0.0.0.0 exposes every
  // network interface, which combined with the historical "empty users
  // table = admin" shortcut (CR-02) meant anyone on the LAN could POST
  // as admin. Teams that actually want a shared server set
  // VULNFORGE_HOST=0.0.0.0 explicitly and typically also configure
  // TLS + users.
  const HOST = process.env.VULNFORGE_HOST || '127.0.0.1';
  // Emit a loud warning if a publicly-bound process has zero users —
  // the "empty users = admin" convenience in authMiddleware will treat
  // every request as admin. Refuse to boot with that combination since
  // it means "anyone on the LAN is admin until setup completes".
  if (HOST === '0.0.0.0' || HOST === '::') {
    try {
      const { countUsers } = await import('./db.js');
      if (countUsers() === 0) {
        console.error(
          '[FATAL] Bound to %s with zero users in DB. ' +
          'This would grant every incoming request admin privileges ' +
          '(see authMiddleware). Either:\n' +
          '  1. Set VULNFORGE_HOST=127.0.0.1 (single-user/desktop mode)\n' +
          '  2. Run the setup flow first to seed an initial admin user\n' +
          '  3. Set VULNFORGE_ALLOW_UNAUTH_PUBLIC=1 if you really know what you are doing',
          HOST,
        );
        if (process.env.VULNFORGE_ALLOW_UNAUTH_PUBLIC !== '1') {
          process.exit(2);
        }
      } else {
        console.warn(
          '[WARN] Bound to %s. Ensure you have set up TLS termination + users; ' +
          'otherwise credentials cross the network in plaintext.',
          HOST,
        );
      }
    } catch { /* DB not ready; authMiddleware will re-check */ }
  }

  // Dynamic port selection: try preferred PORT, increment on EADDRINUSE
  // up to 20 times (3001 -> 3020 by default). Useful in desktop mode
  // where another process may already own the preferred port. Emit a
  // structured marker line so parent processes (e.g. Electron main)
  // can read the actual bound port from stdout.
  const portRetryLimit = 20;
  let boundPort = PORT;
  let finalized = false;

  function onListening(): void {
    if (finalized) return; // guard against the 'listening' callback firing
                           // for a port that was already superseded on retry.
    finalized = true;
    const mode = HEADLESS ? 'HEADLESS' : 'FULL';
    // Write the port to a file next to package.json so the vite dev
    // config (and anything else that starts AFTER the server) can find
    // the actual port without needing an env var. Best-effort - if the
    // cwd is read-only we just skip. Uses the statically-imported fs
    // helper instead of an ESM-illegal `require` call.
    try {
      writeFileSync('.vulnforge-port', String(boundPort), 'utf8');
    } catch {
      /* non-fatal */
    }
    // Structured marker for parent processes (Electron main) to parse.
    // Keep the literal token stable; main.ts greps for this prefix.
    console.log(`VULNFORGE_READY_PORT=${boundPort}`);
    console.log(`
=================================================
  VulnForge Backend  |  port ${boundPort}  |  ${mode}
=================================================
  API:       http://localhost:${boundPort}/api
  WebSocket: ws://localhost:${boundPort}/ws
  MCP:       http://localhost:${boundPort}/mcp
  Health:    http://localhost:${boundPort}/api/health${HEADLESS ? '\n  Mode:      Headless (no UI served, API/WS/MCP only)' : ''}
=================================================
`);
    // If forked by Electron main, also send an IPC message so the parent
    // can react before any child stdout buffering kicks in.
    if (typeof process.send === 'function') {
      try { process.send({ type: 'vulnforge:ready', port: boundPort }); } catch { /* ignore */ }
    }
  }

  function onError(err: NodeJS.ErrnoException, attempt: number): void {
    if (err.code === 'EADDRINUSE' && attempt < portRetryLimit) {
      console.warn(`[Server] port ${boundPort} in use, trying ${boundPort + 1}`);
      boundPort += 1;
      // Reuse the same server object - just re-arm listeners + listen again.
      server.removeAllListeners('error');
      server.removeAllListeners('listening');
      server.once('listening', onListening);
      server.once('error', (e: NodeJS.ErrnoException) => onError(e, attempt + 1));
      server.listen(boundPort, HOST);
      return;
    }
    console.error('[Server] listen failed:', err.message);
    process.exit(1);
  }

  server.once('listening', onListening);
  server.once('error', (e: NodeJS.ErrnoException) => onError(e, 1));
  server.listen(boundPort, HOST);

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('[Server] SIGTERM received, shutting down gracefully');
    server.close(() => process.exit(0));
  });

  process.on('SIGINT', () => {
    console.log('[Server] SIGINT received, shutting down gracefully');
    server.close(() => process.exit(0));
  });
}

main().catch(err => {
  console.error('[Server] Fatal startup error:', err);
  process.exit(1);
});

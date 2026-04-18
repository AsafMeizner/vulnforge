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

async function main(): Promise<void> {
  // Init database
  console.log('[DB] Initializing SQLite database...');
  await initDb();
  console.log('[DB] Database ready');

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
      const toolsDir =
        process.env.VULNFORGE_TOOLS_DIR || 'X:/security-solver/tools';
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
  // CORS: configurable via VULNFORGE_CORS_ORIGIN env var (comma-separated) or defaults to localhost
  const corsOrigins = process.env.VULNFORGE_CORS_ORIGIN
    ? process.env.VULNFORGE_CORS_ORIGIN === '*' ? true : process.env.VULNFORGE_CORS_ORIGIN.split(',').map(s => s.trim())
    : ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'];
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

  // AI chat endpoint
  app.post('/api/ai/chat', async (req, res) => {
    try {
      const { routeAI } = await import('./ai/router.js');
      const { messages, systemPrompt, temperature, maxTokens } = req.body;
      if (!messages || !Array.isArray(messages)) {
        res.status(400).json({ error: 'messages array required' });
        return;
      }
      const response = await routeAI({ messages, systemPrompt, temperature, maxTokens, task: 'chat' as any });
      res.json({ response: response.content, model: response.model, provider: response.provider });
    } catch (err: any) {
      console.error('[AI] Chat error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // AI triage endpoint - single vuln by DB id
  app.post('/api/ai/triage/:id', async (req, res) => {
    try {
      const { triageFinding } = await import('./ai/pipeline.js');
      const { getVulnerabilityById } = await import('./db.js');
      const id = Number(req.params.id);
      if (isNaN(id)) {
        res.status(400).json({ error: 'Invalid ID' });
        return;
      }
      const vuln = getVulnerabilityById(id);
      if (!vuln) {
        res.status(404).json({ error: 'Vulnerability not found' });
        return;
      }
      // Fire-and-forget: return 202 immediately, then run triage in a
      // detached promise with its own error handler. The previous
      // `await` after the response was sent leaked any post-response
      // rejection as an unhandled-promise warning.
      res.status(202).json({ id, message: 'Triage started' });
      void triageFinding(id).catch((e) =>
        console.error('[AI] Triage error (detached):', e?.message || e),
      );
    } catch (err: any) {
      console.error('[AI] Triage error:', err.message);
      // Response may already be sent; swallow any write-after-end errors
    }
  });

  // Legacy triage endpoint used by existing callers (kept for compatibility)
  app.post('/api/ai/triage-legacy/:id', async (req, res) => {
    try {
      const { triageFinding: legacyTriage } = await import('./ai/router.js');
      const { getVulnerabilityById, updateVulnerability } = await import('./db.js');
      const id = Number(req.params.id);
      const vuln = getVulnerabilityById(id);
      if (!vuln) {
        res.status(404).json({ error: 'Vulnerability not found' });
        return;
      }
      const triage = await legacyTriage(vuln as Record<string, any>);
      updateVulnerability(id, { ai_triage: triage });
      res.json({ id, triage });
    } catch (err: any) {
      console.error('[AI] Legacy triage error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/ai/suggest-fix - AI-generated fix for a vulnerability
  app.post('/api/ai/suggest-fix', async (req, res) => {
    try {
      const { routeAI } = await import('./ai/router.js');
      const { getVulnerabilityById, updateVulnerability } = await import('./db.js');
      const { vuln_id } = req.body;
      if (!vuln_id) { res.status(400).json({ error: 'vuln_id required' }); return; }
      const vuln = getVulnerabilityById(Number(vuln_id));
      if (!vuln) { res.status(404).json({ error: 'Vulnerability not found' }); return; }

      const prompt = `You are an expert security engineer. Generate a concrete fix for this vulnerability.

Title: ${vuln.title}
Severity: ${vuln.severity}
File: ${vuln.file || 'N/A'}
CWE: ${vuln.cwe || 'N/A'}
Description: ${vuln.description || 'N/A'}
Impact: ${vuln.impact || 'N/A'}

Code with the vulnerability:
\`\`\`
${vuln.code_snippet || 'Not provided'}
\`\`\`

Respond with ONLY a JSON object in this exact format (no markdown fences):
{
  "suggested_fix": "A plain English explanation of the fix, 2-4 sentences.",
  "fix_diff": "A unified diff showing the code change. Use + for additions and - for removals."
}`;

      const response = await routeAI({
        messages: [{ role: 'user', content: prompt }],
        systemPrompt: 'You are an expert security engineer. Output only valid JSON, no markdown.',
        temperature: 0.1,
        maxTokens: 2048,
      });

      let suggested_fix = '';
      let fix_diff = '';
      try {
        // Strip any markdown fences the model may have added
        const cleaned = response.content.replace(/^```[a-z]*\n?/m, '').replace(/```$/m, '').trim();
        const parsed = JSON.parse(cleaned);
        suggested_fix = parsed.suggested_fix || response.content;
        fix_diff = parsed.fix_diff || '';
      } catch {
        suggested_fix = response.content;
      }

      // Persist the fix back to the DB if one wasn't already there
      if (!vuln.suggested_fix) {
        updateVulnerability(Number(vuln_id), { suggested_fix, fix_diff } as any);
      }

      res.json({ suggested_fix, fix_diff });
    } catch (err: any) {
      console.error('[AI] suggest-fix error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/ai/deep-analyze - thorough analysis with full context
  app.post('/api/ai/deep-analyze', async (req, res) => {
    try {
      const { routeAI } = await import('./ai/router.js');
      const { getVulnerabilityById, getProjectById } = await import('./db.js');
      const { vuln_id } = req.body;
      if (!vuln_id) { res.status(400).json({ error: 'vuln_id required' }); return; }
      const vuln = getVulnerabilityById(Number(vuln_id));
      if (!vuln) { res.status(404).json({ error: 'Vulnerability not found' }); return; }

      let projectContext = '';
      if (vuln.project_id) {
        try {
          const proj = getProjectById(vuln.project_id);
          if (proj) projectContext = `Project: ${proj.name} (${proj.language || 'unknown language'})`;
        } catch { /* non-fatal */ }
      }

      const prompt = `You are a senior security researcher performing a thorough vulnerability analysis.

${projectContext}
Title: ${vuln.title}
Severity: ${vuln.severity} | CVSS: ${vuln.cvss || 'N/A'} | CWE: ${vuln.cwe || 'N/A'}
File: ${vuln.file || 'N/A'}${vuln.line_start ? ` (line ${vuln.line_start})` : ''}
Tool: ${vuln.tool_name || 'N/A'} | Method: ${vuln.method || 'N/A'}
Confidence: ${vuln.confidence != null ? vuln.confidence : 'N/A'}

Description:
${vuln.description || 'N/A'}

Impact:
${vuln.impact || 'N/A'}

Code snippet:
\`\`\`
${vuln.code_snippet || 'Not provided'}
\`\`\`

Reproduction steps:
${vuln.reproduction_steps || 'Not provided'}

Existing AI triage:
${vuln.ai_triage || 'None'}

Provide a DEEP, THOROUGH analysis covering:
1. Exploitability - exact conditions, prerequisites, trigger path
2. Real-world impact - what an attacker can actually achieve, affected deployments
3. Root cause - the precise programming error and why it exists
4. Verification methodology - how to definitively confirm this is a real vulnerability
5. Fix strategy - specific code changes needed, including edge cases
6. Similar CVEs or known variants of this bug class
7. Disclosure strategy - recommended approach (private, coordinated, public)
8. Final verdict - Tier A (private disclosure), B (open PR), or C (internal note) with reasoning

Be technical, precise, and actionable.`;

      const response = await routeAI({
        messages: [{ role: 'user', content: prompt }],
        systemPrompt: 'You are a senior security researcher. Be thorough, technical, and precise.',
        temperature: 0.2,
        maxTokens: 4096,
      });

      res.json({ analysis: response.content });
    } catch (err: any) {
      console.error('[AI] deep-analyze error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // AI agent endpoint
  app.post('/api/ai/agent', async (req, res) => {
    try {
      const { runAgent } = await import('./ai/agent.js');
      const { goal, max_steps } = req.body;
      if (!goal || typeof goal !== 'string') {
        res.status(400).json({ error: 'goal (string) is required' });
        return;
      }
      const steps = await runAgent(goal, max_steps ? Number(max_steps) : 10);
      res.json({ goal, steps });
    } catch (err: any) {
      console.error('[AI] Agent error:', err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/ai/models - full model registry
  app.get('/api/ai/models', async (_req, res) => {
    try {
      const { MODEL_REGISTRY } = await import('./ai/models.js');
      res.json(MODEL_REGISTRY);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/ai/routing - current routing rules
  app.get('/api/ai/routing', async (_req, res) => {
    try {
      const { getRoutingRules } = await import('./ai/routing.js');
      res.json(getRoutingRules());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // PUT /api/ai/routing - replace routing rules (persisted to DB)
  app.put('/api/ai/routing', async (req, res) => {
    try {
      const { persistRules } = await import('./ai/routing.js');
      const rules = req.body;
      if (!Array.isArray(rules)) {
        res.status(400).json({ error: 'Body must be an array of routing rules' });
        return;
      }
      await persistRules(rules);
      res.json({ success: true, count: rules.length });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/ai/routing/presets - list available presets
  app.get('/api/ai/routing/presets', async (_req, res) => {
    try {
      const { ROUTING_PRESETS } = await import('./ai/routing.js');
      const presets = Object.values(ROUTING_PRESETS).map(p => ({
        name: p.name,
        label: p.label,
        description: p.description,
        ruleCount: p.rules.length,
      }));
      res.json(presets);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/ai/routing/presets/:name - apply a preset
  app.post('/api/ai/routing/presets/:name', async (req, res) => {
    try {
      const { ROUTING_PRESETS, persistRules } = await import('./ai/routing.js');
      const preset = ROUTING_PRESETS[req.params.name];
      if (!preset) {
        res.status(404).json({ error: `Preset "${req.params.name}" not found`, available: Object.keys(ROUTING_PRESETS) });
        return;
      }
      await persistRules(preset.rules);
      res.json({ success: true, preset: preset.name, count: preset.rules.length });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // AI providers CRUD
  app.get('/api/ai/providers', async (_req, res) => {
    try {
      const { getAllAIProviders } = await import('./db.js');
      const providers = getAllAIProviders();
      // Mask API keys
      const masked = providers.map(p => ({ ...p, api_key: p.api_key ? '***' : '' }));
      res.json({ data: masked });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.put('/api/ai/providers/:id', async (req, res) => {
    try {
      const { getAIProviderById, upsertAIProvider } = await import('./db.js');
      const id = Number(req.params.id);
      const existing = getAIProviderById(id);
      if (!existing) {
        res.status(404).json({ error: 'Provider not found' });
        return;
      }
      // Don't overwrite key with masked value
      const updates = { ...req.body };
      if (updates.api_key === '***') delete updates.api_key;
      upsertAIProvider({ ...existing, ...updates });
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // POST /api/ai/providers - create (or upsert-by-name) a provider. Without
  // this, the UI has no way to add a provider from an empty database -
  // PUT /:id requires an existing row.
  app.post('/api/ai/providers', async (req, res) => {
    try {
      const { upsertAIProvider, getAllAIProviders } = await import('./db.js');
      const body = req.body || {};
      if (!body.name || typeof body.name !== 'string') {
        res.status(400).json({ error: 'name is required' });
        return;
      }
      upsertAIProvider({
        name: body.name,
        model: body.model || null,
        api_key: body.api_key || null,
        base_url: body.base_url || null,
        enabled: body.enabled ? 1 : 0,
        config: body.config || null,
      } as any);
      const all = getAllAIProviders();
      const created = all.find((p) => p.name === body.name);
      res.status(201).json({
        success: true,
        provider: created ? { ...created, api_key: created.api_key ? '***' : '' } : null,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // DELETE /api/ai/providers/:id - also missing from the original CRUD.
  app.delete('/api/ai/providers/:id', async (req, res) => {
    try {
      const { getAIProviderById, getDb, persistDb } = await import('./db.js');
      const id = Number(req.params.id);
      const existing = getAIProviderById(id);
      if (!existing) {
        res.status(404).json({ error: 'Provider not found' });
        return;
      }
      const db = getDb();
      db.run('DELETE FROM ai_providers WHERE id = ?', [id]);
      persistDb();
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', ts: new Date().toISOString() });
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
    wss.handleUpgrade(req, socket as any, head, (ws) => {
      wss.emit('connection', ws, req);
    });
  });
  console.log('[WS] Upgrade dispatcher registered for /ws + /sync');
  console.log('[WS] WebSocket server initialized at /ws');

  // ── MCP server via SSE at /mcp ────────────────────────────────────────
  setupMcpServer(app);
  console.log('[MCP] MCP server initialized at /mcp');

  // ── Start ─────────────────────────────────────────────────────────────
  const HOST = process.env.VULNFORGE_HOST || '0.0.0.0';

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

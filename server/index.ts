import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { fileURLToPath } from 'url';
import path from 'path';

import { initDb } from './db.js';
import { initWebSocket } from './ws.js';

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

// Disclosure & Bounty Ops (Theme 5)
import disclosureRouter from './routes/disclosure.js';

// Export + Audit (Themes 7+9)
import exportRouter from './routes/export.js';

// MCP
import { setupMcpServer } from './mcp/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3001;
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

  // Express app
  const app = express();

  // ── Middleware ────────────────────────────────────────────────────────
  app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'],
    credentials: true,
  }));
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // Request logging
  app.use((req, _res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
  });

  // ── API Routes ────────────────────────────────────────────────────────
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
  app.use('/api/disclosure', disclosureRouter);
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

  // AI triage endpoint — single vuln by DB id
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
      // Run triage asynchronously; return 202 immediately
      res.status(202).json({ id, message: 'Triage started' });
      await triageFinding(id);
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

  // POST /api/ai/suggest-fix — AI-generated fix for a vulnerability
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

  // POST /api/ai/deep-analyze — thorough analysis with full context
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
1. Exploitability — exact conditions, prerequisites, trigger path
2. Real-world impact — what an attacker can actually achieve, affected deployments
3. Root cause — the precise programming error and why it exists
4. Verification methodology — how to definitively confirm this is a real vulnerability
5. Fix strategy — specific code changes needed, including edge cases
6. Similar CVEs or known variants of this bug class
7. Disclosure strategy — recommended approach (private, coordinated, public)
8. Final verdict — Tier A (private disclosure), B (open PR), or C (internal note) with reasoning

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

  // GET /api/ai/models — full model registry
  app.get('/api/ai/models', async (_req, res) => {
    try {
      const { MODEL_REGISTRY } = await import('./ai/models.js');
      res.json(MODEL_REGISTRY);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // GET /api/ai/routing — current routing rules
  app.get('/api/ai/routing', async (_req, res) => {
    try {
      const { getRoutingRules } = await import('./ai/routing.js');
      res.json(getRoutingRules());
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // PUT /api/ai/routing — replace routing rules (persisted to DB)
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

  // GET /api/ai/routing/presets — list available presets
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

  // POST /api/ai/routing/presets/:name — apply a preset
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

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', ts: new Date().toISOString() });
  });

  // ── HTTP server ───────────────────────────────────────────────────────
  const server = createServer(app);

  // ── WebSocket ─────────────────────────────────────────────────────────
  initWebSocket(server);
  console.log('[WS] WebSocket server initialized at /ws');

  // ── MCP server via SSE at /mcp ────────────────────────────────────────
  setupMcpServer(app);
  console.log('[MCP] MCP server initialized at /mcp');

  // ── Start ─────────────────────────────────────────────────────────────
  server.listen(PORT, () => {
    const mode = HEADLESS ? 'HEADLESS' : 'FULL';
    console.log(`
=================================================
  VulnForge Backend  |  port ${PORT}  |  ${mode}
=================================================
  API:       http://localhost:${PORT}/api
  WebSocket: ws://localhost:${PORT}/ws
  MCP:       http://localhost:${PORT}/mcp
  Health:    http://localhost:${PORT}/api/health${HEADLESS ? '\n  Mode:      Headless (no UI served, API/WS/MCP only)' : ''}
=================================================
`);
  });

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

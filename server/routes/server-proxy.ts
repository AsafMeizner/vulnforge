/**
 * Server-proxied capability invocation.
 *
 * Mounted at /api/server/*. These routes run server-side AI providers and
 * integrations on behalf of the caller, so the upstream secret never
 * leaves the server. Response is streamed back.
 *
 *   GET  /api/server/capabilities
 *   POST /api/server/ai/invoke                  {capability, task, payload}
 *   POST /api/server/integrations/:name/:action {payload}
 *
 * RBAC: `ai:use` or `integrations:use` per route.
 * Rate-limited at the express app level (operator installs it).
 */
import { Router, type Request, type Response } from 'express';

import { assertPermission } from '../auth/permissions.js';
import { getServerCapabilityManifest } from '../sync/capabilities.js';
import { getDb } from '../db.js';

const router = Router();

router.get('/capabilities', (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  res.json(getServerCapabilityManifest({ user_id: req.user.id, role: req.user.role }));
});

// ── AI proxy ───────────────────────────────────────────────────────────────

router.post('/ai/invoke', async (req: Request, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'not authenticated' });
    if (!assertPermission(req, 'ai', 'use', res)) return;
    const { capability, task, payload } = req.body ?? {};
    if (typeof capability !== 'string' || typeof task !== 'string') {
      return res.status(400).json({ error: 'capability + task required' });
    }
    const provider = lookupAiCapability(capability);
    if (!provider) return res.status(404).json({ error: `no server AI capability: ${capability}` });
    if (!provider.enabled) return res.status(409).json({ error: 'capability disabled' });

    // Delegate to existing AI runtime. Lazy string-ref import so TS doesn't
    // resolve at compile time - the module name is picked per deployment and
    // may not exist until the AI stack is wired.
    let runtimeModule: any;
    try {
      const mod = '../ai/runtime.js';
      // @ts-ignore - dynamic, resolved at runtime only
      runtimeModule = await import(mod);
    } catch (e: any) {
      return res.status(500).json({ error: `ai runtime unavailable: ${e.message}` });
    }
    const invoke = runtimeModule.invokeProvider || runtimeModule.default;
    if (typeof invoke !== 'function') {
      return res.status(500).json({ error: 'ai runtime missing invokeProvider' });
    }
    const result = await invoke({
      provider_name: provider.name,
      provider_type: provider.provider,
      config: safeParse(provider.config),
      task,
      payload,
      invoked_by: { user_id: req.user.id, role: req.user.role },
    });
    res.json({ ok: true, result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── Integration proxy ──────────────────────────────────────────────────────

router.post('/integrations/:name/:action', async (req: Request, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ error: 'not authenticated' });
    if (!assertPermission(req, 'integrations', 'use', res)) return;
    const { name, action } = req.params;
    const integration = lookupIntegration(String(name));
    if (!integration) return res.status(404).json({ error: `no server integration: ${name}` });
    if (!integration.enabled) return res.status(409).json({ error: 'integration disabled' });

    let registryModule: any;
    try { registryModule = await import('../integrations/registry.js'); }
    catch (e: any) {
      return res.status(500).json({ error: `integrations registry unavailable: ${e.message}` });
    }
    const getIntegrationImpl = registryModule.getServiceIntegration || registryModule.getIntegration;
    if (typeof getIntegrationImpl !== 'function') {
      return res.status(500).json({ error: 'integrations registry missing lookup' });
    }
    const impl = getIntegrationImpl(integration.type);
    if (!impl) return res.status(404).json({ error: `no handler for type ${integration.type}` });

    const config = safeParse(integration.config);
    const payload = req.body ?? {};

    let result: any;
    switch (action) {
      case 'create_ticket':
        if (typeof impl.createTicket !== 'function') return res.status(405).json({ error: 'unsupported action' });
        result = await impl.createTicket(payload, config);
        break;
      case 'update_ticket':
        if (typeof impl.updateTicket !== 'function') return res.status(405).json({ error: 'unsupported action' });
        result = await impl.updateTicket(payload.ticket_id, payload.updates, config);
        break;
      case 'send_notification':
        if (typeof impl.sendNotification !== 'function') return res.status(405).json({ error: 'unsupported action' });
        result = await impl.sendNotification(payload.message, config);
        break;
      case 'test':
        if (typeof impl.testConnection !== 'function') return res.status(405).json({ error: 'unsupported action' });
        result = await impl.testConnection(config);
        break;
      default:
        return res.status(400).json({ error: `unknown action: ${action}` });
    }
    res.json({ ok: true, result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── helpers ────────────────────────────────────────────────────────────────

interface AiCapabilityRow {
  name: string;
  provider: string;
  config: string;
  enabled: number;
  task_tags: string;
}

function lookupAiCapability(name: string): AiCapabilityRow | null {
  try {
    const db = getDb();
    const stmt = db.prepare(
      `SELECT name, provider, config, enabled, task_tags
       FROM ai_providers
       WHERE name = ? AND source = 'server' LIMIT 1`,
    );
    stmt.bind([name]);
    if (!stmt.step()) { stmt.free(); return null; }
    const row = stmt.get();
    stmt.free();
    return {
      name: String(row[0]),
      provider: String(row[1]),
      config: String(row[2] ?? '{}'),
      enabled: Number(row[3]),
      task_tags: String(row[4] ?? '[]'),
    };
  } catch { return null; }
}

interface IntegrationRow {
  name: string;
  type: string;
  config: string;
  enabled: number;
}

function lookupIntegration(name: string): IntegrationRow | null {
  try {
    const db = getDb();
    const stmt = db.prepare(
      `SELECT name, type, config, enabled
       FROM integrations
       WHERE name = ? AND source = 'server' LIMIT 1`,
    );
    stmt.bind([name]);
    if (!stmt.step()) { stmt.free(); return null; }
    const row = stmt.get();
    stmt.free();
    return {
      name: String(row[0]),
      type: String(row[1]),
      config: String(row[2] ?? '{}'),
      enabled: Number(row[3]),
    };
  } catch { return null; }
}

function safeParse(raw: string): Record<string, any> {
  try {
    const v = JSON.parse(raw || '{}');
    return v && typeof v === 'object' ? v : {};
  } catch { return {}; }
}

export default router;

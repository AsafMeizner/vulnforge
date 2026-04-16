import { Router, type Request, type Response } from 'express';
import {
  getIntegrations,
  getIntegrationById,
  createIntegration,
  updateIntegration,
  deleteIntegration,
  getIntegrationTickets,
  createIntegrationTicket,
  getVulnerabilityById,
  getDisclosureById,
} from '../db.js';
import { getServiceIntegration, listAvailableIntegrations } from '../integrations/registry.js';

const router = Router();

// GET /api/integrations — list configured + available
router.get('/', (_req: Request, res: Response) => {
  try {
    const configured = getIntegrations();
    const available = listAvailableIntegrations();

    // Parse configs (mask secrets)
    const safe = configured.map(i => {
      let config: any = {};
      try { config = JSON.parse(i.config || '{}'); } catch {}
      const masked: any = {};
      for (const [k, v] of Object.entries(config)) {
        masked[k] = typeof v === 'string' && (k.includes('token') || k.includes('key') || k.includes('password'))
          ? String(v).slice(0, 4) + '****'
          : v;
      }
      return { ...i, config: masked };
    });

    res.json({ configured: safe, available, total: configured.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/integrations — add a new integration
router.post('/', (req: Request, res: Response) => {
  try {
    const { name, type, config, enabled } = req.body;
    if (!name || !type) { res.status(400).json({ error: 'name and type required' }); return; }

    const service = getServiceIntegration(name);
    if (!service) { res.status(400).json({ error: `Unknown service: ${name}` }); return; }

    const id = createIntegration({
      name,
      type: service.type,
      enabled: enabled ? 1 : 0,
      config: JSON.stringify(config || {}),
    });
    res.status(201).json(getIntegrationById(id));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/integrations/:id
router.put('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    const updates: any = {};
    if (req.body.enabled !== undefined) updates.enabled = req.body.enabled ? 1 : 0;
    if (req.body.config) updates.config = JSON.stringify(req.body.config);
    updateIntegration(id, updates);
    res.json(getIntegrationById(id));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/integrations/:id
router.delete('/:id', (req: Request, res: Response) => {
  try {
    deleteIntegration(Number(req.params.id));
    res.json({ deleted: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/integrations/:id/test — test connection
router.post('/:id/test', async (req: Request, res: Response) => {
  try {
    const integration = getIntegrationById(Number(req.params.id));
    if (!integration) { res.status(404).json({ error: 'not found' }); return; }

    const service = getServiceIntegration(integration.name);
    if (!service) { res.status(400).json({ error: `No service for ${integration.name}` }); return; }

    const config = JSON.parse(integration.config || '{}');
    const result = await service.testConnection(config);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/integrations/:id/create-ticket — create ticket from finding or disclosure
router.post('/:id/create-ticket', async (req: Request, res: Response) => {
  try {
    const integration = getIntegrationById(Number(req.params.id));
    if (!integration) { res.status(404).json({ error: 'not found' }); return; }

    const service = getServiceIntegration(integration.name);
    if (!service) { res.status(400).json({ error: `No service for ${integration.name}` }); return; }

    const { finding_id, disclosure_id, title, description, severity } = req.body;

    // Auto-fill from finding or disclosure if ID provided
    let ticketTitle = title || '';
    let ticketDesc = description || '';
    let ticketSev = severity;

    if (finding_id) {
      const vuln = getVulnerabilityById(Number(finding_id));
      if (vuln) {
        ticketTitle = ticketTitle || vuln.title;
        ticketDesc = ticketDesc || vuln.description || '';
        ticketSev = ticketSev || vuln.severity;
      }
    }

    if (disclosure_id) {
      const disc = getDisclosureById(Number(disclosure_id));
      if (disc) {
        ticketTitle = ticketTitle || disc.title;
      }
    }

    if (!ticketTitle) { res.status(400).json({ error: 'title required (or provide finding_id/disclosure_id)' }); return; }

    const config = JSON.parse(integration.config || '{}');
    const result = await service.createTicket(
      { title: ticketTitle, description: ticketDesc, severity: ticketSev },
      config,
    );

    // Store the ticket link
    const ticketRowId = createIntegrationTicket({
      integration_id: Number(req.params.id),
      finding_id: finding_id ? Number(finding_id) : undefined,
      disclosure_id: disclosure_id ? Number(disclosure_id) : undefined,
      ticket_id: result.ticket_id,
      ticket_url: result.url,
      status: 'created',
    });

    res.json({ ...result, db_id: ticketRowId });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/integrations/tickets — list all linked tickets
router.get('/tickets', (req: Request, res: Response) => {
  try {
    const filters: any = {};
    if (req.query.finding_id) filters.finding_id = Number(req.query.finding_id);
    if (req.query.disclosure_id) filters.disclosure_id = Number(req.query.disclosure_id);
    if (req.query.integration_id) filters.integration_id = Number(req.query.integration_id);
    const tickets = getIntegrationTickets(filters);
    res.json({ data: tickets, total: tickets.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/integrations/:id/notify — send notification (Slack etc.)
router.post('/:id/notify', async (req: Request, res: Response) => {
  try {
    const integration = getIntegrationById(Number(req.params.id));
    if (!integration) { res.status(404).json({ error: 'not found' }); return; }

    const service = getServiceIntegration(integration.name);
    if (!service?.sendNotification) { res.status(400).json({ error: `${integration.name} does not support notifications` }); return; }

    const config = JSON.parse(integration.config || '{}');
    await service.sendNotification(req.body.message || 'VulnForge notification', config);
    res.json({ sent: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;

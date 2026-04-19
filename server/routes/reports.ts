import { Router, Request, Response, NextFunction } from 'express';
import {
  getAllReports,
  getReportById,
  createReport,
  updateReport,
  deleteReport,
  getVulnerabilityById,
} from '../db.js';

const router = Router();

// POST /api/reports/generate
// Body: { vuln_id, type: 'disclosure'|'email'|'advisory'|'summary', provider?: string }
router.post('/generate', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { vuln_id, type = 'disclosure' } = req.body;

    if (!vuln_id) {
      res.status(400).json({ error: 'vuln_id is required' });
      return;
    }

    const vuln = getVulnerabilityById(Number(vuln_id));
    if (!vuln) {
      res.status(404).json({ error: 'Vulnerability not found' });
      return;
    }

    const { buildReportPrompt } = await import('../ai/prompts/report.js');
    const { routeAI } = await import('../ai/router.js');

    const prompt = buildReportPrompt(vuln as Record<string, any>, type);

    const response = await routeAI({
      messages: [{ role: 'user', content: prompt.userMessage }],
      systemPrompt: prompt.systemPrompt,
      temperature: 0.3,
      maxTokens: 3000,
    });

    const content = response.content;

    // Persist the report in DB
    const reportId = createReport({
      vuln_id: Number(vuln_id),
      type,
      format: 'markdown',
      content,
      generated_by: response.provider || 'ai',
    });

    const report = getReportById(reportId);
    res.status(201).json(report);
  } catch (err: any) {
    console.error('[Reports] Generate error:', err.message);
    next(err);
  }
});

// GET /api/reports
router.get('/', (_req: Request, res: Response, next: NextFunction) => {
  try {
    const reports = getAllReports();
    res.json({ data: reports, total: reports.length });
  } catch (err: any) {
    console.error('[Reports] List error:', err.message);
    next(err);
  }
});

// GET /api/reports/:id
router.get('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const report = getReportById(id);
    if (!report) {
      res.status(404).json({ error: 'Report not found' });
      return;
    }
    res.json(report);
  } catch (err: any) {
    console.error('[Reports] Get error:', err.message);
    next(err);
  }
});

// POST /api/reports - manual create (no AI). For the "Write
// Manually" path in the UI, where the user wants to author a report
// from scratch without calling a provider. AI-generated reports go
// through /reports/generate which does both the AI call and the DB
// insert in one step.
router.post('/', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { vuln_id, type, format, content } = (req.body || {}) as {
      vuln_id?: number; type?: string; format?: string; content?: string;
    };
    if (!vuln_id || isNaN(Number(vuln_id))) {
      res.status(400).json({ error: 'vuln_id is required' });
      return;
    }
    if (!getVulnerabilityById(Number(vuln_id))) {
      res.status(404).json({ error: 'vuln_id does not exist' });
      return;
    }
    const id = createReport({
      vuln_id: Number(vuln_id),
      type: type || 'manual',
      format: format || 'markdown',
      content: content || '',
      generated_by: 'manual',
    } as any);
    res.status(201).json(getReportById(id));
  } catch (err: any) {
    console.error('[Reports] Manual create error:', err.message);
    next(err);
  }
});

// PUT /api/reports/:id - edit the content (or type/format) of a report.
// Main use case: user refines the AI-generated disclosure before sending
// it to the vendor.
router.put('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }
    const existing = getReportById(id);
    if (!existing) { res.status(404).json({ error: 'Report not found' }); return; }
    updateReport(id, req.body || {});
    res.json(getReportById(id));
  } catch (err: any) {
    console.error('[Reports] Update error:', err.message);
    next(err);
  }
});

// DELETE /api/reports/:id - throw away a report the user doesn't want
// to keep (wrong template, bad AI output, etc.).
router.delete('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }
    const existing = getReportById(id);
    if (!existing) { res.status(404).json({ error: 'Report not found' }); return; }
    deleteReport(id);
    res.status(204).send();
  } catch (err: any) {
    next(err);
  }
});

export default router;

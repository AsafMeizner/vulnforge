import { Router, Request, Response } from 'express';
import {
  getAllReports,
  getReportById,
  createReport,
  getVulnerabilityById,
} from '../db.js';

const router = Router();

// POST /api/reports/generate
// Body: { vuln_id, type: 'disclosure'|'email'|'advisory'|'summary', provider?: string }
router.post('/generate', async (req: Request, res: Response) => {
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
    res.status(500).json({ error: err.message });
  }
});

// GET /api/reports
router.get('/', (_req: Request, res: Response) => {
  try {
    const reports = getAllReports();
    res.json({ data: reports, total: reports.length });
  } catch (err: any) {
    console.error('[Reports] List error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/reports/:id
router.get('/:id', (req: Request, res: Response) => {
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
    res.status(500).json({ error: err.message });
  }
});

export default router;

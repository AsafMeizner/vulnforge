import { Router, type Request, type Response } from 'express';
import { getTeachExamples, getLearnedPatterns, getProjectById } from '../db.js';
import { teachFromDecision, runLearnedPatterns, validatePoCInSandbox } from '../pipeline/ai/teach.js';

const router = Router();

// POST /api/teach - record a user decision and learn from it
router.post('/', async (req: Request, res: Response) => {
  try {
    const { finding_id, action, reasoning } = req.body;
    if (!finding_id || !action) {
      res.status(400).json({ error: 'finding_id and action required' });
      return;
    }
    if (!['confirmed', 'rejected', 'false_positive'].includes(action)) {
      res.status(400).json({ error: 'action must be confirmed, rejected, or false_positive' });
      return;
    }
    const result = await teachFromDecision({ findingId: finding_id, action, reasoning });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/teach/examples - list teach examples
router.get('/examples', (req: Request, res: Response) => {
  try {
    const examples = getTeachExamples({
      finding_id: req.query.finding_id ? Number(req.query.finding_id) : undefined,
      action: req.query.action as string | undefined,
      limit: req.query.limit ? Number(req.query.limit) : undefined,
    });
    res.json({ data: examples, total: examples.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/teach/patterns - list learned patterns
router.get('/patterns', (_req: Request, res: Response) => {
  try {
    const patterns = getLearnedPatterns();
    res.json({ data: patterns, total: patterns.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/teach/patterns/run - run learned patterns against a project
router.post('/patterns/run', async (req: Request, res: Response) => {
  try {
    const { project_id } = req.body;
    if (!project_id) { res.status(400).json({ error: 'project_id required' }); return; }
    const project = getProjectById(Number(project_id));
    if (!project?.path) { res.status(404).json({ error: 'project has no local path' }); return; }

    const results = await runLearnedPatterns(project.path);
    res.json({
      data: results,
      total_patterns: results.length,
      total_matches: results.reduce((n, r) => n + r.matches.length, 0),
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/teach/validate-poc - run an exploit in a sandbox
router.post('/validate-poc', async (req: Request, res: Response) => {
  try {
    const { exploit_id, target_image, timeout } = req.body;
    if (!exploit_id) { res.status(400).json({ error: 'exploit_id required' }); return; }
    const result = await validatePoCInSandbox({
      exploitId: Number(exploit_id),
      targetImage: target_image,
      timeout: timeout ? Number(timeout) : undefined,
    });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;

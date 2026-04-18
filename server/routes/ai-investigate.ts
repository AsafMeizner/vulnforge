import { Router, type Request, type Response } from 'express';
import {
  startInvestigation,
  proposeNextStep,
  executeStep,
  rejectStep,
  cancelInvestigation,
  listInvestigations,
  getInvestigation,
} from '../pipeline/ai/investigate.js';
import { extractAssumptions, generateHypotheses } from '../pipeline/ai/assumptions.js';
import { getProjectById } from '../db.js';

const router = Router();

// ── Investigation sessions ────────────────────────────────────────────────

router.get('/sessions', (_req: Request, res: Response) => {
  try {
    const sessions = listInvestigations();
    res.json({ data: sessions, total: sessions.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id', (req: Request, res: Response) => {
  try {
    const session = getInvestigation(String(req.params.id));
    if (!session) { res.status(404).json({ error: 'session not found' }); return; }
    res.json(session);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/sessions', async (req: Request, res: Response) => {
  try {
    const { goal, finding_id } = req.body;
    if (!goal) { res.status(400).json({ error: 'goal required' }); return; }
    const session = await startInvestigation(goal, finding_id ? Number(finding_id) : undefined);
    res.status(201).json(session);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/sessions/:id/next-step', async (req: Request, res: Response) => {
  try {
    const step = await proposeNextStep(String(req.params.id));
    res.json(step);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /sessions/:id/manual-step
// Body: { thought: string, action?: string, args?: object }
// Manual step entry that makes no AI call - lets users drive the
// investigation themselves when they don't want/need a provider.
router.post('/sessions/:id/manual-step', async (req: Request, res: Response) => {
  try {
    const { thought, action, args } = req.body || {};
    if (typeof thought !== 'string' || !thought.trim()) {
      res.status(400).json({ error: 'thought (string) required' });
      return;
    }
    const { addManualStep } = await import('../pipeline/ai/investigate.js');
    const step = addManualStep(String(req.params.id), { thought, action, args });
    res.status(201).json(step);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/sessions/:id/execute/:step', async (req: Request, res: Response) => {
  try {
    const step = await executeStep(String(req.params.id), Number(req.params.step));
    res.json(step);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/sessions/:id/reject/:step', (req: Request, res: Response) => {
  try {
    const step = rejectStep(String(req.params.id), Number(req.params.step), req.body?.reason);
    res.json(step);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/sessions/:id/cancel', (req: Request, res: Response) => {
  try {
    cancelInvestigation(String(req.params.id));
    res.json({ cancelled: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /sessions/:id - permanently remove an investigation row from
// the session_state store. Different from cancel (which flips status
// to 'cancelled' but keeps the record around). Users needed a way to
// actually clear finished or abandoned investigations from the
// sidebar instead of accumulating history forever.
router.delete('/sessions/:id', async (req: Request, res: Response) => {
  try {
    const { deleteInvestigation } = await import('../pipeline/ai/investigate.js');
    const removed = deleteInvestigation(String(req.params.id));
    if (!removed) { res.status(404).json({ error: 'Investigation not found' }); return; }
    res.status(204).send();
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── Assumption extraction ────────────────────────────────────────────────

router.post('/assumptions', async (req: Request, res: Response) => {
  try {
    const { file, function: functionName } = req.body;
    if (!file || !functionName) { res.status(400).json({ error: 'file and function required' }); return; }
    const report = await extractAssumptions(file, functionName);
    res.json(report);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── Hypothesis auto-generation ───────────────────────────────────────────

router.post('/hypotheses', async (req: Request, res: Response) => {
  try {
    const { project_id } = req.body;
    if (!project_id) { res.status(400).json({ error: 'project_id required' }); return; }
    const project = getProjectById(Number(project_id));
    if (!project?.path) { res.status(404).json({ error: 'project has no local path' }); return; }

    const hypotheses = await generateHypotheses(project.path);
    res.json({ data: hypotheses, total: hypotheses.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;

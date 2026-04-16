import { Router, Request, Response } from 'express';
import {
  getPipelineRun,
  getActivePipelineRuns,
  getPipelineRuns,
} from '../db.js';
import { runPipeline, cancelPipeline, pausePipeline, resumePipeline } from '../pipeline/orchestrator.js';

const router = Router();

// ── POST /api/pipeline/start ─────────────────────────────────────────────
// Start a new pipeline. Accepts: { url }, { path }, or { project_id }

router.post('/start', async (req: Request, res: Response) => {
  try {
    const { url, path, project_id, branch, depth, toolOverrides } = req.body;

    if (!url && !path && !project_id) {
      res.status(400).json({ error: 'Must provide url, path, or project_id' });
      return;
    }

    const pipelineId = await runPipeline({
      url,
      path,
      project_id: project_id ? Number(project_id) : undefined,
      branch,
      depth: depth ? Number(depth) : undefined,
      toolOverrides,
    });

    const pipeline = getPipelineRun(pipelineId);
    res.status(202).json({
      pipelineId,
      projectId: pipeline?.project_id,
      status: pipeline?.status || 'pending',
    });
  } catch (err: any) {
    console.error('POST /pipeline/start error:', err);
    res.status(400).json({ error: err.message });
  }
});

// ── POST /api/pipeline/batch ─────────────────────────────────────────────
// Start multiple pipelines in parallel.

router.post('/batch', async (req: Request, res: Response) => {
  try {
    const { targets } = req.body;
    if (!Array.isArray(targets) || targets.length === 0) {
      res.status(400).json({ error: 'targets array is required' });
      return;
    }

    if (targets.length > 10) {
      res.status(400).json({ error: 'Maximum 10 targets per batch' });
      return;
    }

    const results: Array<{ pipelineId: string; projectId?: number; error?: string }> = [];

    for (const target of targets) {
      try {
        const pipelineId = await runPipeline({
          url: target.url,
          path: target.path,
          project_id: target.project_id ? Number(target.project_id) : undefined,
          branch: target.branch,
          depth: target.depth,
        });
        const pipeline = getPipelineRun(pipelineId);
        results.push({ pipelineId, projectId: pipeline?.project_id });
      } catch (err: any) {
        results.push({ pipelineId: '', error: err.message });
      }
    }

    res.status(202).json({ pipelines: results });
  } catch (err: any) {
    console.error('POST /pipeline/batch error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/pipeline/:id ────────────────────────────────────────────────

router.get('/:id', (req: Request, res: Response) => {
  try {
    const pipeline = getPipelineRun(String(req.params.id));
    if (!pipeline) {
      res.status(404).json({ error: 'Pipeline not found' });
      return;
    }
    res.json(pipeline);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/pipeline/active ─────────────────────────────────────────────

router.get('/', (req: Request, res: Response) => {
  try {
    const activeOnly = req.query.active === 'true';
    const pipelines = activeOnly ? getActivePipelineRuns() : getPipelineRuns();
    res.json({ data: pipelines, total: pipelines.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/pipeline/:id/pause ──────────────────────────────────────────

router.post('/:id/pause', (req: Request, res: Response) => {
  try {
    const success = pausePipeline(String(req.params.id));
    if (success) {
      res.json({ message: 'Pipeline paused', pipelineId: String(req.params.id) });
    } else {
      res.status(404).json({ error: 'Pipeline not running or not found' });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/pipeline/:id/resume ────────────────────────────────────────

router.post('/:id/resume', async (req: Request, res: Response) => {
  try {
    const success = await resumePipeline(String(req.params.id));
    if (success) {
      res.json({ message: 'Pipeline resumed', pipelineId: String(req.params.id) });
    } else {
      const pipeline = getPipelineRun(String(req.params.id));
      if (!pipeline) {
        res.status(404).json({ error: 'Pipeline not found' });
      } else {
        res.status(400).json({ error: `Pipeline is "${pipeline.status}", not paused` });
      }
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /api/pipeline/:id ─────────────────────────────────────────────

router.delete('/:id', (req: Request, res: Response) => {
  try {
    const success = cancelPipeline(String(req.params.id));
    if (success) {
      res.json({ message: 'Pipeline cancelled' });
    } else {
      res.status(404).json({ error: 'Pipeline not found or already completed' });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;

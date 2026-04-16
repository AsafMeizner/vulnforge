/**
 * Pipeline-jobs REST routes for server-executor jobs.
 *
 * Mounted at /api/jobs/*. Operates on the pipeline_jobs queue.
 *
 *   GET    /api/jobs                 list all jobs
 *   GET    /api/jobs/pool            worker pool status
 *   POST   /api/jobs/enqueue         enqueue a server-side job
 *   POST   /api/jobs/:id/cancel      cancel
 */
import { Router, type Request, type Response } from 'express';

import { assertPermission } from '../auth/permissions.js';
import {
  enqueueServerJob,
  cancelServerJob,
  listServerJobs,
  getPoolStatus,
} from '../workers/pool.js';
import { isServerMode } from '../deployment/mode.js';

const router = Router();

router.get('/', (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  if (!assertPermission(req, 'pipelines', 'read', res)) return;
  const limit = Math.max(1, Math.min(500, Number(req.query.limit ?? 100)));
  res.json({ data: listServerJobs(limit), total: listServerJobs(limit).length });
});

router.get('/pool', (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  if (!assertPermission(req, 'pipelines', 'read', res)) return;
  res.json(getPoolStatus());
});

router.post('/enqueue', (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  if (!assertPermission(req, 'pipelines', 'run', res)) return;
  if (!isServerMode()) {
    return res.status(409).json({ error: 'server-executor jobs only available in server mode' });
  }
  const { project_id, stages, priority } = req.body ?? {};
  if (!Array.isArray(stages)) {
    return res.status(400).json({ error: 'stages must be an array' });
  }
  const result = enqueueServerJob({
    project_id: typeof project_id === 'number' ? project_id : null,
    requested_by_user_id: req.user.id,
    stages: stages.map(String),
    priority: typeof priority === 'number' ? priority : undefined,
  });
  res.json({ ok: true, ...result });
});

router.post('/:id/cancel', (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  if (!assertPermission(req, 'pipelines', 'run', res)) return;
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'invalid id' });
  const ok = cancelServerJob(id);
  res.json({ ok });
});

export default router;

import { Router, Request, Response } from 'express';
import {
  getAllScans,
  getScanById,
  getProjectById,
  getAllTools,
} from '../db.js';
import { scanQueue } from '../scanner/queue.js';
import { getProfile, listProfiles } from '../scanner/profiles.js';
import { broadcast } from '../ws.js';

const router = Router();

// ── Wire scan-queue events → WebSocket broadcast ───────────────────────────
//
// This wiring happens once at module load. Because this module is imported
// by index.ts, the queue's event listeners are registered before any HTTP
// request arrives.

scanQueue.on('job:start', (job) => {
  broadcast({
    type: 'scan:start',
    jobId: job.id,
    scanDbId: job.scanDbId,
    projectId: job.projectId,
    toolName: job.toolName,
    startedAt: job.startedAt,
  });
});

scanQueue.on('job:output', (job, line: string) => {
  broadcast({
    type: 'scan:output',
    jobId: job.id,
    scanDbId: job.scanDbId,
    data: line,
  });
});

scanQueue.on('job:complete', (job, findings: number) => {
  broadcast({
    type: 'scan:complete',
    jobId: job.id,
    scanDbId: job.scanDbId,
    findings,
    status: job.status,
    completedAt: job.completedAt,
  });
});

scanQueue.on('job:error', (job, err: Error) => {
  broadcast({
    type: 'scan:error',
    jobId: job.id,
    scanDbId: job.scanDbId,
    error: err.message,
    status: job.status,
  });
});

scanQueue.on('queue:drain', () => {
  broadcast({ type: 'queue:drain', status: scanQueue.getStatus() });
});

scanQueue.on('triage:complete', (vulnId: number, result: any) => {
  broadcast({
    type: 'triage:complete',
    vulnId,
    severity: result.severity,
    tier: result.tier,
    summary: result.summary,
  });
});

scanQueue.on('triage:error', (vulnId: number, err: Error) => {
  broadcast({ type: 'triage:error', vulnId, error: err.message });
});

// ── GET /api/scans ─────────────────────────────────────────────────────────

router.get('/', (req: Request, res: Response) => {
  try {
    const limit = req.query.limit ? Number(req.query.limit) : 50;
    const scans = getAllScans(limit);
    res.json({ data: scans, total: scans.length });
  } catch (err: any) {
    console.error('GET /scans error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/scans/queue ───────────────────────────────────────────────────

router.get('/queue', (_req: Request, res: Response) => {
  try {
    const status = scanQueue.getStatus();
    const jobs = scanQueue.getJobs().map(j => ({
      id: j.id,
      scanDbId: j.scanDbId,
      projectId: j.projectId,
      toolName: j.toolName,
      status: j.status,
      findings: j.findings,
      startedAt: j.startedAt,
      completedAt: j.completedAt,
      error: j.error,
    }));
    res.json({ status, jobs });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/scans/profiles ────────────────────────────────────────────────

router.get('/profiles', (_req: Request, res: Response) => {
  res.json({ data: listProfiles() });
});

// ── GET /api/scans/:id ─────────────────────────────────────────────────────

router.get('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const scan = getScanById(id);
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    res.json(scan);
  } catch (err: any) {
    console.error(`GET /scans/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/scans ────────────────────────────────────────────────────────
//
// Body: { project_id, tools: string[], auto_triage?: boolean }
// Returns 202 with the array of ScanJob objects immediately.

router.post('/', (req: Request, res: Response) => {
  try {
    const { project_id, tools, auto_triage = false } = req.body;

    if (!project_id) {
      res.status(400).json({ error: 'project_id is required' });
      return;
    }

    if (!Array.isArray(tools) || tools.length === 0) {
      res.status(400).json({ error: 'tools must be a non-empty array of tool names' });
      return;
    }

    const project = getProjectById(Number(project_id));
    if (!project) {
      res.status(404).json({ error: 'Project not found' });
      return;
    }
    if (!project.path) {
      res.status(400).json({ error: 'Project has no path configured' });
      return;
    }

    const jobs = scanQueue.enqueue(
      Number(project_id),
      project.path,
      tools,
      Boolean(auto_triage),
    );

    res.status(202).json({
      message: `Enqueued ${jobs.length} scan job(s)`,
      jobs: jobs.map(j => ({
        id: j.id,
        scanDbId: j.scanDbId,
        toolName: j.toolName,
        status: j.status,
      })),
    });
  } catch (err: any) {
    console.error('POST /scans error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/scans/profile ────────────────────────────────────────────────
//
// Body: { project_id, profile: string, auto_triage?: boolean }
// Expands the profile's tool list and enqueues.

router.post('/profile', (req: Request, res: Response) => {
  try {
    const { project_id, profile: profileKey, auto_triage = false } = req.body;

    if (!project_id || !profileKey) {
      res.status(400).json({ error: 'project_id and profile are required' });
      return;
    }

    const profile = getProfile(profileKey);
    if (!profile) {
      res.status(400).json({
        error: `Unknown profile: ${profileKey}`,
        available: listProfiles().map(p => p.key),
      });
      return;
    }

    const project = getProjectById(Number(project_id));
    if (!project) {
      res.status(404).json({ error: 'Project not found' });
      return;
    }
    if (!project.path) {
      res.status(400).json({ error: 'Project has no path configured' });
      return;
    }

    // 'full' profile: expand to all enabled tools in the DB
    let toolNames: string[] = profile.tools;
    if (toolNames.length === 0) {
      const allTools = getAllTools();
      toolNames = allTools.filter(t => t.enabled === 1).map(t => t.name);
    }

    if (toolNames.length === 0) {
      res.status(400).json({ error: 'No enabled tools found for this profile' });
      return;
    }

    const jobs = scanQueue.enqueue(
      Number(project_id),
      project.path,
      toolNames,
      Boolean(auto_triage),
    );

    res.status(202).json({
      message: `Enqueued ${jobs.length} scan job(s) for profile "${profile.name}"`,
      profile: profileKey,
      jobs: jobs.map(j => ({
        id: j.id,
        scanDbId: j.scanDbId,
        toolName: j.toolName,
        status: j.status,
      })),
    });
  } catch (err: any) {
    console.error('POST /scans/profile error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /api/scans/:id ──────────────────────────────────────────────────
//
// Cancels a queued job identified by its UUID job id.
// Note: the :id here is the in-memory ScanJob UUID, not the DB scan row id.

router.delete('/:id', (req: Request, res: Response) => {
  try {
    const id = String(req.params['id']);
    const job = scanQueue.getJob(id);

    if (!job) {
      res.status(404).json({ error: 'Job not found in queue' });
      return;
    }

    if (job.status === 'completed' || job.status === 'failed') {
      res.status(409).json({ error: `Job already ${job.status}` });
      return;
    }

    scanQueue.cancel(id);
    res.json({ message: 'Job cancelled', jobId: id });
  } catch (err: any) {
    console.error(`DELETE /scans/${req.params['id']} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

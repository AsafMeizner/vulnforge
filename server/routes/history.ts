import { Router, type Request, type Response, NextFunction } from 'express';
import {
  getProjectById,
  getCveIntel,
  getCveIntelById,
  getCveProjectMatches,
  getBisectResults,
} from '../db.js';

const router = Router();

// GET /api/history/cves - list recent CVE intel
router.get('/cves', (req: Request, res: Response, next: NextFunction) => {
  try {
    const cves = getCveIntel({
      severity: req.query.severity as string | undefined,
      since: req.query.since as string | undefined,
      limit: req.query.limit ? Number(req.query.limit) : undefined,
    });
    // Parse JSON columns for convenience
    const hydrated = cves.map(c => ({
      ...c,
      affected_products: (() => { try { return JSON.parse(c.affected_products || '[]'); } catch { return []; } })(),
      cve_references: (() => { try { return JSON.parse(c.cve_references || '[]'); } catch { return []; } })(),
    }));
    res.json({ data: hydrated, total: hydrated.length });
  } catch (err: any) {
    next(err);
  }
});

// GET /api/history/cves/:id - single CVE
router.get('/cves/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const cve = getCveIntelById(String(req.params.id));
    if (!cve) { res.status(404).json({ error: 'CVE not found' }); return; }
    res.json({
      ...cve,
      affected_products: (() => { try { return JSON.parse(cve.affected_products || '[]'); } catch { return []; } })(),
      cve_references: (() => { try { return JSON.parse(cve.cve_references || '[]'); } catch { return []; } })(),
    });
  } catch (err: any) {
    next(err);
  }
});

// POST /api/history/cves/sync - trigger NVD sync
router.post('/cves/sync', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const days = req.body?.days || 30;
    const { fullSync } = await import('../pipeline/history/nvd-sync.js');
    const result = await fullSync(days);
    res.json(result);
  } catch (err: any) {
    next(err);
  }
});

// GET /api/history/matches - CVE project matches
router.get('/matches', (req: Request, res: Response, next: NextFunction) => {
  try {
    const matches = getCveProjectMatches({
      project_id: req.query.project_id ? Number(req.query.project_id) : undefined,
      cve_id: req.query.cve_id as string | undefined,
    });
    res.json({ data: matches, total: matches.length });
  } catch (err: any) {
    next(err);
  }
});

// GET /api/history/bisect - list bisect results
router.get('/bisect', (req: Request, res: Response, next: NextFunction) => {
  try {
    const results = getBisectResults({
      job_id: req.query.job_id as string | undefined,
    });
    res.json({ data: results, total: results.length });
  } catch (err: any) {
    next(err);
  }
});

// POST /api/history/analyze-commit - analyze a commit by SHA
router.post('/analyze-commit', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { project_id, sha } = req.body;
    if (!project_id || !sha) { res.status(400).json({ error: 'project_id and sha required' }); return; }

    const project = getProjectById(Number(project_id));
    if (!project?.path) { res.status(404).json({ error: 'project not found or has no local path' }); return; }

    const { analyzeCommit } = await import('../pipeline/history/patch-analyzer.js');
    const result = await analyzeCommit(project.path, sha);
    res.json(result);
  } catch (err: any) {
    next(err);
  }
});

// GET /api/history/project/:id - full history for a project
router.get('/project/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(String(req.params.id));
    const project = getProjectById(id);
    if (!project) { res.status(404).json({ error: 'project not found' }); return; }

    const matches = getCveProjectMatches({ project_id: id });

    // Git analysis (if available)
    let gitAnalysis: any = null;
    if (project.path) {
      try {
        const { analyzeRecentCommits } = await import('../pipeline/git-analyzer.js');
        gitAnalysis = await analyzeRecentCommits(project.path, 100);
      } catch { /* may not be a git repo */ }
    }

    res.json({
      project,
      cve_matches: matches,
      git_analysis: gitAnalysis,
    });
  } catch (err: any) {
    next(err);
  }
});

export default router;

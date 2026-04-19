/**
 * AI workflow routes - exposes the Parasoft-inspired capabilities:
 * triage memory, root-cause clustering, autonomous remediation, change impact.
 */

import { Router, type Request, type Response, NextFunction } from 'express';
import {
  listTriagePatterns,
  applyTriageMemory,
  applyTriageMemoryToBatch,
  recordTriageDecision,
} from '../ai/triage-memory.js';
import { clusterByRootCause } from '../ai/root-cause.js';
import { autonomousRemediate, generateFix } from '../ai/remediation.js';
import { analyzeChangeImpact } from '../pipeline/change-impact.js';
import { cveMatchProbability } from '../ai/cve-match-probability.js';
import { recommendAssignees } from '../ai/assignment-recommender.js';
import { getScanFindings, getScanFindingById, getProjectById } from '../db.js';
import { rateLimit } from '../utils/rate-limit.js';

const router = Router();

/**
 * Rate-limiters scoped to the expense of each endpoint class:
 *   - aiCallLimiter: hits an LLM provider (costs money + tokens)
 *   - writeLimiter:  mutates git state (creates branches/commits/PRs)
 *   - readLimiter:   read-only DB/git queries (cheap)
 *
 * All are per-IP sliding windows. Tune per ops feedback.
 */
const aiCallLimiter = rateLimit({
  windowMs: 60_000,
  max: 20,
  message: 'AI endpoint rate limit exceeded. Slow down to avoid unexpected AI costs.',
});
const writeLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  message: 'Autonomous-remediation rate limit exceeded. Review PRs before creating more.',
});
const readLimiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  message: 'Read rate limit exceeded.',
});

// ──────────────────────────────────────────────────────────────────────────
//  Triage memory
// ──────────────────────────────────────────────────────────────────────────

router.get('/triage-memory/patterns', readLimiter, (req: Request, res: Response, next: NextFunction) => {
  try {
    const decision = req.query.decision as 'accept' | 'reject' | 'ignore' | undefined;
    const minTotal = req.query.min ? Number(req.query.min) : 1;
    const limit = req.query.limit ? Number(req.query.limit) : 100;
    const rows = listTriagePatterns({ decision, minTotal, limit });
    res.json({ data: rows, total: rows.length });
  } catch (err: any) {
    next(err);
  }
});

router.get('/triage-memory/suggest/:findingId', readLimiter, (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.findingId);
    const f = getScanFindingById(id);
    if (!f) { res.status(404).json({ error: 'finding not found' }); return; }
    res.json(applyTriageMemory(f));
  } catch (err: any) {
    next(err);
  }
});

router.post('/triage-memory/apply-batch', readLimiter, (req: Request, res: Response, next: NextFunction) => {
  try {
    const { pipeline_id, project_id, threshold } = req.body as {
      pipeline_id?: string;
      project_id?: number;
      threshold?: number;
    };
    if (!pipeline_id && !project_id) {
      res.status(400).json({ error: 'pipeline_id or project_id required' });
      return;
    }
    const findings = getScanFindings({ pipeline_id, project_id, status: 'pending' });
    const result = applyTriageMemoryToBatch(findings, threshold ?? 0.7);
    res.json({ ...result, total: findings.length });
  } catch (err: any) {
    next(err);
  }
});

router.post('/triage-memory/record', readLimiter, (req: Request, res: Response, next: NextFunction) => {
  try {
    const { finding_id, decision } = req.body as {
      finding_id: number;
      decision: 'accept' | 'reject' | 'ignore';
    };
    if (!finding_id || !['accept', 'reject', 'ignore'].includes(decision)) {
      res.status(400).json({ error: 'finding_id + decision required' });
      return;
    }
    const f = getScanFindingById(finding_id);
    if (!f) { res.status(404).json({ error: 'finding not found' }); return; }
    recordTriageDecision(f, decision);
    res.json({ success: true });
  } catch (err: any) {
    next(err);
  }
});

// ──────────────────────────────────────────────────────────────────────────
//  Root-cause clustering
// ──────────────────────────────────────────────────────────────────────────

router.post('/root-cause/cluster', aiCallLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { pipeline_id, project_id, semantic = false, maxSemanticInput } = req.body as {
      pipeline_id?: string;
      project_id?: number;
      semantic?: boolean;
      maxSemanticInput?: number;
    };
    if (!pipeline_id && !project_id) {
      res.status(400).json({ error: 'pipeline_id or project_id required' });
      return;
    }
    const findings = getScanFindings({ pipeline_id, project_id });
    const clusters = await clusterByRootCause(findings, { semantic, maxSemanticInput });
    res.json({ clusters, total_findings: findings.length, total_clusters: clusters.length });
  } catch (err: any) {
    next(err);
  }
});

// ──────────────────────────────────────────────────────────────────────────
//  Autonomous remediation
// ──────────────────────────────────────────────────────────────────────────

router.post('/remediation/generate-fix', aiCallLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { finding_id } = req.body as { finding_id: number };
    const f = getScanFindingById(finding_id);
    if (!f) { res.status(404).json({ error: 'finding not found' }); return; }
    const project = f.project_id ? getProjectById(f.project_id) : null;
    if (!project?.path) { res.status(400).json({ error: 'project has no local path' }); return; }
    const fix = await generateFix(f, project.path);
    res.json(fix);
  } catch (err: any) {
    next(err);
  }
});

router.post('/remediation/autonomous', writeLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { finding_id, mode = 'dry-run', branch, draft, requireClean } = req.body as {
      finding_id: number;
      mode?: 'dry-run' | 'branch' | 'pr' | 'direct';
      branch?: string;
      draft?: boolean;
      requireClean?: boolean;
    };
    if (!finding_id) {
      res.status(400).json({ error: 'finding_id required' });
      return;
    }
    const result = await autonomousRemediate(finding_id, { mode, branch, draft, requireClean });
    res.json(result);
  } catch (err: any) {
    next(err);
  }
});

// ──────────────────────────────────────────────────────────────────────────
//  Change impact analysis
// ──────────────────────────────────────────────────────────────────────────

router.post('/change-impact/analyze', readLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { project_id, since_ref, head_ref, statuses } = req.body as {
      project_id: number;
      since_ref: string;
      head_ref?: string;
      statuses?: string[];
    };
    if (!project_id || !since_ref) {
      res.status(400).json({ error: 'project_id and since_ref required' });
      return;
    }
    const result = await analyzeChangeImpact(project_id, since_ref, { headRef: head_ref, statuses });
    res.json(result);
  } catch (err: any) {
    next(err);
  }
});

// ──────────────────────────────────────────────────────────────────────────
//  CVE match probability
// ──────────────────────────────────────────────────────────────────────────

router.post('/cve-match/score', readLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { finding_id, topK, minScore, candidatePool } = req.body as {
      finding_id: number;
      topK?: number;
      minScore?: number;
      candidatePool?: number;
    };
    const f = getScanFindingById(finding_id);
    if (!f) { res.status(404).json({ error: 'finding not found' }); return; }
    const result = await cveMatchProbability(f, { topK, minScore, candidatePool });
    res.json(result);
  } catch (err: any) {
    next(err);
  }
});

router.post('/cve-match/score-batch', aiCallLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { pipeline_id, project_id, topK, minScore } = req.body as {
      pipeline_id?: string;
      project_id?: number;
      topK?: number;
      minScore?: number;
    };
    if (!pipeline_id && !project_id) {
      res.status(400).json({ error: 'pipeline_id or project_id required' });
      return;
    }
    const findings = getScanFindings({ pipeline_id, project_id, status: 'pending' });
    const results = [];
    for (const f of findings) {
      const r = await cveMatchProbability(f, { topK, minScore });
      if (r.probability > 0) results.push(r);
    }
    results.sort((a, b) => b.probability - a.probability);
    res.json({ data: results, total: results.length, total_findings_checked: findings.length });
  } catch (err: any) {
    next(err);
  }
});

// ──────────────────────────────────────────────────────────────────────────
//  Assignment recommendation
// ──────────────────────────────────────────────────────────────────────────

router.post('/assignment/recommend', readLimiter, async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { finding_id, topK, perSignalLimit } = req.body as {
      finding_id: number;
      topK?: number;
      perSignalLimit?: number;
    };
    const f = getScanFindingById(finding_id);
    if (!f) { res.status(404).json({ error: 'finding not found' }); return; }
    if (!f.project_id) { res.status(400).json({ error: 'finding has no project' }); return; }
    const project = getProjectById(f.project_id);
    if (!project?.path) { res.status(400).json({ error: 'project has no local path' }); return; }
    const result = await recommendAssignees(f, project.path, { topK, perSignalLimit });
    res.json(result);
  } catch (err: any) {
    next(err);
  }
});

export default router;

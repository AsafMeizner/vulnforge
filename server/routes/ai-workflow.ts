/**
 * AI workflow routes - exposes the Parasoft-inspired capabilities:
 * triage memory, root-cause clustering, autonomous remediation, change impact.
 */

import { Router, type Request, type Response } from 'express';
import {
  listTriagePatterns,
  applyTriageMemory,
  applyTriageMemoryToBatch,
  recordTriageDecision,
} from '../ai/triage-memory.js';
import { clusterByRootCause } from '../ai/root-cause.js';
import { autonomousRemediate, generateFix } from '../ai/remediation.js';
import { analyzeChangeImpact } from '../pipeline/change-impact.js';
import { getScanFindings, getScanFindingById, getProjectById } from '../db.js';

const router = Router();

// ──────────────────────────────────────────────────────────────────────────
//  Triage memory
// ──────────────────────────────────────────────────────────────────────────

router.get('/triage-memory/patterns', (req: Request, res: Response) => {
  try {
    const decision = req.query.decision as 'accept' | 'reject' | 'ignore' | undefined;
    const minTotal = req.query.min ? Number(req.query.min) : 1;
    const limit = req.query.limit ? Number(req.query.limit) : 100;
    const rows = listTriagePatterns({ decision, minTotal, limit });
    res.json({ data: rows, total: rows.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/triage-memory/suggest/:findingId', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.findingId);
    const f = getScanFindingById(id);
    if (!f) { res.status(404).json({ error: 'finding not found' }); return; }
    res.json(applyTriageMemory(f));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/triage-memory/apply-batch', (req: Request, res: Response) => {
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
    res.status(500).json({ error: err.message });
  }
});

router.post('/triage-memory/record', (req: Request, res: Response) => {
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
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────
//  Root-cause clustering
// ──────────────────────────────────────────────────────────────────────────

router.post('/root-cause/cluster', async (req: Request, res: Response) => {
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
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────
//  Autonomous remediation
// ──────────────────────────────────────────────────────────────────────────

router.post('/remediation/generate-fix', async (req: Request, res: Response) => {
  try {
    const { finding_id } = req.body as { finding_id: number };
    const f = getScanFindingById(finding_id);
    if (!f) { res.status(404).json({ error: 'finding not found' }); return; }
    const project = f.project_id ? getProjectById(f.project_id) : null;
    if (!project?.path) { res.status(400).json({ error: 'project has no local path' }); return; }
    const fix = await generateFix(f, project.path);
    res.json(fix);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/remediation/autonomous', async (req: Request, res: Response) => {
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
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────
//  Change impact analysis
// ──────────────────────────────────────────────────────────────────────────

router.post('/change-impact/analyze', async (req: Request, res: Response) => {
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
    res.status(500).json({ error: err.message });
  }
});

export default router;

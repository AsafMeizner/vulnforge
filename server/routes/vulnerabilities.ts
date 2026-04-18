import { Router, Request, Response } from 'express';
import {
  getAllVulnerabilities,
  countVulnerabilities,
  getVulnerabilityById,
  createVulnerability,
  updateVulnerability,
  deleteVulnerability,
  deleteVulnerabilitiesBulk,
  type VulnFilters,
} from '../db.js';

const router = Router();

// GET /api/vulnerabilities
router.get('/', (req: Request, res: Response) => {
  try {
    const filters: VulnFilters = {};

    if (req.query.severity) filters.severity = String(req.query.severity);
    if (req.query.status) filters.status = String(req.query.status);
    if (req.query.project_id) filters.project_id = Number(req.query.project_id);
    if (req.query.search) filters.search = String(req.query.search);
    if (req.query.sort) filters.sort = String(req.query.sort);
    if (req.query.order) filters.order = String(req.query.order);
    if (req.query.limit) filters.limit = Math.min(Number(req.query.limit), 500);
    if (req.query.offset) filters.offset = Number(req.query.offset);

    const vulns = getAllVulnerabilities(filters);
    // Return true total (without pagination) for page controls
    const total = (filters.limit !== undefined || filters.offset !== undefined)
      ? countVulnerabilities(filters)
      : vulns.length;
    // Map project_name from JOIN to the `project` field the frontend expects
    const data = vulns.map((v: any) => ({
      ...v,
      project: v.project_name || v.project || '',
    }));
    res.json({ data, total });
  } catch (err: any) {
    console.error('GET /vulnerabilities error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/vulnerabilities/:id
router.get('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const vuln = getVulnerabilityById(id);
    if (!vuln) {
      res.status(404).json({ error: 'Vulnerability not found' });
      return;
    }
    res.json(vuln);
  } catch (err: any) {
    console.error(`GET /vulnerabilities/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/vulnerabilities/bulk-delete
// Body: { ids: number[] }
// Dedicated bulk path so the UI's multi-select delete needs one
// request instead of N serial DELETEs. Must be declared BEFORE the
// `/:id` param routes below, otherwise Express tries to parse
// "bulk-delete" as a numeric id and returns "Invalid ID".
router.post('/bulk-delete', (req: Request, res: Response) => {
  try {
    const rawIds = (req.body || {}).ids;
    if (!Array.isArray(rawIds)) {
      res.status(400).json({ error: 'ids: number[] required in body' });
      return;
    }
    const ids = rawIds
      .map((n: unknown) => Number(n))
      .filter((n) => Number.isFinite(n) && n > 0);
    if (ids.length === 0) {
      res.status(400).json({ error: 'ids must contain at least one positive integer' });
      return;
    }
    const deleted = deleteVulnerabilitiesBulk(ids);
    res.json({ deleted });
  } catch (err: any) {
    console.error('POST /vulnerabilities/bulk-delete error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/vulnerabilities
router.post('/', (req: Request, res: Response) => {
  try {
    const body = req.body;
    if (!body.title) {
      res.status(400).json({ error: 'title is required' });
      return;
    }
    const id = createVulnerability(body);
    const created = getVulnerabilityById(id);
    res.status(201).json(created);
  } catch (err: any) {
    console.error('POST /vulnerabilities error:', err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/vulnerabilities/:id
router.put('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const existing = getVulnerabilityById(id);
    if (!existing) {
      res.status(404).json({ error: 'Vulnerability not found' });
      return;
    }
    updateVulnerability(id, req.body);
    const updated = getVulnerabilityById(id);
    res.json(updated);
  } catch (err: any) {
    console.error(`PUT /vulnerabilities/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/vulnerabilities/:id/verify  - toggle verified flag
router.put('/:id/verify', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }
    const existing = getVulnerabilityById(id);
    if (!existing) { res.status(404).json({ error: 'Not found' }); return; }
    const newVal = existing.verified ? 0 : 1;
    updateVulnerability(id, { verified: newVal } as any);
    res.json(getVulnerabilityById(id));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/vulnerabilities/:id/false-positive  - mark as false positive
router.put('/:id/false-positive', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }
    const existing = getVulnerabilityById(id);
    if (!existing) { res.status(404).json({ error: 'Not found' }); return; }
    updateVulnerability(id, { false_positive: 1, status: 'Wont Fix' } as any);
    res.json(getVulnerabilityById(id));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/vulnerabilities/:id
router.delete('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const existing = getVulnerabilityById(id);
    if (!existing) {
      res.status(404).json({ error: 'Vulnerability not found' });
      return;
    }
    deleteVulnerability(id);
    res.status(204).send();
  } catch (err: any) {
    console.error(`DELETE /vulnerabilities/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

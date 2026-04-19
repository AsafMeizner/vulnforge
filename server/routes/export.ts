import { Router, type Request, type Response, NextFunction } from 'express';
import {
  getAuditLog,
  getVulnerabilityById,
  logAudit,
} from '../db.js';
import { exportSarif, exportCveJson, exportWorkspace } from '../pipeline/export/formats.js';

const router = Router();

// ── SARIF export ─────────────────────────────────────────────────────────
router.get('/sarif', (req: Request, res: Response, next: NextFunction) => {
  try {
    const filters: { project_id?: number } = {};
    if (req.query.project_id) filters.project_id = Number(req.query.project_id);
    const sarif = exportSarif(filters);
    logAudit({ action: 'export', entity_type: 'vulnerability', entity_id: 'all', details: JSON.stringify({ format: 'sarif', filters }) });
    res.setHeader('Content-Disposition', 'attachment; filename=vulnforge-findings.sarif.json');
    res.json(sarif);
  } catch (err: any) {
    next(err);
  }
});

// ── CVE JSON export (per finding) ────────────────────────────────────────
router.get('/cve/:vuln_id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const vuln = getVulnerabilityById(Number(req.params.vuln_id));
    if (!vuln) { res.status(404).json({ error: 'finding not found' }); return; }
    const cve = exportCveJson(vuln);
    logAudit({ action: 'export', entity_type: 'vulnerability', entity_id: String(vuln.id), details: JSON.stringify({ format: 'cve-json' }) });
    res.setHeader('Content-Disposition', `attachment; filename=vulnforge-${vuln.id}.cve.json`);
    res.json(cve);
  } catch (err: any) {
    next(err);
  }
});

// ── Full workspace export (JSON backup) ─────────────────────────────────
router.get('/workspace', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const dump = await exportWorkspace();
    logAudit({ action: 'export', entity_type: 'workspace', entity_id: 'full', details: JSON.stringify({ format: 'json' }) });
    res.setHeader('Content-Disposition', `attachment; filename=vulnforge-workspace-${Date.now()}.json`);
    res.json(dump);
  } catch (err: any) {
    next(err);
  }
});

// ── Audit log ────────────────────────────────────────────────────────────
router.get('/audit', (req: Request, res: Response, next: NextFunction) => {
  try {
    const filters: any = {};
    if (req.query.entity_type) filters.entity_type = String(req.query.entity_type);
    if (req.query.entity_id) filters.entity_id = String(req.query.entity_id);
    if (req.query.action) filters.action = String(req.query.action);
    if (req.query.limit) filters.limit = Number(req.query.limit);
    const log = getAuditLog(filters);
    res.json({ data: log, total: log.length });
  } catch (err: any) {
    next(err);
  }
});

export default router;

import { Router, Request, Response } from 'express';
import {
  getScanFindings,
  getScanFindingById,
  updateScanFinding,
  countScanFindings,
  createVulnerability,
  getVulnerabilityById,
} from '../db.js';

const router = Router();

// ── GET /api/scan-findings?scan_id=X ──────────────────────────────────────

router.get('/', (req: Request, res: Response) => {
  try {
    const filters: { scan_id?: number; project_id?: number; pipeline_id?: string; status?: string } = {};

    if (req.query.scan_id) filters.scan_id = Number(req.query.scan_id);
    if (req.query.project_id) filters.project_id = Number(req.query.project_id);
    if (req.query.pipeline_id) filters.pipeline_id = String(req.query.pipeline_id);
    if (req.query.status) filters.status = String(req.query.status);

    const findings = getScanFindings(filters);
    const counts = countScanFindings(filters);
    res.json({ data: findings, counts, total: findings.length });
  } catch (err: any) {
    console.error('GET /scan-findings error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /api/scan-findings/:id/accept ─────────────────────────────────────
// Promotes a staged finding into the vulnerabilities table.

router.put('/:id/accept', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }

    const sf = getScanFindingById(id);
    if (!sf) { res.status(404).json({ error: 'Scan finding not found' }); return; }
    if (sf.status === 'accepted') { res.status(409).json({ error: 'Already accepted' }); return; }

    // Promote to vulnerabilities
    const vulnId = createVulnerability({
      project_id: sf.project_id,
      title: sf.title,
      severity: sf.severity || 'Medium',
      status: 'Open',
      cvss: sf.cvss || undefined,
      cwe: sf.cwe || undefined,
      file: sf.file || undefined,
      line_start: sf.line_start,
      line_end: sf.line_end,
      code_snippet: sf.code_snippet || undefined,
      description: sf.description || undefined,
      tool_name: sf.tool_name || undefined,
      confidence: sf.confidence === 'High' ? 0.9 : sf.confidence === 'Medium' ? 0.6 : 0.3,
      verified: 0,
      false_positive: 0,
    });

    updateScanFinding(id, { status: 'accepted' });

    const vuln = getVulnerabilityById(vulnId);
    res.json({ success: true, vuln_id: vulnId, vuln });
  } catch (err: any) {
    console.error(`PUT /scan-findings/${req.params.id}/accept error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /api/scan-findings/:id/reject ─────────────────────────────────────

router.put('/:id/reject', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }

    const sf = getScanFindingById(id);
    if (!sf) { res.status(404).json({ error: 'Scan finding not found' }); return; }

    const reason = req.body?.reason || 'Manually rejected';
    updateScanFinding(id, { status: 'rejected', rejection_reason: reason });
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/scan-findings/bulk-accept ───────────────────────────────────

router.post('/bulk-accept', (req: Request, res: Response) => {
  try {
    const { ids } = req.body as { ids: number[] };
    if (!Array.isArray(ids) || ids.length === 0) {
      res.status(400).json({ error: 'ids array required' });
      return;
    }

    const vulnIds: number[] = [];
    const errors: string[] = [];

    for (const id of ids) {
      const sf = getScanFindingById(id);
      if (!sf || sf.status === 'accepted') continue;

      try {
        const vulnId = createVulnerability({
          project_id: sf.project_id,
          title: sf.title,
          severity: sf.severity || 'Medium',
          status: 'Open',
          cvss: sf.cvss || undefined,
          cwe: sf.cwe || undefined,
          file: sf.file || undefined,
          line_start: sf.line_start,
          line_end: sf.line_end,
          code_snippet: sf.code_snippet || undefined,
          description: sf.description || undefined,
          tool_name: sf.tool_name || undefined,
          confidence: sf.confidence === 'High' ? 0.9 : sf.confidence === 'Medium' ? 0.6 : 0.3,
          verified: 0,
          false_positive: 0,
        });
        updateScanFinding(id, { status: 'accepted' });
        vulnIds.push(vulnId);
      } catch (e: any) {
        errors.push(`id ${id}: ${e.message}`);
      }
    }

    res.json({ accepted: vulnIds.length, vuln_ids: vulnIds, errors });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/scan-findings/bulk-reject ───────────────────────────────────

router.post('/bulk-reject', (req: Request, res: Response) => {
  try {
    const { ids, reason } = req.body as { ids: number[]; reason?: string };
    if (!Array.isArray(ids) || ids.length === 0) {
      res.status(400).json({ error: 'ids array required' });
      return;
    }

    let count = 0;
    for (const id of ids) {
      const sf = getScanFindingById(id);
      if (!sf) continue;
      updateScanFinding(id, { status: 'rejected', rejection_reason: reason || 'Bulk rejected' });
      count++;
    }

    res.json({ rejected: count });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/scan-findings/accept-all?scan_id=X ─────────────────────────

router.post('/accept-all', (req: Request, res: Response) => {
  try {
    const scan_id = req.query.scan_id ? Number(req.query.scan_id) : undefined;
    const pending = getScanFindings({ scan_id, status: 'pending' });

    const vulnIds: number[] = [];
    for (const sf of pending) {
      try {
        const vulnId = createVulnerability({
          project_id: sf.project_id,
          title: sf.title,
          severity: sf.severity || 'Medium',
          status: 'Open',
          cvss: sf.cvss || undefined,
          cwe: sf.cwe || undefined,
          file: sf.file || undefined,
          line_start: sf.line_start,
          line_end: sf.line_end,
          code_snippet: sf.code_snippet || undefined,
          description: sf.description || undefined,
          tool_name: sf.tool_name || undefined,
          confidence: sf.confidence === 'High' ? 0.9 : sf.confidence === 'Medium' ? 0.6 : 0.3,
          verified: 0,
          false_positive: 0,
        });
        updateScanFinding(sf.id!, { status: 'accepted' });
        vulnIds.push(vulnId);
      } catch { /* skip individual errors */ }
    }

    res.json({ accepted: vulnIds.length, vuln_ids: vulnIds });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/scan-findings/ai-review?scan_id=X ───────────────────────────
// Sends pending findings to AI for batch triage recommendation.

router.post('/ai-review', async (req: Request, res: Response) => {
  try {
    const scan_id = req.query.scan_id ? Number(req.query.scan_id) : undefined;
    const pending = getScanFindings({ scan_id, status: 'pending' });

    if (pending.length === 0) {
      res.json({ message: 'No pending findings to review', reviews: [] });
      return;
    }

    const { routeAI } = await import('../ai/router.js');

    const prompt = `You are a security triage expert. Review these ${pending.length} scan findings and for each one determine if it should be ACCEPTED (real vulnerability) or REJECTED (false positive).

Findings:
${pending.slice(0, 30).map((f, i) => `
${i + 1}. ID: ${f.id}
   Title: ${f.title}
   Severity: ${f.severity}
   File: ${f.file || 'N/A'}
   Confidence: ${f.confidence}
   Description: ${(f.description || '').substring(0, 200)}
`).join('')}

Respond ONLY with a JSON array like:
[{"id": 1, "decision": "accept", "reason": "..."},  {"id": 2, "decision": "reject", "reason": "..."}]
No markdown fences. Just the JSON array.`;

    const response = await routeAI({
      messages: [{ role: 'user', content: prompt }],
      systemPrompt: 'You are a security triage expert. Output only valid JSON.',
      temperature: 0.1,
      maxTokens: 4096,
    });

    let reviews: Array<{ id: number; decision: 'accept' | 'reject'; reason: string }> = [];
    try {
      const cleaned = response.content.replace(/^```[a-z]*\n?/m, '').replace(/```$/m, '').trim();
      reviews = JSON.parse(cleaned);
    } catch {
      res.json({ message: 'AI response could not be parsed', raw: response.content, reviews: [] });
      return;
    }

    // Apply the AI decisions
    let accepted = 0, rejected = 0;
    for (const review of reviews) {
      const sf = getScanFindingById(review.id);
      if (!sf || sf.status !== 'pending') continue;

      if (review.decision === 'accept') {
        try {
          createVulnerability({
            project_id: sf.project_id,
            title: sf.title,
            severity: sf.severity || 'Medium',
            status: 'Open',
            cvss: sf.cvss || undefined,
            cwe: sf.cwe || undefined,
            file: sf.file || undefined,
            line_start: sf.line_start,
            line_end: sf.line_end,
            code_snippet: sf.code_snippet || undefined,
            description: sf.description || undefined,
            tool_name: sf.tool_name || undefined,
            confidence: sf.confidence === 'High' ? 0.9 : sf.confidence === 'Medium' ? 0.6 : 0.3,
            verified: 0,
            false_positive: 0,
          });
          updateScanFinding(review.id, { status: 'accepted', rejection_reason: review.reason });
          accepted++;
        } catch { /* skip */ }
      } else {
        updateScanFinding(review.id, { status: 'rejected', rejection_reason: review.reason });
        rejected++;
      }
    }

    res.json({ accepted, rejected, reviews });
  } catch (err: any) {
    console.error('POST /scan-findings/ai-review error:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

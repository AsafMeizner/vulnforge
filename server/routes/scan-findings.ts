import { Router, Request, Response } from 'express';
import {
  getScanFindings,
  getScanFindingById,
  updateScanFinding,
  countScanFindings,
  createVulnerability,
  getVulnerabilityById,
  type ScanFinding,
} from '../db.js';
import { recordTriageDecision } from '../ai/triage-memory.js';

const router = Router();

// Record a user's accept/reject/ignore into the triage-memory store so
// future scans of this pattern can auto-triage. Safe: errors swallowed,
// never blocks the primary response.
function rememberTriage(findingId: number, decision: 'accept' | 'reject' | 'ignore'): void {
  try {
    const f = getScanFindingById(findingId);
    if (f) recordTriageDecision(f, decision);
  } catch (err) {
    console.warn('[triage-memory] record failed:', (err as Error).message);
  }
}

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
    rememberTriage(id, 'reject');
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
        rememberTriage(id, 'accept');
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
      rememberTriage(id, 'reject');
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

// ── POST /api/scan-findings/:id/deep-triage ───────────────────────────────
// Run the 4-stage AI chain on a single finding. Returns the result
// (which also gets persisted on scan_findings.ai_verification).
// Slow - each call makes 4 LLM round-trips.
router.post('/:id/deep-triage', async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }
    const f = getScanFindingById(id);
    if (!f) { res.status(404).json({ error: 'not found' }); return; }

    const { deepTriageFinding } = await import('../ai/deep-triage.js');
    const result = await deepTriageFinding(f);
    updateScanFinding(id, { ai_verification: JSON.stringify(result) });
    res.json({ id, result });
  } catch (err: any) {
    console.error('POST /scan-findings/:id/deep-triage error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/scan-findings/deep-triage-batch ─────────────────────────────
// Body: { ids?: number[], pipeline_id?: string, project_id?: number,
//         status?: string, limit?: number, concurrency?: number }
// Runs the 4-stage chain on a set of findings. Always returns 202 and
// broadcasts progress over the WebSocket (category='deep-triage'). If
// none of ids/pipeline_id/project_id is supplied, batches all
// status='pending' findings.
router.post('/deep-triage-batch', (req: Request, res: Response) => {
  try {
    const body = req.body as {
      ids?: number[];
      pipeline_id?: string;
      project_id?: number;
      status?: string;
      limit?: number;
      concurrency?: number;
    };

    // Select the batch up front so the response knows how many to expect.
    let findings: ScanFinding[] = [];
    if (Array.isArray(body.ids) && body.ids.length) {
      findings = body.ids
        .map((id) => getScanFindingById(Number(id)))
        .filter((f): f is ScanFinding => !!f);
    } else {
      findings = getScanFindings({
        pipeline_id: body.pipeline_id,
        project_id: body.project_id,
        status: body.status || 'pending',
      });
    }
    if (body.limit && body.limit > 0) findings = findings.slice(0, body.limit);

    const batchId = 'dtb-' + Math.random().toString(36).slice(2, 10);
    res.status(202).json({ batchId, total: findings.length });

    // Detached worker. Bounded concurrency so we don't stack 100 LLM
    // requests against a single Ollama instance.
    const concurrency = Math.min(
      Math.max(1, Number(body.concurrency) || 2),
      8,
    );

    (async () => {
      let done = 0;
      let verified = 0;
      let rejected = 0;
      let errored = 0;

      const { deepTriageFinding } = await import('../ai/deep-triage.js');
      const { broadcastProgress } = await import('../ws.js');

      // `broadcastProgress` expects a constrained shape
      // ({ step, detail?, progress?, status? }) so we serialise the
      // batch stats into `detail` as JSON. Frontend parses it.
      function emit(opts: { completed?: boolean; last_id?: number } = {}): void {
        broadcastProgress('deep-triage', batchId, {
          step: opts.completed ? 'deep-triage complete' : 'deep-triage',
          progress: findings.length === 0 ? 100 : Math.round((done / findings.length) * 100),
          status: opts.completed ? 'complete' : 'running',
          detail: JSON.stringify({
            done,
            total: findings.length,
            verified,
            rejected,
            errored,
            last_id: opts.last_id,
            completed: opts.completed === true,
          }),
        });
      }

      emit();

      let idx = 0;
      async function worker(): Promise<void> {
        while (idx < findings.length) {
          const i = idx++;
          const f = findings[i];
          try {
            const result = await deepTriageFinding(f);
            updateScanFinding(f.id, { ai_verification: JSON.stringify(result) });
            if (result.verdict === 'verified' || result.verdict === 'likely') verified++;
            else if (result.verdict === 'rejected') rejected++;
          } catch (err: any) {
            errored++;
            console.warn(`[deep-triage] finding ${f.id} failed:`, err?.message);
          }
          done++;
          emit({ last_id: f.id });
        }
      }
      const workers: Promise<void>[] = [];
      for (let w = 0; w < Math.min(concurrency, findings.length); w++) workers.push(worker());
      await Promise.all(workers);
      emit({ completed: true });
      console.log(`[deep-triage] batch ${batchId} done - verified=${verified} rejected=${rejected} errored=${errored}`);
    })().catch((err) => console.error('[deep-triage] batch worker crashed:', err));
  } catch (err: any) {
    console.error('POST /scan-findings/deep-triage-batch error:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

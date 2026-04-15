// ── AI auto-triage pipeline ────────────────────────────────────────────────
//
// After a scan completes, this module takes each new vulnerability ID,
// calls the AI provider with the structured triage prompt, parses the
// response, and writes ai_triage + ai_summary back to the DB row.
//
// It emits 'triage:complete' and 'triage:error' on the shared scanQueue
// EventEmitter so WebSocket handlers can broadcast progress.

import {
  getVulnerabilityById,
  updateVulnerability,
  getProjectById,
  type Vulnerability,
} from '../db.js';
import { routeAI } from './router.js';
import {
  buildTriagePrompt,
  parseTriageResponse,
  TRIAGE_SYSTEM_PROMPT,
  type TriageInput,
  type TriageResult,
} from './prompts/triage.js';
import { scanQueue } from '../scanner/queue.js';

// ── Single-finding triage ──────────────────────────────────────────────────

/**
 * Triage a single vulnerability by its DB id.
 * Writes ai_triage (full JSON string) and ai_summary to the vulnerability row.
 * Emits 'triage:complete' | 'triage:error' on the scanQueue event bus.
 */
export async function triageFinding(vulnId: number): Promise<void> {
  const vuln = getVulnerabilityById(vulnId);
  if (!vuln) {
    const err = new Error(`Vulnerability ${vulnId} not found`);
    scanQueue.emit('triage:error', vulnId, err);
    throw err;
  }

  // Resolve project name for context
  let projectName = 'unknown';
  if (vuln.project_id) {
    try {
      const proj = getProjectById(vuln.project_id);
      if (proj) projectName = proj.name;
    } catch { /* non-fatal */ }
  }

  const input: TriageInput = {
    title:               vuln.title,
    tool_output:         vuln.description || '',
    file:                vuln.file || '',
    code_snippet:        vuln.code_snippet || '',
    project:             projectName,
    severity:            vuln.severity,
    cwe:                 vuln.cwe,
    cvss:                vuln.cvss,
    description:         vuln.description,
    impact:              vuln.impact,
    reproduction_steps:  vuln.reproduction_steps,
  };

  const userMessage = buildTriagePrompt(input);

  let raw: string;
  try {
    const response = await routeAI({
      messages: [{ role: 'user', content: userMessage }],
      systemPrompt: TRIAGE_SYSTEM_PROMPT,
      temperature: 0.1,   // low temperature for deterministic structured output
      maxTokens: 1024,
    });
    raw = response.content;
  } catch (err: any) {
    console.error(`[Pipeline] AI call failed for vuln ${vulnId}:`, err.message);
    scanQueue.emit('triage:error', vulnId, err);
    throw err;
  }

  let result: TriageResult;
  try {
    result = parseTriageResponse(raw);
  } catch (parseErr: any) {
    console.error(`[Pipeline] Failed to parse AI triage for vuln ${vulnId}:`, parseErr.message);
    // Store the raw response anyway so it isn't lost
    updateVulnerability(vulnId, { ai_triage: raw });
    scanQueue.emit('triage:error', vulnId, parseErr);
    throw parseErr;
  }

  // Persist structured JSON + human-readable summary
  const updates: Partial<Vulnerability> = {
    ai_triage: JSON.stringify(result),
    ai_summary: result.summary,
  };

  // Optionally promote AI-derived fields when they are absent in the original
  if (!vuln.cvss && result.cvss_score)  updates.cvss = result.cvss_score;
  if (!vuln.cvss_vector && result.cvss_vector) updates.cvss_vector = result.cvss_vector;
  if (!vuln.cwe && result.cwe)          updates.cwe = result.cwe;

  updateVulnerability(vulnId, updates);
  scanQueue.emit('triage:complete', vulnId, result);

  console.log(`[Pipeline] Triage complete for vuln ${vulnId}: ${result.severity} / tier ${result.tier}`);
}

// ── Batch triage ───────────────────────────────────────────────────────────

/**
 * Triage multiple vulnerabilities sequentially (to avoid hammering the AI
 * provider with parallel requests). Failures are logged and skipped — the
 * function does not throw if individual triages fail.
 */
export async function triageAll(vulnIds: number[]): Promise<void> {
  console.log(`[Pipeline] Starting batch triage for ${vulnIds.length} findings`);
  for (const id of vulnIds) {
    try {
      await triageFinding(id);
    } catch (err: any) {
      console.error(`[Pipeline] Skipping vuln ${id} after error:`, err.message);
    }
  }
  console.log(`[Pipeline] Batch triage complete for ${vulnIds.length} findings`);
}

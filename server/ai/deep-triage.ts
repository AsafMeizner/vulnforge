/**
 * AI Deep Triage - a 4-stage prompt chain that takes a raw scanner
 * finding, verifies whether it's real, plans a test to prove it,
 * writes a proof-of-concept, and returns a final verdict.
 *
 * Stage 1: VERIFY - "Given this code and the scanner's claim, is this
 *          a real vulnerability? What makes it real or a false positive?"
 * Stage 2: TEST   - "Write a test case (input, expected-behaviour) that
 *          would demonstrate the bug if it is real."
 * Stage 3: WRITE  - "Write a minimal proof-of-concept that triggers the
 *          bug. Keep it to one runnable snippet."
 * Stage 4: VERDICT - "Summarise: verified / rejected / needs-runtime,
 *          plus a confidence score 0-100 and one-paragraph rationale."
 *
 * Results are stored as JSON in scan_findings.ai_verification with the
 * shape documented in DeepTriageResult below. The Review UI reads this
 * blob to render the "Verified / Rejected" filter and the per-stage
 * output tabs.
 */
import { routeAI } from './router.js';
import { describeTool } from '../lib/tool-descriptions.js';
import type { ScanFinding } from '../db.js';

export type DeepTriageVerdict =
  | 'verified'        // confirmed exploitable
  | 'likely'          // almost certainly a bug, not yet proved exploitable
  | 'rejected'        // false positive - not a real issue
  | 'needs-runtime'   // can't tell statically; need to run / fuzz
  | 'insufficient';   // scanner output too thin to reason about

export interface DeepTriageResult {
  /** Schema version so future shape changes stay backwards-compatible. */
  v: 1;
  /** Terminal verdict after all four stages. */
  verdict: DeepTriageVerdict;
  /** 0-100 - how sure the model is about the verdict. */
  confidence: number;
  /** One-paragraph summary, suitable for the Review card. */
  rationale: string;
  /** Raw text output of each stage (handy for debugging + the "raw" tab). */
  stages: {
    verify?: string;
    test?: string;
    write?: string;
    verdict?: string;
  };
  /** Timestamps for progress UIs. */
  started_at: string;
  completed_at?: string;
  /** Which model answered (for auditability / cost accounting). */
  model?: string;
}

function shortSystemPrompt(): string {
  return (
    'You are a senior application-security engineer triaging findings ' +
    'from static analysis tools. Answer concisely. Do not speculate ' +
    'beyond what the code shows. When unsure, say so explicitly.'
  );
}

function buildContext(finding: ScanFinding): string {
  const toolDesc = describeTool(finding.tool_name || '') || '';
  const parts: string[] = [];
  parts.push(`Scanner: ${finding.tool_name || 'unknown'}`);
  if (toolDesc) parts.push(`Scanner check: ${toolDesc}`);
  parts.push(`Severity (tool-reported): ${finding.severity}`);
  if (finding.confidence) parts.push(`Confidence (tool-reported): ${finding.confidence}`);
  if (finding.cwe) parts.push(`CWE: ${finding.cwe}`);
  if (finding.file) parts.push(`File: ${finding.file}${finding.line_start ? ':' + finding.line_start : ''}`);
  parts.push(`Title: ${finding.title || '(none)'}`);
  if (finding.description) parts.push(`\nDescription:\n${finding.description}`);
  if (finding.code_snippet) parts.push(`\nCode snippet:\n\`\`\`\n${finding.code_snippet}\n\`\`\``);
  return parts.join('\n');
}

async function callStage(
  stageName: string,
  userPrompt: string,
  systemPrompt: string,
): Promise<string> {
  const resp = await routeAI({
    task: 'verify',
    messages: [{ role: 'user', content: userPrompt }],
    systemPrompt,
    temperature: 0.2,
    maxTokens: 1024,
  });
  return (resp.content || '').trim();
}

/**
 * Parse the terminal "verdict" stage into a structured verdict + score.
 * Falls back to `insufficient` if the model didn't return something we
 * can parse - the caller keeps the raw rationale so nothing is lost.
 */
function parseVerdict(
  text: string,
): { verdict: DeepTriageVerdict; confidence: number; rationale: string } {
  const lower = text.toLowerCase();

  let verdict: DeepTriageVerdict = 'insufficient';
  if (/verdict[^a-z]*:[^a-z]*verified/.test(lower) || /\bverified\b/.test(lower)) verdict = 'verified';
  else if (/verdict[^a-z]*:[^a-z]*likely/.test(lower) || /\blikely\b.*\breal\b/.test(lower)) verdict = 'likely';
  else if (/verdict[^a-z]*:[^a-z]*rejected/.test(lower) || /\bfalse positive\b/.test(lower)) verdict = 'rejected';
  else if (/\bneeds?.?runtime\b/.test(lower) || /\bruntime verification\b/.test(lower)) verdict = 'needs-runtime';

  // Look for "confidence: NN" or "NN% confidence"
  let confidence = 50;
  const pct = text.match(/confidence[^\d]*(\d{1,3})/i) || text.match(/(\d{1,3})\s*%/);
  if (pct) {
    const n = Number(pct[1]);
    if (!Number.isNaN(n) && n >= 0 && n <= 100) confidence = n;
  }

  // Use the first non-empty line as a rationale preview if the model
  // didn't explicitly demarcate one.
  const rationale = text.slice(0, 800);

  return { verdict, confidence, rationale };
}

/**
 * Run the full 4-stage chain on one finding. Slow-ish (one LLM call
 * per stage). Callers that want to run many should use a concurrency-
 * limited fan-out.
 */
export async function deepTriageFinding(finding: ScanFinding): Promise<DeepTriageResult> {
  const system = shortSystemPrompt();
  const ctx = buildContext(finding);

  const started_at = new Date().toISOString();
  const stages: DeepTriageResult['stages'] = {};

  // Stage 1 — VERIFY
  const verifyPrompt =
    `${ctx}\n\n` +
    'Task: decide whether this is a real vulnerability based on the code shown.\n' +
    'Think about: is the sink actually reachable? is the input actually attacker- ' +
    'controllable? is there any mitigating check the scanner missed?\n' +
    'Answer in 3-6 lines.';
  stages.verify = await callStage('verify', verifyPrompt, system);

  // Stage 2 — TEST
  const testPrompt =
    `${ctx}\n\n` +
    `Verification notes so far:\n${stages.verify}\n\n` +
    'Task: sketch a test case that would prove this bug is real.\n' +
    'Describe: the input, the expected observable (crash, wrong output, ' +
    'leaked secret, etc.), and how you would set up the test fixture.\n' +
    'Be concrete - write it as a bulleted checklist.';
  stages.test = await callStage('test', testPrompt, system);

  // Stage 3 — WRITE (proof of concept)
  const writePrompt =
    `${ctx}\n\n` +
    `Test plan:\n${stages.test}\n\n` +
    'Task: write a minimal proof-of-concept snippet that triggers the bug.\n' +
    'One runnable file or one shell pipeline. Avoid scaffolding that is not ' +
    'strictly necessary. If a PoC is not possible without more context, say so ' +
    'and explain what context is missing.';
  stages.write = await callStage('write', writePrompt, system);

  // Stage 4 — VERDICT
  const verdictPrompt =
    `${ctx}\n\n` +
    `Verification:\n${stages.verify}\n\n` +
    `Test plan:\n${stages.test}\n\n` +
    `Proof of concept:\n${stages.write}\n\n` +
    'Task: give a final verdict.\n' +
    'Reply with exactly these lines at the top:\n' +
    '  Verdict: <verified | likely | rejected | needs-runtime | insufficient>\n' +
    '  Confidence: <0-100>\n' +
    'Then 2-4 lines of rationale citing what in the code + your analysis drives the verdict.';
  stages.verdict = await callStage('verdict', verdictPrompt, system);

  const parsed = parseVerdict(stages.verdict);
  return {
    v: 1,
    verdict: parsed.verdict,
    confidence: parsed.confidence,
    rationale: parsed.rationale,
    stages,
    started_at,
    completed_at: new Date().toISOString(),
  };
}

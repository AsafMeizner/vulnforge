// ── AI triage prompt builder ───────────────────────────────────────────────

export interface TriageInput {
  title: string;
  tool_output: string;
  file: string;
  code_snippet: string;
  project: string;
  severity?: string;
  cwe?: string;
  cvss?: string;
  description?: string;
  impact?: string;
  reproduction_steps?: string;
}

/** Expected shape of the JSON object the AI must return. */
export interface TriageResult {
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  exploitability: 'High' | 'Medium' | 'Low' | 'None';
  false_positive_risk: 'High' | 'Medium' | 'Low';
  confidence: number;          // 0.0 – 1.0
  summary: string;             // one paragraph, plain text
  suggested_fix: string;       // concrete remediation advice
  tier: 'A' | 'B' | 'C';      // A=private disclosure, B=open PR, C=internal
  cvss_score?: string;         // e.g. "7.8"
  cvss_vector?: string;        // e.g. "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
  cwe?: string;                // e.g. "CWE-190"
  reasoning: string;           // one–two sentences explaining the tier/severity choice
}

export const TRIAGE_SYSTEM_PROMPT = `\
You are an expert security researcher and vulnerability analyst specialising in \
memory-safety bugs, cryptographic weaknesses, and protocol parsing errors in \
open-source C/C++, Python, and Go projects.

Your task is to triage a security finding produced by an automated static-analysis \
tool and return a JSON object - nothing else, no markdown fences, no commentary \
outside the JSON.

Severity tiers (align with CVSS v3.1):
  Critical  CVSS 9.0+   Pre-auth RCE / memory corruption with reliable PoC
  High      CVSS 7.0–8.9 Significant impact but requires some precondition
  Medium    CVSS 4.0–6.9 Limited exploitability or authenticated-only
  Low       CVSS < 4.0   Informational, hardening improvement

Tier classification (matches project RALPH loop):
  A  Private disclosure - deterministic, pre-auth or zero-click, real deployments affected
  B  Open PR - real defect but needs chaining or has limited real-world impact
  C  Internal note - theoretical, OOM-gated, or already mitigated by documented threat model

False-positive risk:
  High   - Static tool pattern with many benign matches; no concrete trigger identified
  Medium - Pattern is suspicious but requires manual confirmation
  Low    - Reproduction steps present, code snippet directly shows the flaw

Return ONLY a valid JSON object matching this TypeScript interface:
{
  "severity": "Critical" | "High" | "Medium" | "Low",
  "exploitability": "High" | "Medium" | "Low" | "None",
  "false_positive_risk": "High" | "Medium" | "Low",
  "confidence": <number 0.0–1.0>,
  "summary": "<one-paragraph plain-text summary>",
  "suggested_fix": "<concrete remediation>",
  "tier": "A" | "B" | "C",
  "cvss_score": "<optional string e.g. 7.8>",
  "cvss_vector": "<optional CVSS vector string>",
  "cwe": "<optional e.g. CWE-190>",
  "reasoning": "<1-2 sentences justifying tier and severity>"
}`;

/**
 * Build the user-facing triage prompt for a single finding.
 *
 * The system prompt already instructs the model to return only JSON, so the
 * user turn just provides structured context about the finding.
 */
export function buildTriagePrompt(finding: TriageInput): string {
  const lines: string[] = [];

  lines.push(`Project: ${finding.project || 'unknown'}`);
  lines.push(`Finding title: ${finding.title}`);

  if (finding.severity) lines.push(`Reported severity: ${finding.severity}`);
  if (finding.cwe)      lines.push(`CWE: ${finding.cwe}`);
  if (finding.cvss)     lines.push(`CVSS: ${finding.cvss}`);
  if (finding.file)     lines.push(`Location: ${finding.file}`);

  if (finding.description) {
    lines.push('');
    lines.push('Description:');
    lines.push(finding.description.trim());
  }

  if (finding.impact) {
    lines.push('');
    lines.push('Impact:');
    lines.push(finding.impact.trim());
  }

  if (finding.reproduction_steps) {
    lines.push('');
    lines.push('Reproduction steps:');
    lines.push(finding.reproduction_steps.trim());
  }

  if (finding.code_snippet) {
    lines.push('');
    lines.push('Code snippet:');
    lines.push('```');
    lines.push(finding.code_snippet.trim());
    lines.push('```');
  }

  if (finding.tool_output) {
    // Truncate very long tool output to avoid blowing the context window
    const excerpt = finding.tool_output.length > 4000
      ? finding.tool_output.slice(0, 4000) + '\n... [truncated]'
      : finding.tool_output;
    lines.push('');
    lines.push('Full tool output excerpt:');
    lines.push(excerpt);
  }

  lines.push('');
  lines.push('Return the JSON triage object now.');

  return lines.join('\n');
}

/**
 * Parse the raw AI text response into a TriageResult.
 * Handles the common case where the model wraps JSON in markdown fences.
 * Throws if the text cannot be parsed as JSON.
 */
export function parseTriageResponse(raw: string): TriageResult {
  // Strip optional markdown code fences
  let text = raw.trim();
  const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenceMatch) {
    text = fenceMatch[1].trim();
  }

  // Try to extract a JSON object even if there is surrounding text
  const objMatch = text.match(/\{[\s\S]*\}/);
  if (objMatch) {
    text = objMatch[0];
  }

  const parsed = JSON.parse(text) as TriageResult;

  // Validate required fields minimally so callers can rely on them
  const required = ['severity', 'exploitability', 'false_positive_risk', 'confidence', 'summary', 'suggested_fix', 'tier'] as const;
  for (const key of required) {
    if (parsed[key] === undefined || parsed[key] === null) {
      throw new Error(`AI triage response missing required field: ${key}`);
    }
  }

  return parsed;
}

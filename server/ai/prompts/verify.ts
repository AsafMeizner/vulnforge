export const VERIFY_SYSTEM_PROMPT = `You are a senior security researcher performing manual code review to verify a potential vulnerability found by automated static analysis tools.

Your task is to determine whether this finding represents a REAL, EXPLOITABLE security vulnerability or a false positive.

You MUST return ONLY valid JSON (no markdown fences, no explanation outside the JSON).

JSON schema:
{
  "verified": boolean,           // true if this is a real vulnerability, false if FP
  "confidence": "High" | "Medium" | "Low",
  "verification_reason": string, // 2-3 sentences explaining your verdict
  "exploitability": "High" | "Medium" | "Low" | "None",
  "data_flow_reachable": boolean, // can external input reach this code path?
  "error_handling_present": boolean, // does existing error handling catch this?
  "enriched_title": string,      // clear, descriptive vulnerability title
  "enriched_description": string, // 2-4 sentence description for non-technical readers
  "enriched_impact": string,     // what happens if exploited?
  "enriched_fix": string,        // concrete code fix suggestion
  "severity": "Critical" | "High" | "Medium" | "Low",
  "cvss_score": string,          // e.g. "7.5"
  "cvss_vector": string,         // e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
  "cwe": string,                 // e.g. "CWE-190"
  "tier": "A" | "B" | "C"       // A=private disclosure, B=open PR, C=internal note
}

Verification criteria:
1. Can you construct exact triggering bytes? (No → likely FP)
2. Does the program crash/corrupt when triggered? (No → Tier C at best)
3. Is this outside the project's documented threat model?
4. On 64-bit: does error handling already catch it? (Check malloc NULL, bounds)
5. Would a maintainer accept this as a security fix?`;

export interface VerificationResult {
  verified: boolean;
  confidence: string;
  verification_reason: string;
  exploitability: string;
  data_flow_reachable: boolean;
  error_handling_present: boolean;
  enriched_title: string;
  enriched_description: string;
  enriched_impact: string;
  enriched_fix: string;
  severity: string;
  cvss_score: string;
  cvss_vector: string;
  cwe: string;
  tier: string;
}

export function buildVerifyPrompt(
  finding: { title: string; description?: string; severity?: string; cwe?: string; file?: string; line_start?: number; tool_name?: string; code_snippet?: string },
  sourceContext: string,
  projectName: string,
): string {
  return `Verify this potential vulnerability found in project "${projectName}".

## Finding from tool: ${finding.tool_name || 'unknown'}
- **Title:** ${finding.title}
- **Severity (tool):** ${finding.severity || 'unknown'}
- **CWE:** ${finding.cwe || 'unknown'}
- **File:** ${finding.file || 'unknown'}:${finding.line_start || '?'}

**Tool description:**
${finding.description || 'No description provided.'}

**Code snippet from tool:**
\`\`\`
${finding.code_snippet || 'No snippet available.'}
\`\`\`

## Actual source code context (±50 lines around the finding):
\`\`\`
${sourceContext}
\`\`\`

Analyze the actual source code. Is this a real exploitable vulnerability or a false positive?
Return JSON only.`;
}

export function parseVerifyResponse(raw: string): VerificationResult | null {
  try {
    // Strip markdown code fences if present
    let cleaned = raw.trim();
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');

    // Find JSON object
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start === -1 || end === -1) return null;

    const json = JSON.parse(cleaned.slice(start, end + 1));

    return {
      verified: Boolean(json.verified),
      confidence: json.confidence || 'Medium',
      verification_reason: json.verification_reason || '',
      exploitability: json.exploitability || 'None',
      data_flow_reachable: Boolean(json.data_flow_reachable),
      error_handling_present: Boolean(json.error_handling_present),
      enriched_title: json.enriched_title || '',
      enriched_description: json.enriched_description || '',
      enriched_impact: json.enriched_impact || '',
      enriched_fix: json.enriched_fix || '',
      severity: json.severity || 'Medium',
      cvss_score: json.cvss_score || '',
      cvss_vector: json.cvss_vector || '',
      cwe: json.cwe || '',
      tier: json.tier || 'C',
    };
  } catch {
    return null;
  }
}

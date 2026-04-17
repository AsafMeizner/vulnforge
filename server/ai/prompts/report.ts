// ── Report Generation Prompt Templates ─────────────────────────────────────
//
// Four report types:
//   disclosure  - Full markdown disclosure (security-solver TEMPLATE.md format)
//   email       - Plain text email body for private disclosure
//   advisory    - GitHub Security Advisory structured format
//   summary     - Executive summary for non-technical audience

export type ReportType = 'disclosure' | 'email' | 'advisory' | 'summary';

export interface ReportPrompt {
  systemPrompt: string;
  userMessage: string;
}

// ── Shared context builder ──────────────────────────────────────────────────

function buildVulnContext(vuln: Record<string, any>): string {
  const lines: string[] = [];
  lines.push(`Project: ${vuln.project_name || vuln.project || 'Unknown'}`);
  lines.push(`Title: ${vuln.title}`);
  if (vuln.severity)    lines.push(`Severity: ${vuln.severity}`);
  if (vuln.cvss)        lines.push(`CVSS Score: ${vuln.cvss}`);
  if (vuln.cvss_vector) lines.push(`CVSS Vector: ${vuln.cvss_vector}`);
  if (vuln.cwe)         lines.push(`CWE: ${vuln.cwe}`);
  if (vuln.file)        lines.push(`File: ${vuln.file}${vuln.line_start ? `:${vuln.line_start}` : ''}`);
  if (vuln.method)      lines.push(`Function: ${vuln.method}`);

  if (vuln.description) {
    lines.push('\nDescription:');
    lines.push(vuln.description.trim());
  }
  if (vuln.impact) {
    lines.push('\nImpact:');
    lines.push(vuln.impact.trim());
  }
  if (vuln.reproduction_steps) {
    lines.push('\nReproduction Steps:');
    lines.push(vuln.reproduction_steps.trim());
  }
  if (vuln.code_snippet) {
    lines.push('\nCode Snippet:');
    lines.push('```c');
    lines.push(vuln.code_snippet.trim());
    lines.push('```');
  }
  if (vuln.suggested_fix) {
    lines.push('\nSuggested Fix:');
    lines.push(vuln.suggested_fix.trim());
  }
  if (vuln.ai_triage) {
    lines.push('\nAI Triage Analysis:');
    // Try to parse as JSON for a cleaner summary
    try {
      const triage = JSON.parse(vuln.ai_triage);
      lines.push(`Tier: ${triage.tier}, Exploitability: ${triage.exploitability}`);
      if (triage.reasoning) lines.push(`Reasoning: ${triage.reasoning}`);
    } catch {
      lines.push(String(vuln.ai_triage).slice(0, 800));
    }
  }

  return lines.join('\n');
}

// ── Disclosure report prompt ────────────────────────────────────────────────

function buildDisclosurePrompt(vuln: Record<string, any>): ReportPrompt {
  const isGitHub = !!(vuln.advisory_url?.includes('github.com') || vuln.submit_to?.toLowerCase().includes('github'));

  const systemPrompt = `\
You are an expert security researcher writing a professional vulnerability disclosure report.
Write in clear, technical English. Be precise and factual.
Do not exaggerate or speculate beyond what the data supports.
Follow responsible disclosure best practices.`;

  const format = isGitHub
    ? `GitHub Security Advisory format with these sections:
## Title
## Version tested
## Summary
## Details  (include file:line references and code snippets with fenced blocks)
## PoC
## Impact
## Suggested fix  (use a diff code block)
## Discovery method
Wrap the whole report between --- BEGIN REPORT --- and --- END REPORT ---`
    : `Email disclosure format with these sections:
- Plain text only, NO markdown
- To: [security contact if known, else "Security Team"]
- Subject: [concise title]
--- BEGIN EMAIL BODY --- marker
Hi [team],
[version tested]
Description
-----------
Impact
------
Suggested fix
-------------
Best regards,
[Security Researcher]
--- END EMAIL BODY --- marker`;

  const userMessage = `Write a full vulnerability disclosure report for this finding.

${buildVulnContext(vuln)}

Use ${format}.

Produce only the report content - no preamble, no "here is the report", no meta-commentary.`;

  return { systemPrompt, userMessage };
}

// ── Email report prompt ─────────────────────────────────────────────────────

function buildEmailPrompt(vuln: Record<string, any>): ReportPrompt {
  const systemPrompt = `\
You are a security researcher writing a private disclosure email.
Write in plain text - absolutely no markdown, no asterisks, no backticks, no fenced code blocks.
Indented code uses 2 spaces. Tone is professional and collaborative.
Be specific: include version numbers, file paths, and line numbers.`;

  const userMessage = `Write a private disclosure email for this vulnerability.

${buildVulnContext(vuln)}

Format:
To: [security email if known, else "security@[project].org"]
Subject: [Brief, accurate title - not alarming but clear]

[Email body - plain text only]

The email must include:
1. Brief introduction (who you are, responsible disclosure intent)
2. Version/commit tested
3. Description with exact file:line references (use plain indented code, NOT markdown)
4. Impact assessment
5. Suggested fix with pseudocode or diff (plain text)
6. 90-day disclosure timeline statement
7. Offer to assist with fix verification

Produce only the email text - no meta-commentary.`;

  return { systemPrompt, userMessage };
}

// ── GitHub Advisory prompt ──────────────────────────────────────────────────

function buildAdvisoryPrompt(vuln: Record<string, any>): ReportPrompt {
  const systemPrompt = `\
You are a security researcher filling out a GitHub Security Advisory form.
Produce structured content that maps exactly to GitHub's advisory fields.
Use markdown formatting. Be precise and technical.`;

  const userMessage = `Generate a GitHub Security Advisory for this vulnerability.

${buildVulnContext(vuln)}

Output these fields in order, each as a markdown section:

### Ecosystem
[The package ecosystem: PyPI, npm, Maven, Go, etc. - or "n/a" for C/C++ native projects]

### Package Name
[Package or project name]

### Affected Versions
[Version range, e.g. "< 1.2.3" or "all versions as of YYYY-MM-DD"]

### Patched Version
[Version where fix landed, or "none yet"]

### Severity
[Critical / High / Medium / Low] - CVSS ${vuln.cvss || 'score TBD'}

### CVSS Vector
${vuln.cvss_vector || '[CVSS:3.1/... vector]'}

### CWE
${vuln.cwe || '[CWE-XXX: name]'}

### Summary
[2-3 sentence plain-language summary]

### Description
[Technical description with file:line references and code snippets]

### Proof of Concept
[PoC steps or code]

### Impact
[What an attacker can achieve]

### References
[Links to commits, issues, or related advisories]

Produce only the advisory content - no preamble.`;

  return { systemPrompt, userMessage };
}

// ── Executive summary prompt ────────────────────────────────────────────────

function buildSummaryPrompt(vuln: Record<string, any>): ReportPrompt {
  const systemPrompt = `\
You are a security analyst writing an executive briefing for a non-technical audience.
Avoid jargon. Focus on business impact, risk, and what needs to happen.
Keep it concise - under 400 words. No code blocks. No technical minutiae.`;

  const userMessage = `Write an executive summary for this security vulnerability.

${buildVulnContext(vuln)}

Structure:
1. What is the issue? (1-2 sentences, plain language)
2. What is at risk? (data, systems, users - what can go wrong)
3. How serious is it? (use Critical/High/Medium/Low and explain what that means in plain terms)
4. Who is affected? (which users/deployments/environments)
5. What needs to happen? (immediate actions, timeline, owner)
6. Has a fix been identified? (yes/no, brief description of fix approach)

Write in paragraph form (no bullet points). Target audience: non-technical manager or executive.
Produce only the summary - no preamble.`;

  return { systemPrompt, userMessage };
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Build the prompt pair (system + user) for the requested report type.
 * The caller passes the raw vulnerability DB row as a plain object.
 */
export function buildReportPrompt(
  vuln: Record<string, any>,
  type: ReportType | string
): ReportPrompt {
  switch (type) {
    case 'disclosure': return buildDisclosurePrompt(vuln);
    case 'email':      return buildEmailPrompt(vuln);
    case 'advisory':   return buildAdvisoryPrompt(vuln);
    case 'summary':    return buildSummaryPrompt(vuln);
    default:           return buildDisclosurePrompt(vuln);
  }
}

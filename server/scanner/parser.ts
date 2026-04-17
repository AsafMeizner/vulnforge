import type { Vulnerability } from '../db.js';

// ── Severity mapping ───────────────────────────────────────────────────────

const SEVERITY_MAP: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  med: 'Medium',
  low: 'Low',
  info: 'Low',
  informational: 'Low',
};

function normalizeSeverity(raw: string): string {
  return SEVERITY_MAP[raw.toLowerCase()] || 'Medium';
}

// ── Line/file parsing ──────────────────────────────────────────────────────

function parseFileLocation(loc: string): { file: string; lineStart?: number; lineEnd?: number } {
  // Patterns: "file.c:123", "file.c:123-456", "path/to/file.c:123"
  const match = loc.match(/^(.+?):(\d+)(?:-(\d+))?$/);
  if (match) {
    return {
      file: match[1].trim(),
      lineStart: parseInt(match[2], 10),
      lineEnd: match[3] ? parseInt(match[3], 10) : undefined,
    };
  }
  return { file: loc.trim() };
}

// ── Code block extraction ──────────────────────────────────────────────────

function extractCodeBlock(text: string): string | undefined {
  const match = text.match(/```[\w]*\n?([\s\S]*?)```/);
  return match ? match[1].trim() : undefined;
}

// ── Section extraction ─────────────────────────────────────────────────────

function extractSection(text: string, heading: string): string | undefined {
  // Match a markdown heading and capture text until the next heading
  const escaped = heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`(?:^|\\n)#{1,4}\\s*${escaped}[:\\s]*([\\s\\S]*?)(?=\\n#{1,4}\\s|$)`, 'i');
  const match = text.match(regex);
  return match ? match[1].trim() : undefined;
}

// ── Main finding header patterns ───────────────────────────────────────────

// Pattern 1: ### [SEVERITY] path/to/file.c:123 - Title
// Pattern 2: ### SEVERITY: Title (file.c:123)
// Pattern 3: ## Finding N: Title
// Pattern 4: **[CRITICAL]** Title at file.c:123

const FINDING_PATTERNS = [
  // ### [CRITICAL] src/foo.c:123 - Buffer overflow in parse()
  /^#{1,4}\s*\[?(CRITICAL|HIGH|MEDIUM|MED|LOW|INFO|INFORMATIONAL)\]?\s+([^\n]+)/im,
  // ### CRITICAL: Buffer overflow
  /^#{1,4}\s*(CRITICAL|HIGH|MEDIUM|MED|LOW|INFO):\s*([^\n]+)/im,
  // **[HIGH]** Title
  /\*\*\[?(CRITICAL|HIGH|MEDIUM|MED|LOW|INFO)\]?\*\*\s*([^\n]+)/im,
];

interface RawFinding {
  severity: string;
  rawTitle: string;
  body: string;
  startIndex: number;
}

function splitIntoFindings(markdown: string): RawFinding[] {
  const findings: RawFinding[] = [];

  // Split on heading-based finding blocks
  // Try: "### [SEV]" or "### SEV:" or "## Finding"
  const splitRegex = /(?=^#{1,4}\s*(?:\[)?(CRITICAL|HIGH|MEDIUM|MED|LOW|INFO(?:RMATIONAL)?)\]?\s)/im;
  const blocks = markdown.split(splitRegex);

  // blocks will have the captured severity groups interspersed - reassemble
  const assembled: string[] = [];
  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];
    if (/^(CRITICAL|HIGH|MEDIUM|MED|LOW|INFO(?:RMATIONAL)?)$/i.test(block.trim())) {
      // This is a captured group - prepend to next block
      if (i + 1 < blocks.length) {
        assembled.push(block + blocks[i + 1]);
        i++;
      }
    } else if (block.trim()) {
      assembled.push(block);
    }
  }

  for (const block of assembled) {
    const lines = block.split('\n');
    const headerLine = lines[0];

    let severity = 'Medium';
    let title = '';

    // Try each header pattern
    for (const pattern of FINDING_PATTERNS) {
      const m = headerLine.match(pattern);
      if (m) {
        severity = normalizeSeverity(m[1]);
        title = m[2].trim();
        break;
      }
    }

    if (!title) {
      // Fallback: use full header line stripped of markdown
      title = headerLine.replace(/^#+\s*/, '').replace(/\*\*/g, '').trim();
    }

    if (title) {
      findings.push({
        severity,
        rawTitle: title,
        body: block,
        startIndex: markdown.indexOf(block),
      });
    }
  }

  return findings;
}

// ── Parse a single finding block ───────────────────────────────────────────

function parseFinding(finding: RawFinding, projectId?: number): Partial<Vulnerability> {
  const { severity, rawTitle, body } = finding;

  // Extract file location from title
  // Title might be: "heap overflow in foo() at src/bar.c:123"
  // or: "src/bar.c:123 - integer overflow"
  let title = rawTitle;
  let file: string | undefined;
  let lineStart: number | undefined;
  let lineEnd: number | undefined;

  // Look for "at file.c:123" pattern in title
  const atFileMatch = rawTitle.match(/\bat\s+([^\s]+:\d+(?:-\d+)?)\s*$/i);
  if (atFileMatch) {
    const loc = parseFileLocation(atFileMatch[1]);
    file = loc.file;
    lineStart = loc.lineStart;
    lineEnd = loc.lineEnd;
    title = rawTitle.replace(atFileMatch[0], '').trim().replace(/\s*-\s*$/, '').trim();
  }

  // Look for "file.c:123 - title" pattern in title
  const fileFirstMatch = rawTitle.match(/^([^\s]+:\d+(?:-\d+)?)\s*[-–-]+\s*(.+)$/);
  if (!file && fileFirstMatch) {
    const loc = parseFileLocation(fileFirstMatch[1]);
    file = loc.file;
    lineStart = loc.lineStart;
    lineEnd = loc.lineEnd;
    title = fileFirstMatch[2].trim();
  }

  // If still no file, look for "**File:**" or "File:" in body
  if (!file) {
    const fileMatch = body.match(/\*\*(?:File|Location|Path)\*\*[:\s]+([^\n]+)/i) ||
                      body.match(/(?:File|Location|Path):\s+([^\n]+)/i);
    if (fileMatch) {
      const loc = parseFileLocation(fileMatch[1].trim());
      file = loc.file;
      lineStart = loc.lineStart;
      lineEnd = loc.lineEnd;
    }
  }

  // Extract code snippet
  const codeSnippet = extractCodeBlock(body);

  // Extract description - text between header and first sub-heading
  const descMatch = body.match(/^#{1,4}[^\n]+\n+([\s\S]*?)(?=\n#{1,4}\s|$)/);
  let description = descMatch ? descMatch[1].trim() : '';
  // Remove code blocks from description
  description = description.replace(/```[\s\S]*?```/g, '').trim();

  // Extract named sections
  const impact = extractSection(body, 'Impact') ||
                 extractSection(body, 'Security Impact');
  const reproduction = extractSection(body, 'Reproduction') ||
                       extractSection(body, 'PoC') ||
                       extractSection(body, 'Proof of Concept') ||
                       extractSection(body, 'Trigger');
  const suggestedFix = extractSection(body, 'Fix') ||
                       extractSection(body, 'Suggested Fix') ||
                       extractSection(body, 'Recommendation') ||
                       extractSection(body, 'Mitigation');

  // Extract CWE
  const cweMatch = body.match(/CWE-(\d+)/i);
  const cwe = cweMatch ? `CWE-${cweMatch[1]}` : undefined;

  // Extract CVSS score
  const cvssMatch = body.match(/CVSS[:\s]+([0-9.]+)/i);
  const cvss = cvssMatch ? cvssMatch[1] : undefined;

  // Extract CVSS vector
  const cvssVectorMatch = body.match(/(CVSS:\d+\.\d+\/[A-Z:A-Z\/]+)/);
  const cvssVector = cvssVectorMatch ? cvssVectorMatch[1] : undefined;

  // Confidence estimation based on presence of reproduction steps + code snippet
  let confidence = 0.5;
  if (codeSnippet) confidence += 0.2;
  if (reproduction) confidence += 0.2;
  if (cvss) confidence += 0.1;

  return {
    project_id: projectId,
    title: title.replace(/\*\*/g, '').trim(),
    severity,
    status: 'Open',
    cvss,
    cvss_vector: cvssVector,
    cwe,
    file,
    line_start: lineStart,
    line_end: lineEnd,
    code_snippet: codeSnippet,
    description: description || undefined,
    impact,
    reproduction_steps: reproduction,
    suggested_fix: suggestedFix,
    confidence: Math.min(confidence, 1.0),
    verified: 0,
    false_positive: 0,
  };
}

// ── Public API ─────────────────────────────────────────────────────────────

export function parseToolOutput(
  markdown: string,
  projectId?: number,
  toolName?: string
): Partial<Vulnerability>[] {
  if (!markdown || !markdown.trim()) return [];

  const findings = splitIntoFindings(markdown);
  const results: Partial<Vulnerability>[] = [];

  for (const finding of findings) {
    const vuln = parseFinding(finding, projectId);
    if (vuln.title) {
      if (toolName) vuln.tool_name = toolName;
      results.push(vuln);
    }
  }

  // Fallback: if no structured findings, check for simple list
  if (results.length === 0) {
    const bulletMatches = markdown.match(/^[-*]\s+(.+)$/gm);
    if (bulletMatches) {
      for (const bullet of bulletMatches.slice(0, 20)) {
        const title = bullet.replace(/^[-*]\s+/, '').trim();
        if (title.length > 10) {
          results.push({
            project_id: projectId,
            title,
            severity: 'Medium',
            status: 'Open',
            tool_name: toolName,
            confidence: 0.3,
            verified: 0,
            false_positive: 0,
          });
        }
      }
    }
  }

  return results;
}

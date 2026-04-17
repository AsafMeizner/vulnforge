/**
 * Assumption Extractor - ask the AI to read a function and list its
 * implicit assumptions (input non-null, bounds, invariants, etc.) so
 * researchers can manually mark which are enforced by callers.
 */
import { readFileSync, existsSync } from 'fs';
import path from 'path';
import { routeAI } from '../../ai/router.js';

export interface ExtractedAssumption {
  id: number;
  text: string;
  category: 'input' | 'state' | 'invariant' | 'bounds' | 'ordering' | 'other';
  severity: 'critical' | 'high' | 'medium' | 'low';
  enforced_by?: string;  // filled by user: 'caller' | 'validator' | 'type_system' | 'none'
}

export interface AssumptionReport {
  function_name: string;
  file: string;
  line_start: number;
  line_end: number;
  source_snippet: string;
  assumptions: ExtractedAssumption[];
  raw_ai_response: string;
}

const SYSTEM_PROMPT = `You are a formal verification expert. Given a source code function, list ALL the implicit assumptions the function makes about its inputs and state.

For each assumption, categorize it:
- "input"     - assumptions about input parameters (non-null, valid range, etc.)
- "state"     - assumptions about global/object state
- "invariant" - assumptions that should hold before and after the function
- "bounds"    - assumptions about sizes, lengths, array indices
- "ordering"  - assumptions about event/call ordering (thread safety, initialization)
- "other"

Rate the severity of each assumption being violated:
- "critical" - violation = memory corruption, RCE, auth bypass
- "high"     - violation = crash, data corruption, significant logic error
- "medium"   - violation = wrong result, graceful failure
- "low"      - violation = minor issue, recoverable

Return ONLY a JSON object:
{
  "assumptions": [
    { "text": "input buffer must not be NULL", "category": "input", "severity": "critical" },
    ...
  ]
}

Be exhaustive but precise. Each assumption should be a single, testable statement.`;

/** Read a function's source from a file (heuristic - find the line with function_name). */
export function extractFunctionSource(
  filePath: string,
  functionName: string,
  maxLines = 100,
): { source: string; line_start: number; line_end: number } | null {
  if (!existsSync(filePath)) return null;
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');

  // Find a line that looks like a function definition matching functionName
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // C/C++/Java-ish: returntype functionName(
    if (new RegExp(`\\b${functionName}\\s*\\(`).test(line) && !/\b(if|while|switch|return|for)\b/.test(line.split(functionName)[0])) {
      // Prefer lines that look like a definition (contain { or end with ) and not ;)
      if (line.includes('{') || (!line.trim().endsWith(';') && i + 1 < lines.length && lines[i + 1].includes('{'))) {
        startIdx = i;
        break;
      }
    }
  }

  if (startIdx === -1) return null;

  // Walk forward balancing braces to find function end
  let braceDepth = 0;
  let opened = false;
  let endIdx = startIdx;
  for (let i = startIdx; i < Math.min(lines.length, startIdx + maxLines); i++) {
    for (const ch of lines[i]) {
      if (ch === '{') { braceDepth++; opened = true; }
      if (ch === '}') braceDepth--;
    }
    if (opened && braceDepth === 0) { endIdx = i; break; }
    endIdx = i;
  }

  return {
    source: lines.slice(startIdx, endIdx + 1).join('\n'),
    line_start: startIdx + 1,
    line_end: endIdx + 1,
  };
}

/** Analyze a function via the AI and return structured assumptions. */
export async function extractAssumptions(
  filePath: string,
  functionName: string,
): Promise<AssumptionReport> {
  const extracted = extractFunctionSource(filePath, functionName);
  if (!extracted) {
    throw new Error(`Could not locate function "${functionName}" in ${filePath}`);
  }

  const userMessage = [
    `Function: ${functionName}`,
    `File: ${path.basename(filePath)}`,
    '',
    'Source:',
    '```',
    extracted.source,
    '```',
    '',
    'List all implicit assumptions. Return JSON only.',
  ].join('\n');

  const response = await routeAI({
    messages: [{ role: 'user', content: userMessage }],
    systemPrompt: SYSTEM_PROMPT,
    temperature: 0.1,
    maxTokens: 2048,
    task: 'deep-analyze' as any,
  });

  // Parse
  let parsed: { assumptions: Array<{ text: string; category: string; severity: string }> } = { assumptions: [] };
  try {
    let jsonText = response.content.trim();
    const fenceMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch) jsonText = fenceMatch[1].trim();
    const objMatch = jsonText.match(/\{[\s\S]*\}/);
    if (objMatch) jsonText = objMatch[0];
    parsed = JSON.parse(jsonText);
  } catch (err: any) {
    console.warn(`[Assumptions] Parse failed: ${err.message}`);
  }

  const assumptions: ExtractedAssumption[] = (parsed.assumptions || []).map((a: any, idx: number) => ({
    id: idx + 1,
    text: a.text || '',
    category: (a.category as any) || 'other',
    severity: (a.severity as any) || 'medium',
  }));

  return {
    function_name: functionName,
    file: filePath,
    line_start: extracted.line_start,
    line_end: extracted.line_end,
    source_snippet: extracted.source.slice(0, 4000),
    assumptions,
    raw_ai_response: response.content,
  };
}

/**
 * Hypothesis auto-generator - read a project's top files and ask the AI
 * to brainstorm a prioritized list of "places to investigate".
 */
export async function generateHypotheses(
  projectPath: string,
  maxFiles = 20,
): Promise<Array<{ title: string; rationale: string; file?: string; priority: string }>> {
  // Grab a sample of security-sensitive files from the project
  const { readdirSync, statSync } = await import('fs');
  const files: string[] = [];

  function walk(dir: string, depth: number): void {
    if (depth > 3 || files.length >= maxFiles) return;
    try {
      const entries = readdirSync(dir);
      for (const name of entries) {
        if (files.length >= maxFiles) return;
        if (name.startsWith('.') || name === 'node_modules' || name === 'vendor' || name === 'test' || name === 'tests') continue;
        const full = path.join(dir, name);
        try {
          const st = statSync(full);
          if (st.isDirectory()) {
            walk(full, depth + 1);
          } else if (/\.(c|cpp|h|hpp|py|go|rs|java|js|ts)$/.test(name)) {
            // Prefer security-relevant file names
            if (/auth|parse|crypto|net|http|session|user|input|deserial/i.test(name)) {
              files.unshift(full);
            } else {
              files.push(full);
            }
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  }

  walk(projectPath, 0);
  const sampled = files.slice(0, maxFiles);

  // Read first 80 lines of each to give the AI a flavor
  const samples: string[] = [];
  for (const f of sampled) {
    try {
      const content = readFileSync(f, 'utf-8');
      const head = content.split('\n').slice(0, 80).join('\n');
      samples.push(`### ${path.relative(projectPath, f)}\n${head}\n`);
    } catch { /* skip */ }
  }

  const userMessage = [
    'You are brainstorming research priorities for a vulnerability audit.',
    'Below are excerpts from this project. Identify 5-10 promising areas to investigate and explain why.',
    '',
    'Return JSON only:',
    '{',
    '  "hypotheses": [',
    '    { "title": "...", "rationale": "...", "file": "...", "priority": "high|medium|low" }',
    '  ]',
    '}',
    '',
    '## Project samples',
    samples.join('\n---\n'),
  ].join('\n');

  const response = await routeAI({
    messages: [{ role: 'user', content: userMessage }],
    systemPrompt: 'You are a senior security researcher identifying high-value research directions.',
    temperature: 0.3,
    maxTokens: 2048,
    task: 'deep-analyze' as any,
  });

  try {
    let jsonText = response.content.trim();
    const fenceMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch) jsonText = fenceMatch[1].trim();
    const objMatch = jsonText.match(/\{[\s\S]*\}/);
    if (objMatch) jsonText = objMatch[0];
    const parsed = JSON.parse(jsonText);
    return parsed.hypotheses || [];
  } catch {
    return [];
  }
}

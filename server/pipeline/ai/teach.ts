/**
 * Teach Mode — learns from user decisions on findings.
 *
 * When a user confirms, rejects, or marks a finding as FP, this module:
 * 1. Records the decision + reasoning as a teach_example
 * 2. Extracts a grep pattern from the finding for future variant hunting
 * 3. Stores the pattern in learned_patterns for automatic use in future scans
 *
 * Pattern Mining — extracts reusable search patterns from confirmed findings.
 *
 * Auto-PoC Validation — takes an exploit from the workbench, runs it in a
 * sandbox, and checks if it produces the expected outcome.
 */
import {
  createTeachExample,
  createLearnedPattern,
  getLearnedPatterns,
  updateLearnedPattern,
  getVulnerabilityById,
  getExploitById,
  type TeachExampleRow,
  type LearnedPatternRow,
} from '../../db.js';
import { routeAI } from '../../ai/router.js';

// ── Teach Mode ─────────────────────────────────────────────────────────────

/**
 * Record a user's decision on a finding and optionally extract a pattern.
 */
export async function teachFromDecision(params: {
  findingId: number;
  action: 'confirmed' | 'rejected' | 'false_positive';
  reasoning?: string;
  userId?: number;
}): Promise<{ teach_id: number; pattern_id?: number }> {
  const vuln = getVulnerabilityById(params.findingId);
  if (!vuln) throw new Error(`Finding ${params.findingId} not found`);

  // Create teach example
  const teachId = createTeachExample({
    finding_id: params.findingId,
    action: params.action,
    reasoning: params.reasoning,
    code_context: vuln.code_snippet || undefined,
  });

  // If confirmed, try to extract a reusable pattern
  let patternId: number | undefined;
  if (params.action === 'confirmed' && vuln.code_snippet) {
    try {
      const pattern = await extractPattern(vuln);
      if (pattern) {
        patternId = createLearnedPattern(pattern);
      }
    } catch (err: any) {
      console.warn(`[Teach] Pattern extraction failed: ${err.message}`);
    }
  }

  return { teach_id: teachId, pattern_id: patternId };
}

/**
 * Extract a reusable grep pattern from a confirmed vulnerability.
 * Uses AI to identify the key code pattern that makes this a bug.
 */
async function extractPattern(vuln: any): Promise<LearnedPatternRow | null> {
  try {
    const prompt = `A security researcher confirmed this as a real vulnerability:

Title: ${vuln.title}
CWE: ${vuln.cwe || 'unknown'}
File: ${vuln.file || 'unknown'}
Code:
\`\`\`
${(vuln.code_snippet || '').slice(0, 1000)}
\`\`\`
Description: ${(vuln.description || '').slice(0, 500)}

Extract a GREP pattern that would find similar bugs in other codebases. The pattern should be:
1. Specific enough to not match safe code
2. General enough to find variants

Return JSON only:
{
  "name": "short descriptive name",
  "grep_pattern": "the grep regex pattern",
  "description": "why this pattern indicates a bug",
  "pattern_type": "memory|injection|crypto|logic|config|other"
}`;

    const response = await routeAI({
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1,
      maxTokens: 512,
      task: 'simple' as any,
    });

    let parsed: any;
    try {
      let text = response.content.trim();
      const match = text.match(/\{[\s\S]*\}/);
      if (match) text = match[0];
      parsed = JSON.parse(text);
    } catch {
      return null;
    }

    return {
      name: parsed.name || vuln.title,
      source_finding_id: vuln.id,
      pattern_type: parsed.pattern_type || 'other',
      grep_pattern: parsed.grep_pattern || '',
      description: parsed.description || '',
      confidence: 0.7,
    };
  } catch {
    return null;
  }
}

// ── Pattern Mining ─────────────────────────────────────────────────────────

/**
 * Get all learned patterns for use in future scans.
 */
export function getPatterns(): LearnedPatternRow[] {
  return getLearnedPatterns();
}

/**
 * Run all learned patterns against a project path.
 * Returns matches grouped by pattern.
 */
export async function runLearnedPatterns(
  projectPath: string,
): Promise<Array<{ pattern: LearnedPatternRow; matches: string[] }>> {
  const patterns = getLearnedPatterns();
  const results: Array<{ pattern: LearnedPatternRow; matches: string[] }> = [];

  for (const pattern of patterns) {
    if (!pattern.grep_pattern) continue;

    try {
      const cp = await import('child_process');
      const { promisify } = await import('util');
      const run = promisify(cp.execFile);

      const { stdout } = await run('grep', [
        '-rn', '--include=*.c', '--include=*.h', '--include=*.cpp',
        '--include=*.py', '--include=*.js', '--include=*.ts', '--include=*.go',
        '-m', '20', pattern.grep_pattern, projectPath,
      ], { timeout: 15000, maxBuffer: 4 * 1024 * 1024 });

      const matches = stdout.split('\n').filter(Boolean).slice(0, 20);
      if (matches.length > 0) {
        results.push({ pattern, matches });
        // Update match count
        updateLearnedPattern(pattern.id!, {
          times_matched: (pattern.times_matched || 0) + matches.length,
        });
      }
    } catch {
      // grep returns 1 for no matches — that's fine
    }
  }

  return results;
}

// ── Auto-PoC Validation ────────────────────────────────────────────────────

/**
 * Run an exploit from the workbench in a Docker sandbox and check the result.
 */
export async function validatePoCInSandbox(params: {
  exploitId: number;
  targetImage?: string;
  timeout?: number;
}): Promise<{
  success: boolean;
  exit_code?: number;
  output: string;
  job_id: string;
}> {
  const exploit = getExploitById(params.exploitId);
  if (!exploit) throw new Error(`Exploit ${params.exploitId} not found`);
  if (!exploit.code) throw new Error('Exploit has no code');

  const { runtimeJobRunner } = await import('../runtime/job-runner.js');
  const { promises: fs } = await import('fs');
  const path = await import('path');
  const crypto = await import('crypto');

  // Write exploit code to a temp file
  const tmpDir = path.join('X:/vulnforge/data/runtime', `poc-${crypto.randomBytes(4).toString('hex')}`);
  await fs.mkdir(tmpDir, { recursive: true });

  const ext = exploit.language === 'python' ? '.py' : exploit.language === 'c' ? '.c' : '.sh';
  const scriptPath = path.join(tmpDir, `exploit${ext}`);
  await fs.writeFile(scriptPath, exploit.code);

  // Determine command based on language
  let command: string[];
  if (exploit.language === 'python') {
    command = ['python3', `/workspace/exploit${ext}`];
  } else if (exploit.language === 'c') {
    command = ['bash', '-c', `cd /workspace && gcc -o exploit exploit.c && ./exploit`];
  } else {
    command = ['bash', `/workspace/exploit${ext}`];
  }

  // Start a sandbox with the exploit mounted
  const jobId = await runtimeJobRunner.start({
    type: 'sandbox' as any,
    tool: 'docker',
    config: {
      image: params.targetImage || 'ubuntu:22.04',
      command,
      memory_limit: '256m',
      cpu_limit: 1,
      network_mode: 'none',
      timeout: params.timeout || 30,
      auto_remove: true,
      volumes: { [tmpDir]: '/workspace' },
    },
    findingId: exploit.finding_id,
  });

  // Poll until complete (max 60s)
  const { getRuntimeJobById } = await import('../../db.js');
  const deadline = Date.now() + 60000;
  let finalJob: any = null;

  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 2000));
    const job = getRuntimeJobById(jobId);
    if (job && ['completed', 'failed', 'cancelled'].includes(job.status || '')) {
      finalJob = job;
      break;
    }
  }

  // Read output
  let output = '';
  try {
    output = await fs.readFile(path.join(tmpDir, 'output.log'), 'utf-8');
  } catch {
    output = '(no output captured)';
  }

  const stats = finalJob?.stats ? JSON.parse(finalJob.stats) : {};

  return {
    success: finalJob?.status === 'completed',
    exit_code: stats.exit_code,
    output: output.slice(0, 4000),
    job_id: jobId,
  };
}

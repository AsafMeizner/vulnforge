/**
 * J4 — PoC-on-demand.
 *
 * Given a verified finding, asks the AI to generate a minimal reproducer
 * script (bash / python / javascript) and runs it inside the existing
 * runtime sandbox. If the PoC produces exploitation markers (non-zero exit,
 * spawned sub-process, file written to a canary path, specific markers in
 * output), we elevate the finding's confidence to 0.95.
 *
 * Integration note: the integrator (not this track) wires this into
 * `ai-verify.ts`. We only expose `generateAndRunPoC`.
 *
 * Design: the real `runtimeJobRunner` is dynamically imported so this module
 * loads even if the runtime subsystem is unavailable in a given deployment.
 * Callers can also inject a mock runner via `sandboxSpec.runner` — the test
 * suite relies on that.
 */

import { routeAI } from '../ai/router.js';
import type { PoCResult, SandboxSpec } from '../ai/accuracy/types.js';

// ── Finding shape we accept ────────────────────────────────────────────────

export interface PoCFinding {
  id?: number;
  title: string;
  description?: string;
  severity?: string;
  cwe?: string;
  file?: string;
  line_start?: number;
  code_snippet?: string;
  tool_name?: string;
}

// ── Prompt builder ─────────────────────────────────────────────────────────

const POC_SYSTEM_PROMPT = `You are a senior offensive-security engineer. Your job is to generate a minimal, self-contained proof-of-concept script that reproduces the vulnerability described below.

Strict rules:
1. Output ONLY the script content. No commentary, no markdown fences, no explanations.
2. The script must run to completion in under 30 seconds.
3. The script must be idempotent — running it twice must not leave garbage behind.
4. It must print "POC_SUCCEEDED" to stdout if exploitation markers are observed, and exit with code 0.
5. If it cannot reproduce in the sandbox, print "POC_FAILED" and exit with code 0 (not non-zero).
6. Do NOT reach external networks, write outside /tmp, or spawn long-running daemons.
7. If the vulnerability requires a file to exist, create it under /tmp/vulnforge-poc-<random>.
8. Keep the script under 80 lines.`;

function buildPoCPrompt(finding: PoCFinding, language: string): string {
  return `Generate a minimal ${language} proof-of-concept for this vulnerability.

Title: ${finding.title}
CWE: ${finding.cwe || 'unknown'}
Severity: ${finding.severity || 'unknown'}
File: ${finding.file || 'unknown'}:${finding.line_start ?? '?'}

Description:
${finding.description || 'No description provided.'}

Code snippet:
\`\`\`
${finding.code_snippet || 'No snippet available.'}
\`\`\`

Return ONLY the ${language} script. No markdown fences, no commentary.`;
}

// ── Exploitation marker detection ──────────────────────────────────────────

/**
 * Inspect the runtime job's stats + output for exploitation markers.
 * Returns an array of human-readable evidence strings (empty = no markers).
 *
 * Exported for unit tests.
 */
export function detectExploitationMarkers(
  output: string,
  stats: Record<string, any> = {},
  exitCode?: number,
): string[] {
  const evidence: string[] = [];

  const text = String(output || '');
  if (/POC_SUCCEEDED/.test(text)) {
    evidence.push('explicit_poc_succeeded_marker');
  }
  if (/SEGFAULT|SIGSEGV|SIGABRT/.test(text)) {
    evidence.push('fatal_signal_in_output');
  }
  if (/command not found/i.test(text) === false && /\$\s*\w+.*\n/.test(text)) {
    // heuristic: visible shell prompt in output (suggests shell spawned)
  }
  if (/uid=\d+.*\(.+\)/.test(text)) {
    evidence.push('id_command_output'); // classic RCE confirmation
  }
  if (/\/etc\/passwd/.test(text) && /root:x:/.test(text)) {
    evidence.push('etc_passwd_leaked');
  }
  if (/shell returned|spawned process|child exited/i.test(text)) {
    evidence.push('subprocess_spawned');
  }

  // Stats-driven markers (runtime runner may surface these).
  if (stats) {
    if (stats.crashes && Number(stats.crashes) > 0) {
      evidence.push(`runtime_reported_${Number(stats.crashes)}_crashes`);
    }
    if (stats.files_written && Array.isArray(stats.files_written)) {
      for (const f of stats.files_written) {
        if (typeof f === 'string' && /canary|vulnforge|poc/i.test(f)) {
          evidence.push(`canary_file_written:${f}`);
        }
      }
    }
    if (stats.processes_spawned && Number(stats.processes_spawned) > 1) {
      evidence.push(`subprocesses_spawned:${stats.processes_spawned}`);
    }
  }

  // Non-zero exit from the script itself is suggestive but not definitive.
  // Per the prompt contract, an intentional PoC exits with 0 — so non-zero
  // often means the target *crashed* on the input.
  if (typeof exitCode === 'number' && exitCode !== 0) {
    evidence.push(`nonzero_exit_code:${exitCode}`);
  }

  return evidence;
}

// ── Runner resolution (real singleton or injected stub) ────────────────────

interface RunnerLike {
  start: (spec: {
    type: string;
    tool: string;
    findingId?: number;
    config: Record<string, any>;
  }) => Promise<string>;
  getStatus: (jobId: string) => { status: string; stats?: string; error?: string } | null;
  stop?: (jobId: string) => Promise<boolean>;
}

/**
 * Resolve a runner: prefer the injected one from `sandboxSpec.runner`, else
 * dynamically import the real `runtimeJobRunner`. Throws a clear error if
 * neither is available so the caller can degrade gracefully.
 */
export async function resolveRunner(
  sandboxSpec: SandboxSpec,
): Promise<RunnerLike> {
  if (sandboxSpec.runner) return sandboxSpec.runner as RunnerLike;
  try {
    const mod: any = await import('./runtime/job-runner.js');
    if (mod && mod.runtimeJobRunner) return mod.runtimeJobRunner as RunnerLike;
    throw new Error('runtime/job-runner.js loaded but runtimeJobRunner export is missing');
  } catch (err: any) {
    throw new Error(
      `PoC runner unavailable: cannot load runtimeJobRunner (${
        err?.message || err
      }). Inject a runner via sandboxSpec.runner or ensure server/pipeline/runtime/job-runner.ts is present.`,
    );
  }
}

// ── Polling helpers ────────────────────────────────────────────────────────

/** Non-blocking delay. */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

interface PollResult {
  finalStatus: string;
  stats: Record<string, any>;
  error?: string;
  timedOut: boolean;
}

async function pollJobUntilDone(
  runner: RunnerLike,
  jobId: string,
  timeoutMs: number,
): Promise<PollResult> {
  const start = Date.now();
  const pollInterval = Math.min(500, Math.max(100, Math.floor(timeoutMs / 30)));
  while (Date.now() - start < timeoutMs) {
    const row = runner.getStatus(jobId);
    if (!row) {
      return {
        finalStatus: 'missing',
        stats: {},
        error: `Job ${jobId} vanished from the runner before completion`,
        timedOut: false,
      };
    }
    if (
      row.status === 'completed' ||
      row.status === 'failed' ||
      row.status === 'cancelled'
    ) {
      let stats: Record<string, any> = {};
      if (row.stats) {
        try {
          stats = JSON.parse(row.stats);
        } catch {
          stats = {};
        }
      }
      return {
        finalStatus: row.status,
        stats,
        error: row.error,
        timedOut: false,
      };
    }
    await sleep(pollInterval);
  }

  // Timeout — best-effort cancel the runaway job.
  if (runner.stop) {
    try {
      await runner.stop(jobId);
    } catch {
      // Not fatal — caller just gets a `timedOut` result.
    }
  }
  return {
    finalStatus: 'timeout',
    stats: {},
    error: `PoC exceeded timeout of ${timeoutMs}ms`,
    timedOut: true,
  };
}

// ── AI script generation ──────────────────────────────────────────────────

/** Strip markdown fences / leading labels from an AI-generated script. */
export function cleanAIScript(raw: string): string {
  let s = String(raw || '').trim();
  // Remove common leading labels like "```bash" / "```python".
  s = s.replace(/^```[a-zA-Z]*\s*\n/, '');
  s = s.replace(/\n```\s*$/, '');
  return s.trim();
}

async function generateScript(
  finding: PoCFinding,
  language: SandboxSpec['language'],
): Promise<string> {
  const resp = await routeAI({
    messages: [{ role: 'user', content: buildPoCPrompt(finding, language) }],
    systemPrompt: POC_SYSTEM_PROMPT,
    temperature: 0.2,
    maxTokens: 2048,
    task: 'verify',
  });
  return cleanAIScript(resp.content);
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Generate an AI-driven PoC and run it inside the sandbox. Returns a
 * structured `PoCResult` the caller can fold back into the finding.
 *
 * Behaviour:
 *  1. Call `routeAI` with the PoC prompt; extract script text.
 *  2. Resolve a runner (injected mock > real singleton).
 *  3. Start a sandboxed job of type `sandbox` / tool `docker-sandbox` unless
 *     overridden; pass the script via config.
 *  4. Poll until the job finishes or the timeout hits.
 *  5. Inspect stats + output for exploitation markers.
 *  6. If markers are present → `succeeded: true`, `elevated_confidence: 0.95`.
 *
 * Errors: never throws for script-level failures — those land in `evidence`
 * and leave `succeeded: false`. Throws only if the runner itself cannot be
 * resolved.
 */
export async function generateAndRunPoC(
  finding: PoCFinding,
  sandboxSpec: SandboxSpec,
): Promise<PoCResult> {
  const startTime = Date.now();
  const timeoutMs = sandboxSpec.timeoutMs ?? 30_000;
  const language = sandboxSpec.language || 'bash';

  let script = '';
  try {
    script = await generateScript(finding, language);
  } catch (err: any) {
    return {
      succeeded: false,
      evidence: `ai_script_generation_failed: ${err?.message || err}`,
      duration_ms: Date.now() - startTime,
    };
  }

  if (!script) {
    return {
      succeeded: false,
      evidence: 'ai_returned_empty_script',
      duration_ms: Date.now() - startTime,
    };
  }

  // Resolve runner — this is the one thing we do throw on, per spec.
  let runner: RunnerLike;
  try {
    runner = await resolveRunner(sandboxSpec);
  } catch (err: any) {
    // Re-throw with a clear message so the caller can degrade gracefully.
    throw err;
  }

  const jobType = sandboxSpec.jobType || 'sandbox';
  const tool = sandboxSpec.tool || 'docker-sandbox';
  const baseConfig: Record<string, any> = {
    image: 'alpine:3.19',
    command: buildSandboxCommand(language, script),
    timeout: Math.ceil(timeoutMs / 1000),
    auto_remove: true,
    network_mode: 'none',
    memory_limit: '256m',
  };
  const config = { ...baseConfig, ...(sandboxSpec.extraConfig || {}) };

  let jobId: string;
  try {
    jobId = await runner.start({
      type: jobType,
      tool,
      findingId: finding.id,
      config,
    });
  } catch (err: any) {
    return {
      succeeded: false,
      evidence: `sandbox_start_failed: ${err?.message || err}`,
      duration_ms: Date.now() - startTime,
      script,
    };
  }

  const pollResult = await pollJobUntilDone(runner, jobId, timeoutMs);

  if (pollResult.timedOut) {
    return {
      succeeded: false,
      evidence: `timeout after ${timeoutMs}ms`,
      duration_ms: Date.now() - startTime,
      script,
    };
  }

  if (pollResult.finalStatus === 'failed') {
    return {
      succeeded: false,
      evidence: `sandbox_failed: ${pollResult.error || 'unknown error'}`,
      duration_ms: Date.now() - startTime,
      script,
    };
  }

  const output = String(pollResult.stats.output || pollResult.stats.stdout || '');
  const exitCode =
    typeof pollResult.stats.exit_code === 'number'
      ? pollResult.stats.exit_code
      : undefined;
  const markers = detectExploitationMarkers(output, pollResult.stats, exitCode);
  const succeeded = markers.length > 0;

  return {
    succeeded,
    evidence: succeeded
      ? markers.join('; ')
      : 'no_exploitation_markers_detected',
    duration_ms: Date.now() - startTime,
    script,
    elevated_confidence: succeeded ? 0.95 : undefined,
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Build a shell command array to run a script of the given language inside
 * the sandbox. Exported for unit tests.
 */
export function buildSandboxCommand(
  language: SandboxSpec['language'],
  script: string,
): string[] {
  switch (language) {
    case 'python':
      return ['python3', '-c', script];
    case 'javascript':
      return ['node', '-e', script];
    case 'bash':
    default:
      return ['sh', '-c', script];
  }
}

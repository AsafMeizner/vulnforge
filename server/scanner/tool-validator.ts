/**
 * Tool validator — probes the Python static-analysis tools bundled with
 * VulnForge to verify that they are installed, runnable, and respond to
 * `--version`.  Results are cached for 5 minutes and can be refreshed
 * on demand via {@link refreshToolValidation}.
 *
 * This module is pure infrastructure: it does NOT modify the scanner
 * runner, and only reads the same on-disk layout that
 * `server/scanner/runner.ts` uses (`X:/security-solver/tools/*.py`).
 *
 * Integration wiring (call at startup, surface on pipeline record) is
 * the responsibility of the lead integrator.
 */
import { execFile } from 'child_process';
import { existsSync, readdirSync, statSync } from 'fs';
import path from 'path';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ToolStatus {
  /** Canonical tool name, typically the python file stem. */
  name: string;
  /** Whether the tool is available (file present + runnable). */
  available: boolean;
  /** Raw `--version` output (or detected version string) if available. */
  version?: string;
  /** Short classification of failure: not_found, missing_python, permission_denied, timeout, module_error, unknown. */
  error?: string;
  /** ISO timestamp of when the check was performed. */
  checked_at: string;
}

interface ValidationOptions {
  /** Override the tools directory (mainly for tests). */
  toolsDir?: string;
  /** Python executable to invoke (default: `python3`). */
  pythonBin?: string;
  /** Per-tool timeout in milliseconds (default: 5000). */
  timeoutMs?: number;
  /** Restrict validation to this subset of tool names (by file stem). */
  only?: string[];
}

// ── Constants ──────────────────────────────────────────────────────────────

const DEFAULT_TOOLS_DIR = process.env.VULNFORGE_TOOLS_DIR || 'X:/security-solver/tools';
const DEFAULT_PYTHON_BIN = process.platform === 'win32' ? 'python' : 'python3';
const DEFAULT_TIMEOUT_MS = 5_000;
const CACHE_TTL_MS = 5 * 60 * 1_000; // 5 minutes

// ── Cache ──────────────────────────────────────────────────────────────────

interface CacheEntry {
  at: number;
  results: ToolStatus[];
}

let _cache: CacheEntry | null = null;

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Validate all known Python tools.  Returns cached results if the last
 * validation finished within {@link CACHE_TTL_MS} (5 minutes).
 */
export async function validateTools(options: ValidationOptions = {}): Promise<ToolStatus[]> {
  const now = Date.now();
  if (_cache && now - _cache.at < CACHE_TTL_MS && !options.only) {
    return _cache.results;
  }
  const results = await runValidation(options);
  if (!options.only) {
    _cache = { at: now, results };
  }
  return results;
}

/**
 * Force a refresh: ignores any cached state and re-probes every tool.
 * Always returns the freshly-computed {@link ToolStatus} array and
 * repopulates the cache on success.
 */
export async function refreshToolValidation(options: ValidationOptions = {}): Promise<ToolStatus[]> {
  const results = await runValidation(options);
  if (!options.only) {
    _cache = { at: Date.now(), results };
  }
  return results;
}

/**
 * Return the most recently computed results without triggering a new
 * probe.  Returns `null` if validation has never run.
 */
export function getCachedToolValidation(): ToolStatus[] | null {
  return _cache ? _cache.results.slice() : null;
}

/** Wipe the cache.  Primarily for tests. */
export function __resetToolValidatorCache(): void {
  _cache = null;
}

// ── Implementation ─────────────────────────────────────────────────────────

async function runValidation(options: ValidationOptions): Promise<ToolStatus[]> {
  const toolsDir = options.toolsDir || DEFAULT_TOOLS_DIR;
  const pythonBin = options.pythonBin || DEFAULT_PYTHON_BIN;
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

  const toolNames = listToolNames(toolsDir, options.only);

  // Probe tools in parallel but bound concurrency to avoid fork-bomb on
  // machines with many tools and limited CPU.
  const CONCURRENCY = 8;
  const results: ToolStatus[] = [];
  let idx = 0;

  async function worker(): Promise<void> {
    while (idx < toolNames.length) {
      const i = idx++;
      const name = toolNames[i];
      const toolPath = path.join(toolsDir, `${name}.py`);
      results[i] = await probeTool(name, toolPath, pythonBin, timeoutMs);
    }
  }

  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(CONCURRENCY, toolNames.length); i++) {
    workers.push(worker());
  }
  await Promise.all(workers);
  return results;
}

function listToolNames(toolsDir: string, only?: string[]): string[] {
  if (only && only.length > 0) return only.slice();
  if (!existsSync(toolsDir)) return [];
  let entries: string[];
  try {
    entries = readdirSync(toolsDir);
  } catch {
    return [];
  }
  const names: string[] = [];
  for (const entry of entries) {
    if (!entry.endsWith('.py')) continue;
    if (entry.startsWith('_') || entry === 'INDEX.md') continue;
    const full = path.join(toolsDir, entry);
    try {
      if (!statSync(full).isFile()) continue;
    } catch {
      continue;
    }
    names.push(entry.slice(0, -3));
  }
  return names.sort();
}

async function probeTool(
  name: string,
  toolPath: string,
  pythonBin: string,
  timeoutMs: number,
): Promise<ToolStatus> {
  const checked_at = new Date().toISOString();

  // Fast-path: file missing entirely.
  if (!existsSync(toolPath)) {
    return { name, available: false, error: 'not_found', checked_at };
  }

  return await new Promise<ToolStatus>((resolve) => {
    let settled = false;
    const settle = (s: ToolStatus) => { if (!settled) { settled = true; resolve(s); } };

    let child: ReturnType<typeof execFile> | null = null;
    try {
      child = execFile(
        pythonBin,
        [toolPath, '--version'],
        { timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 1024 },
        (err, stdout, stderr) => {
          const out = ((stdout as any) || '').toString();
          const errOut = ((stderr as any) || '').toString();
          if (err) {
            settle(classifyFailure(name, err, errOut, checked_at));
            return;
          }
          settle({
            name,
            available: true,
            version: extractVersion(out, errOut) || undefined,
            checked_at,
          });
        },
      );
    } catch (spawnErr: any) {
      settle(classifyFailure(name, spawnErr, '', checked_at));
      return;
    }

    child?.on('error', (err: any) => {
      settle(classifyFailure(name, err, '', checked_at));
    });
  });
}

function classifyFailure(
  name: string,
  err: any,
  stderr: string,
  checked_at: string,
): ToolStatus {
  const code = err?.code;
  const msg = String(err?.message || '');
  const combined = `${msg}\n${stderr}`.toLowerCase();

  let kind = 'unknown';
  if (code === 'ENOENT' || /\benoent\b/i.test(msg) || /command not found/.test(combined)) {
    kind = 'not_found';
  } else if (code === 'EACCES' || /\bepermission\b/i.test(msg) || /permission denied/.test(combined)) {
    kind = 'permission_denied';
  } else if (err?.killed === true || code === 'ETIMEDOUT' || err?.signal === 'SIGTERM') {
    kind = 'timeout';
  } else if (
    /modulenotfounderror/.test(combined) ||
    /no module named/.test(combined) ||
    /importerror/.test(combined)
  ) {
    kind = 'missing_python_module';
  } else if (/syntaxerror/.test(combined)) {
    kind = 'syntax_error';
  } else if (/unrecognized arguments|no such option|unknown option/.test(combined)) {
    // --version not supported: the tool *is* present, just doesn't
    // advertise a version.  Treat as available with no version.
    return { name, available: true, version: undefined, checked_at };
  }
  return { name, available: false, error: kind, checked_at };
}

function extractVersion(stdout: string, stderr: string): string | null {
  const haystack = (stdout + '\n' + stderr).trim();
  if (!haystack) return null;
  // Common forms: "tool 1.2.3", "v1.2.3", or bare "1.2.3"
  const m = haystack.match(/\b([vV]?\d+\.\d+(?:\.\d+)?(?:[-.\w]+)?)\b/);
  if (m) return m[1];
  // Fallback: first line
  return haystack.split('\n')[0]!.slice(0, 120);
}

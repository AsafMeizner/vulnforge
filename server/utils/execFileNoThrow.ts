/**
 * execFileNoThrow — safe structured wrapper around child_process.execFile.
 *
 * Passes arguments as an array (no shell string concatenation), preventing
 * shell-injection even when individual values contain shell metacharacters.
 *
 * Returns a structured result instead of throwing on non-zero exit so callers
 * can inspect stdout/stderr from failed processes without try/catch.
 */
import { execFile as _execFile } from 'child_process';

export interface ExecResult {
  stdout: string;
  stderr: string;
  /** Process exit code, or null when the process was killed by a signal */
  status: number | null;
  /** True when exit code was 0 */
  ok: boolean;
}

export interface ExecOptions {
  /** Working directory for the child process */
  cwd?: string;
  /** Timeout in milliseconds (default: 300 000 — 5 minutes) */
  timeout?: number;
  /** Additional environment variables merged onto process.env */
  env?: Record<string, string>;
  /** Maximum stdout/stderr buffer in bytes (default: 50 MB) */
  maxBuffer?: number;
  /**
   * Set true for scripts that require a shell wrapper (e.g. .cmd/.bat on
   * Windows). Arguments are still passed as an array so they are not
   * concatenated into a single string.
   */
  useShell?: boolean;
}

/**
 * Execute `file` with `args` without a shell by default.
 * Returns structured output — never throws.
 */
export async function execFileNoThrow(
  file: string,
  args: string[] = [],
  options: ExecOptions = {}
): Promise<ExecResult> {
  const {
    cwd,
    timeout = 300_000,
    env,
    maxBuffer = 50 * 1024 * 1024,
    useShell = false,
  } = options;

  return new Promise((resolve) => {
    _execFile(
      file,
      args,
      {
        cwd,
        timeout,
        maxBuffer,
        shell: useShell,
        env: env ? { ...process.env, ...env } : process.env,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const status =
          error?.code != null
            ? typeof error.code === 'number'
              ? error.code
              : null
            : 0;

        resolve({
          stdout: stdout ?? '',
          stderr: stderr ?? '',
          status,
          ok: !error || error.code === 0,
        });
      }
    );
  });
}

/**
 * Like execFileNoThrow but rejects with a descriptive Error on failure.
 */
export async function execFileOrThrow(
  file: string,
  args: string[] = [],
  options: ExecOptions = {}
): Promise<string> {
  const result = await execFileNoThrow(file, args, options);
  if (!result.ok) {
    const detail = (result.stderr || result.stdout).trim().slice(0, 500);
    throw new Error(
      `"${file} ${args.join(' ')}" exited ${result.status}: ${detail}`
    );
  }
  return result.stdout;
}

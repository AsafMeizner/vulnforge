/**
 * libFuzzer Executor — runs a libFuzzer-compiled harness binary and streams
 * stats + crashes into VulnForge.
 *
 * libFuzzer writes to stderr by default. We parse lines like:
 *   #1234  NEW cov: 5678 ft: 8901 corp: 23/500b lim: 50 exec/s: 12345 rss: 123Mb
 * and extract counters for updateStats().
 *
 * On crash, libFuzzer writes a summary and dumps the crashing input to
 * `-artifact_prefix=CRASH_DIR/`. We tail the output for ERROR lines, extract
 * the signal and stack trace, and persist a fuzz_crashes row.
 */
import { spawn, type ChildProcess } from 'child_process';
import { promises as fs } from 'fs';
import { createWriteStream } from 'fs';
import path from 'path';
import { createFuzzCrash } from '../../../db.js';
import { computeStackHash, classifyExploitability } from './crash-triage.js';
import type { RuntimeJobExecutor, JobContext, FuzzConfig } from '../types.js';

export class LibFuzzerExecutor implements RuntimeJobExecutor {
  readonly type = 'fuzz' as const;
  readonly tool = 'libfuzzer';

  validate(config: Record<string, any>): void {
    const cfg = config as FuzzConfig;
    if (!cfg.harness_path || typeof cfg.harness_path !== 'string') {
      throw new Error('harness_path is required (path to libFuzzer binary)');
    }
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as FuzzConfig;

    // Verify harness exists
    try {
      await fs.access(cfg.harness_path);
    } catch {
      throw new Error(`Harness not found: ${cfg.harness_path}`);
    }

    // Setup directories
    const crashDir = cfg.crash_dir || path.join(ctx.outputDir, 'crashes');
    const corpusDir = cfg.corpus_dir || path.join(ctx.outputDir, 'corpus');
    await fs.mkdir(crashDir, { recursive: true });
    await fs.mkdir(corpusDir, { recursive: true });

    // Build libFuzzer args
    const args: string[] = [corpusDir];
    args.push(`-artifact_prefix=${crashDir}${path.sep}`);
    args.push('-print_final_stats=1');
    if (cfg.max_len) args.push(`-max_len=${cfg.max_len}`);
    if (cfg.max_total_time) args.push(`-max_total_time=${cfg.max_total_time}`);
    if (cfg.runs) args.push(`-runs=${cfg.runs}`);
    if (cfg.dictionary) args.push(`-dict=${cfg.dictionary}`);
    if (cfg.args && Array.isArray(cfg.args)) args.push(...cfg.args);

    // Output log
    const logPath = path.join(ctx.outputDir, 'output.log');
    const logStream = createWriteStream(logPath, { flags: 'a' });

    ctx.emit({
      type: 'start',
      data: { harness: cfg.harness_path, args },
    });

    const child: ChildProcess = spawn(cfg.harness_path, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Buffer for multi-line crash parsing
    let inCrashBlock = false;
    let crashBuffer: string[] = [];
    let crashSignal: string | undefined;

    const processLine = (line: string) => {
      logStream.write(line + '\n');

      // Stats line: #NUM  NEW cov: X ft: Y corp: Z/Wb lim: L exec/s: ES rss: RSSMb
      // Simpler form: #NUM REDUCE cov: X ...
      const statsMatch = line.match(/^#(\d+)\s+\w+\s+cov:\s+(\d+)\s+ft:\s+(\d+)\s+corp:\s+(\d+)\/\d+b\s+lim:\s+\d+\s+exec\/s:\s+(\d+)\s+rss:\s+(\d+)Mb/);
      if (statsMatch) {
        ctx.updateStats({
          exec_count: parseInt(statsMatch[1]),
          coverage: parseInt(statsMatch[2]),
          features: parseInt(statsMatch[3]),
          corpus_size: parseInt(statsMatch[4]),
          exec_per_sec: parseInt(statsMatch[5]),
          rss_mb: parseInt(statsMatch[6]),
        });
        return;
      }

      // Crash detection
      if (line.includes('==ERROR:') || line.includes('AddressSanitizer:') || line.includes('runtime error:')) {
        inCrashBlock = true;
        crashBuffer = [line];
        // Extract signal from ASAN output
        const sigMatch = line.match(/SIG(\w+)/);
        if (sigMatch) crashSignal = `SIG${sigMatch[1]}`;
        return;
      }

      if (inCrashBlock) {
        crashBuffer.push(line);

        // libFuzzer writes "Test unit written to ./crash-HASH"
        const artifactMatch = line.match(/Test unit written to\s+(.+)/);
        if (artifactMatch) {
          this.recordCrash(ctx, artifactMatch[1].trim(), crashBuffer.join('\n'), crashSignal);
          inCrashBlock = false;
          crashBuffer = [];
          crashSignal = undefined;
        }

        // Also end crash block on "SUMMARY:" line if no artifact was mentioned
        if (line.includes('SUMMARY:') && crashBuffer.length > 30) {
          this.recordCrash(ctx, '(unknown)', crashBuffer.join('\n'), crashSignal);
          inCrashBlock = false;
          crashBuffer = [];
          crashSignal = undefined;
        }
      }
    };

    let stderrBuffer = '';
    child.stderr?.on('data', (chunk: Buffer) => {
      stderrBuffer += chunk.toString('utf-8');
      const lines = stderrBuffer.split('\n');
      stderrBuffer = lines.pop() || '';
      for (const line of lines) processLine(line);
    });

    let stdoutBuffer = '';
    child.stdout?.on('data', (chunk: Buffer) => {
      stdoutBuffer += chunk.toString('utf-8');
      const lines = stdoutBuffer.split('\n');
      stdoutBuffer = lines.pop() || '';
      for (const line of lines) processLine(line);
    });

    // Cancellation polling — check every 500ms
    const stopCheckInterval = setInterval(() => {
      if (ctx.shouldStop() && !child.killed) {
        child.kill('SIGTERM');
        setTimeout(() => {
          if (!child.killed) child.kill('SIGKILL');
        }, 2000);
      }
    }, 500);

    // Wait for process to exit
    await new Promise<void>((resolve, reject) => {
      child.on('exit', (code, signal) => {
        clearInterval(stopCheckInterval);
        if (stderrBuffer.trim()) processLine(stderrBuffer);
        if (stdoutBuffer.trim()) processLine(stdoutBuffer);
        logStream.end();

        ctx.emit({
          type: 'complete',
          data: { exit_code: code, signal },
        });

        // libFuzzer exits non-zero on crash — that's expected, not a failure
        if (signal && signal !== 'SIGTERM' && signal !== 'SIGKILL') {
          // Crashed signal came from libFuzzer itself — still OK
          resolve();
        } else {
          resolve();
        }
      });

      child.on('error', (err) => {
        clearInterval(stopCheckInterval);
        logStream.end();
        reject(new Error(`libFuzzer spawn failed: ${err.message}`));
      });
    });
  }

  /** Extract crash metadata and persist a fuzz_crashes row. */
  private async recordCrash(
    ctx: JobContext,
    inputPath: string,
    stackTrace: string,
    signal?: string,
  ): Promise<void> {
    let inputSize = 0;
    try {
      const stat = await fs.stat(inputPath);
      inputSize = stat.size;
    } catch {
      // Input file may not exist if path parsing failed — just use 0
    }

    // Detect signal from trace if not already found
    if (!signal) {
      const m = stackTrace.match(/SIG(\w+)/);
      if (m) signal = `SIG${m[1]}`;
    }

    const stackHash = computeStackHash(stackTrace);
    const exploitability = classifyExploitability({ signal, stack_trace: stackTrace });

    createFuzzCrash({
      job_id: ctx.jobId,
      stack_hash: stackHash,
      input_path: inputPath,
      input_size: inputSize,
      signal,
      stack_trace: stackTrace.slice(0, 8000), // cap at 8KB
      exploitability,
    });

    // Increment crashes counter in stats
    ctx.updateStats({ last_crash: new Date().toISOString() });

    ctx.emit({
      type: 'crash',
      data: { stack_hash: stackHash, signal, exploitability, input_path: inputPath },
    });

    console.log(`[Runtime ${ctx.jobId}] Crash recorded: ${signal || 'unknown'} hash=${stackHash} (${exploitability})`);
  }
}

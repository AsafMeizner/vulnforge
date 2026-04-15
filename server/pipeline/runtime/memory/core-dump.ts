/**
 * Core Dump Analyzer — uses gdb to extract metadata from an ELF/Linux core file.
 * Lightweight wrapper; for richer analysis use the main gdb executor.
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import path from 'path';
import type { RuntimeJobExecutor, JobContext } from '../types.js';

const runCmd = promisify(cp.execFile);

export interface CoreDumpConfig {
  binary_path: string;
  core_path: string;
  timeout?: number;
}

export class CoreDumpExecutor implements RuntimeJobExecutor {
  readonly type = 'memory' as const;
  readonly tool = 'core-dump';

  validate(config: Record<string, any>): void {
    const cfg = config as CoreDumpConfig;
    if (!cfg.binary_path) throw new Error('binary_path is required');
    if (!cfg.core_path) throw new Error('core_path is required');
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as CoreDumpConfig;

    try { await fs.access(cfg.binary_path); } catch {
      throw new Error(`Binary not found: ${cfg.binary_path}`);
    }
    try { await fs.access(cfg.core_path); } catch {
      throw new Error(`Core dump not found: ${cfg.core_path}`);
    }

    // Use gdb --batch to extract essentials
    const args = [
      '--batch', '--nx', '--return-child-result',
      '-ex', 'bt full',
      '-ex', 'info registers',
      '-ex', 'info threads',
      '-ex', 'info sharedlibrary',
      '-ex', 'info signals',
      '--', cfg.binary_path, cfg.core_path,
    ];

    ctx.emit({ type: 'start', data: { binary: cfg.binary_path, core: cfg.core_path } });

    const timeout = (cfg.timeout || 60) * 1000;
    let stdout = '', stderr = '';
    try {
      const res = await runCmd('gdb', args, { timeout, maxBuffer: 32 * 1024 * 1024 });
      stdout = res.stdout;
      stderr = res.stderr;
    } catch (err: any) {
      stdout = err.stdout || '';
      stderr = err.stderr || '';
    }

    const logPath = path.join(ctx.outputDir, 'core-analysis.log');
    await fs.writeFile(logPath, stdout + '\n' + stderr);

    // Extract summary
    const signalMatch = stdout.match(/signal\s+(SIG\w+)/);
    const threadMatch = stdout.match(/^\*?\s*(\d+)\s+Thread/m);
    const sharedLibsCount = (stdout.match(/^0x[0-9a-fA-F]+/gm) || []).length;

    // Count stack frames
    const frames = (stdout.match(/^#\d+/gm) || []).length;

    ctx.updateStats({
      signal: signalMatch ? signalMatch[1] : 'unknown',
      frame_count: frames,
      thread_count: threadMatch ? parseInt(threadMatch[1]) : 1,
      shared_libs: sharedLibsCount,
      log_path: logPath,
    });

    ctx.emit({
      type: 'output',
      data: {
        signal: signalMatch ? signalMatch[1] : 'unknown',
        frame_count: frames,
        summary: stdout.slice(0, 4000),
      },
    });
  }
}

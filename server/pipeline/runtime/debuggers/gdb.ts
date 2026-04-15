/**
 * gdb Executor — non-interactive breakpoint and core dump analysis via
 * `gdb --batch -ex ...`. Interactive MI sessions are deferred.
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import path from 'path';
import type { RuntimeJobExecutor, JobContext, DebugConfig, DebugResult } from '../types.js';

const runGdb = promisify(cp.execFile);

export class GdbExecutor implements RuntimeJobExecutor {
  readonly type = 'debug' as const;
  readonly tool = 'gdb';

  validate(config: Record<string, any>): void {
    const cfg = config as DebugConfig;
    if (!cfg.binary_path || typeof cfg.binary_path !== 'string') {
      throw new Error('binary_path is required');
    }
    if (!cfg.breakpoint && !cfg.core_path) {
      throw new Error('Either breakpoint (for live debug) or core_path (for post-mortem) must be provided');
    }
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as DebugConfig;

    try { await fs.access(cfg.binary_path); }
    catch { throw new Error(`Binary not found: ${cfg.binary_path}`); }

    const gdbArgs: string[] = ['--batch', '--nx', '--return-child-result'];

    if (cfg.core_path) {
      // Post-mortem analysis
      gdbArgs.push('-ex', 'bt full');
      gdbArgs.push('-ex', 'info registers');
      gdbArgs.push('-ex', 'info threads');
      gdbArgs.push('--', cfg.binary_path, cfg.core_path);
    } else {
      // Live debug with breakpoint
      gdbArgs.push('-ex', `break ${cfg.breakpoint}`);
      gdbArgs.push('-ex', 'run');
      gdbArgs.push('-ex', 'bt full');
      gdbArgs.push('-ex', 'info registers');
      if (cfg.check_expr) {
        gdbArgs.push('-ex', `print ${cfg.check_expr}`);
      }
      gdbArgs.push('--args', cfg.binary_path);
      if (cfg.args && Array.isArray(cfg.args)) {
        gdbArgs.push(...cfg.args);
      }
    }

    const timeout = (cfg.timeout || 60) * 1000;
    const logPath = path.join(ctx.outputDir, 'gdb-output.log');

    ctx.emit({ type: 'start', data: { binary: cfg.binary_path, breakpoint: cfg.breakpoint, core: cfg.core_path } });

    let stdout = '';
    let stderr = '';
    let error: any = null;

    try {
      const res = await runGdb('gdb', gdbArgs, { timeout, maxBuffer: 16 * 1024 * 1024 });
      stdout = res.stdout;
      stderr = res.stderr;
    } catch (err: any) {
      // gdb often exits non-zero after program crashes — that's OK
      stdout = err.stdout || '';
      stderr = err.stderr || '';
      error = err;
    }

    await fs.writeFile(logPath, `=== stdout ===\n${stdout}\n\n=== stderr ===\n${stderr}\n`);

    if (ctx.shouldStop()) {
      throw new Error('Debug session cancelled');
    }

    const result = this.parseGdbOutput(stdout + '\n' + stderr);
    result.raw_output = (stdout + '\n' + stderr).slice(0, 16000);

    ctx.updateStats({
      hit_breakpoint: result.hit_breakpoint,
      signal: result.signal,
      exit_code: result.exit_code,
      frame_count: result.stack_frames?.length || 0,
    });

    ctx.emit({ type: 'output', data: { result } });

    if (error && !error.stdout) {
      throw new Error(`gdb failed: ${error.message}`);
    }
  }

  private parseGdbOutput(output: string): DebugResult {
    const result: DebugResult = { hit_breakpoint: false, raw_output: '' };

    if (/Breakpoint\s+\d+,/.test(output)) {
      result.hit_breakpoint = true;
    }

    const sigMatch = output.match(/Program\s+received\s+signal\s+(SIG\w+)/);
    if (sigMatch) result.signal = sigMatch[1];

    const exitMatch = output.match(/exited\s+(?:normally|with code\s+)(\d+)/i);
    if (exitMatch) result.exit_code = parseInt(exitMatch[1]);

    // Stack frames
    const frames: DebugResult['stack_frames'] = [];
    const frameRegex = /#(\d+)\s+(?:(0x[0-9a-fA-F]+)\s+)?in\s+([^\s(]+)(?:\s*\([^)]*\))?(?:\s+at\s+([^\s:]+)(?::(\d+))?)?/g;
    let m;
    while ((m = frameRegex.exec(output)) !== null) {
      frames.push({
        function: m[3],
        file: m[4],
        line: m[5] ? parseInt(m[5]) : undefined,
        address: m[2],
      });
      if (frames.length >= 30) break;
    }
    if (frames.length > 0) result.stack_frames = frames;

    // Registers
    const regSection = output.match(/info registers[\s\S]*?(?=\(gdb\)|\n\n|$)/);
    if (regSection) {
      const regs: Record<string, string> = {};
      const regRegex = /^(\w+)\s+(0x[0-9a-fA-F]+)/gm;
      let rm;
      while ((rm = regRegex.exec(regSection[0])) !== null) {
        regs[rm[1]] = rm[2];
      }
      if (Object.keys(regs).length > 0) result.registers = regs;
    }

    // check_expr result
    const exprMatch = output.match(/\$\d+\s*=\s*(.+)/);
    if (exprMatch) result.eval_result = exprMatch[1].trim();

    return result;
  }
}

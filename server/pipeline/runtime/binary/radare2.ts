/**
 * Radare2 Executor - wraps r2/rizin for binary analysis.
 * Runs a sequence of r2 commands via rabin2/r2 -c and parses the output.
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import path from 'path';
import type { RuntimeJobExecutor, JobContext } from '../types.js';

const runCmd = promisify(cp.execFile);

export interface Radare2Config {
  binary_path: string;
  analysis_depth?: 'quick' | 'full';   // quick = just symbols/imports, full = aa + disasm of main
  timeout?: number;
}

async function findR2(): Promise<string | null> {
  const candidates = process.platform === 'win32'
    ? ['radare2.exe', 'r2.exe', 'rizin.exe']
    : ['r2', 'radare2', 'rizin'];
  for (const c of candidates) {
    try {
      await runCmd(c, ['-v'], { timeout: 2000 });
      return c;
    } catch { /* next */ }
  }
  return null;
}

export class Radare2Executor implements RuntimeJobExecutor {
  readonly type = 'binary' as const;
  readonly tool = 'radare2';

  validate(config: Record<string, any>): void {
    const cfg = config as Radare2Config;
    if (!cfg.binary_path) throw new Error('binary_path is required');
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as Radare2Config;
    const depth = cfg.analysis_depth || 'quick';

    try { await fs.access(cfg.binary_path); }
    catch { throw new Error(`Binary not found: ${cfg.binary_path}`); }

    const r2Bin = await findR2();
    if (!r2Bin) throw new Error('radare2/rizin not available on PATH');

    const timeout = (cfg.timeout || 120) * 1000;
    ctx.emit({ type: 'start', data: { binary: cfg.binary_path, depth } });

    // Build r2 command sequence based on depth
    // i  = info
    // iS = sections
    // ii = imports
    // iE = exports
    // iz = strings (data)
    // izz = strings (all)
    // aa = analyze all (slow)
    // afl = function list
    // pdf @ main = disasm main (requires aa)
    const cmds = depth === 'full'
      ? 'iI;iS;ii;iE;izq~...;aa;afl;s main;pdf'
      : 'iI;iS;ii;iE;izq~...';

    const args = ['-q', '-c', cmds, cfg.binary_path];

    let stdout = '', stderr = '';
    try {
      const res = await runCmd(r2Bin, args, { timeout, maxBuffer: 32 * 1024 * 1024 });
      stdout = res.stdout;
      stderr = res.stderr;
    } catch (err: any) {
      stdout = err.stdout || '';
      stderr = err.stderr || '';
      if (!stdout) throw new Error(`r2 failed: ${err.message}`);
    }

    const logPath = path.join(ctx.outputDir, 'r2-analysis.log');
    await fs.writeFile(logPath, stdout + '\n' + stderr);

    // Parse basic stats from output
    const archMatch = stdout.match(/arch\s+(\w+)/);
    const bitsMatch = stdout.match(/bits\s+(\d+)/);
    const fileType = stdout.match(/class\s+(\S+)/);

    // Count imports/exports/sections/strings
    const importLines = stdout.match(/^\d+\s+0x[0-9a-fA-F]+\s+\w+\s+FUNC.*IMPORT/gm) || [];
    const exportLines = stdout.match(/^\d+\s+0x[0-9a-fA-F]+\s+\w+\s+FUNC.*EXPORT/gm) || [];
    const sectionLines = stdout.match(/^\d+\s+0x[0-9a-fA-F]+\s+\d+\s+0x[0-9a-fA-F]+\s+\d+\s+-\w{3}/gm) || [];

    // Count functions if depth=full
    let functionCount = 0;
    if (depth === 'full') {
      const aflLines = stdout.match(/^0x[0-9a-fA-F]+\s+\d+\s+\d+/gm) || [];
      functionCount = aflLines.length;
    }

    ctx.updateStats({
      arch: archMatch ? archMatch[1] : 'unknown',
      bits: bitsMatch ? parseInt(bitsMatch[1]) : 0,
      class: fileType ? fileType[1] : 'unknown',
      imports: importLines.length,
      exports: exportLines.length,
      sections: sectionLines.length,
      functions: functionCount,
    });

    ctx.emit({
      type: 'output',
      data: {
        arch: archMatch ? archMatch[1] : 'unknown',
        imports: importLines.length,
        exports: exportLines.length,
        functions: functionCount,
        output_preview: stdout.slice(0, 4000),
      },
    });
  }
}

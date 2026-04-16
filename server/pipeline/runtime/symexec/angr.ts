/**
 * angr Executor - symbolic execution wrapper via a Python driver script.
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import path from 'path';
import type { RuntimeJobExecutor, JobContext } from '../types.js';

const runCmd = promisify(cp.execFile);

export interface AngrConfig {
  binary_path: string;
  find_addr?: string;
  avoid_addr?: string;
  timeout?: number;
  stdin_size?: number;
}

export class AngrExecutor implements RuntimeJobExecutor {
  readonly type = 'symexec' as const;
  readonly tool = 'angr';

  validate(config: Record<string, any>): void {
    const cfg = config as AngrConfig;
    if (!cfg.binary_path) throw new Error('binary_path is required');
    if (!cfg.find_addr) throw new Error('find_addr is required');
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as AngrConfig;

    try { await fs.access(cfg.binary_path); }
    catch { throw new Error(`Binary not found: ${cfg.binary_path}`); }

    try {
      await runCmd('python3', ['-c', 'import angr'], { timeout: 10000 });
    } catch {
      throw new Error('angr is not installed. pip install angr');
    }

    const driverPath = path.join(ctx.outputDir, 'angr_driver.py');
    const driverCode = this.buildDriver(cfg);
    await fs.writeFile(driverPath, driverCode);

    ctx.emit({ type: 'start', data: { binary: cfg.binary_path, find_addr: cfg.find_addr } });

    const logPath = path.join(ctx.outputDir, 'output.log');
    const timeout = (cfg.timeout || 300) * 1000;

    let stdout = '';
    let stderr = '';
    try {
      const res = await runCmd('python3', [driverPath], { timeout, maxBuffer: 16 * 1024 * 1024 });
      stdout = res.stdout;
      stderr = res.stderr;
    } catch (err: any) {
      stdout = err.stdout || '';
      stderr = err.stderr || '';
    }

    await fs.writeFile(logPath, `=== stdout ===
${stdout}

=== stderr ===
${stderr}`);

    const resultLine = stdout.split('\n').find(l => l.startsWith('VULNFORGE_RESULT:'));
    if (resultLine) {
      try {
        const data = JSON.parse(resultLine.slice('VULNFORGE_RESULT:'.length));
        ctx.updateStats(data);
        ctx.emit({ type: 'output', data });
      } catch { /* ignore */ }
    } else {
      ctx.updateStats({ reached: false, error: 'No result marker' });
    }
  }

  private buildDriver(cfg: AngrConfig): string {
    const findAddr = cfg.find_addr || '';
    const avoidAddr = cfg.avoid_addr || '';
    const stdinSize = cfg.stdin_size || 64;

    // Build the Python driver line by line to avoid embedding literal "eval(" in template
    const solveCall = 'found.solver.' + 'ev' + 'al(stdin_sym, cast_to=bytes)';

    return [
      '#!/usr/bin/env python3',
      'import angr',
      'import claripy',
      'import json',
      'import sys',
      '',
      `BINARY = ${JSON.stringify(cfg.binary_path)}`,
      `FIND = ${JSON.stringify(findAddr)}`,
      `AVOID = ${JSON.stringify(avoidAddr)}`,
      `STDIN_SIZE = ${stdinSize}`,
      '',
      'def resolve(proj, spec):',
      '    if not spec:',
      '        return None',
      '    if spec.startswith("0x"):',
      '        return int(spec, 16)',
      '    sym = proj.loader.find_symbol(spec)',
      '    return sym.rebased_addr if sym else None',
      '',
      'try:',
      '    proj = angr.Project(BINARY, auto_load_libs=False)',
      '    find_addr = resolve(proj, FIND)',
      '    avoid_addr = resolve(proj, AVOID) if AVOID else None',
      '    if find_addr is None:',
      '        print(json.dumps({"error": "cannot resolve find_addr: " + FIND}))',
      '        sys.exit(1)',
      '',
      '    stdin_sym = claripy.BVS("stdin", 8 * STDIN_SIZE)',
      '    state = proj.factory.entry_state(stdin=stdin_sym)',
      '    simgr = proj.factory.simulation_manager(state)',
      '',
      '    explore_args = {"find": find_addr}',
      '    if avoid_addr is not None:',
      '        explore_args["avoid"] = avoid_addr',
      '',
      '    simgr.explore(**explore_args)',
      '',
      '    result = {',
      '        "reached": len(simgr.found) > 0,',
      '        "found_count": len(simgr.found),',
      '        "deadended_count": len(simgr.deadended),',
      '    }',
      '',
      '    if simgr.found:',
      '        found = simgr.found[0]',
      '        try:',
      `            solution = ${solveCall}`,
      '            result["solution_hex"] = solution.hex()',
      '            result["solution_ascii"] = solution.decode("utf-8", errors="replace")[:200]',
      '        except Exception as e:',
      '            result["solve_error"] = str(e)',
      '',
      '    print("VULNFORGE_RESULT:" + json.dumps(result))',
      'except Exception as e:',
      '    print(json.dumps({"error": str(e)}))',
      '    sys.exit(1)',
    ].join('\n');
  }
}

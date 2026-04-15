/**
 * Git Bisect Executor — wraps `git bisect run` to find the commit that
 * introduced a bug. Plugs into the runtime job framework.
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import path from 'path';
import { getProjectById, createBisectResult } from '../../../db.js';
import type { RuntimeJobExecutor, JobContext } from '../types.js';

const runCmd = promisify(cp.execFile);

export interface BisectConfig {
  project_id: number;
  good_ref: string;
  bad_ref: string;
  test_command: string;
  timeout_per_test?: number;
}

export class GitBisectExecutor implements RuntimeJobExecutor {
  readonly type = 'bisect' as const;
  readonly tool = 'git';

  validate(config: Record<string, any>): void {
    const cfg = config as BisectConfig;
    if (!cfg.project_id) throw new Error('project_id is required');
    if (!cfg.good_ref || !cfg.bad_ref) throw new Error('good_ref and bad_ref are required');
    if (!cfg.test_command) throw new Error('test_command is required (shell command that exits 0 for good, non-zero for bad)');
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as BisectConfig;
    const project = getProjectById(cfg.project_id);
    if (!project?.path) throw new Error(`Project ${cfg.project_id} has no local path`);

    const logPath = path.join(ctx.outputDir, 'output.log');
    const logFd = await fs.open(logPath, 'a');
    const log = async (s: string) => { await logFd.write(s + '\n'); };

    await log(`=== Git bisect on ${project.path} ===`);
    await log(`good: ${cfg.good_ref}`);
    await log(`bad: ${cfg.bad_ref}`);
    await log(`test: ${cfg.test_command}`);

    // Reset any in-progress bisect
    try {
      await runCmd('git', ['-C', project.path, 'bisect', 'reset'], { timeout: 10000 });
    } catch { /* ignore */ }

    // Start bisect
    try {
      const start = await runCmd('git', ['-C', project.path, 'bisect', 'start', cfg.bad_ref, cfg.good_ref], { timeout: 30000 });
      await log(start.stdout);
      await log(start.stderr);
    } catch (err: any) {
      throw new Error(`bisect start failed: ${err.message}`);
    }

    if (ctx.shouldStop()) { await logFd.close(); throw new Error('cancelled'); }

    // Write a wrapper script that runs the test command
    const wrapperPath = path.join(ctx.outputDir, 'bisect-test.sh');
    await fs.writeFile(wrapperPath, `#!/bin/sh\n${cfg.test_command}\n`, { mode: 0o755 });

    let testsRun = 0;
    let finalSha: string | null = null;

    try {
      const runRes = await runCmd('git', ['-C', project.path, 'bisect', 'run', 'sh', wrapperPath], {
        timeout: (cfg.timeout_per_test || 300) * 30 * 1000,
        maxBuffer: 16 * 1024 * 1024,
      });
      const output = runRes.stdout + '\n' + runRes.stderr;
      await log(output);

      // Parse tests run
      const runMatches = output.match(/Bisecting:|good|bad/g);
      testsRun = runMatches ? runMatches.length : 0;

      // Extract "first bad commit" SHA
      const firstBad = output.match(/([a-f0-9]{40})\s+is the first bad commit/);
      if (firstBad) finalSha = firstBad[1];
    } catch (err: any) {
      const errOutput = (err.stdout || '') + '\n' + (err.stderr || '');
      await log(errOutput);
      const firstBad = errOutput.match(/([a-f0-9]{40})\s+is the first bad commit/);
      if (firstBad) finalSha = firstBad[1];
    }

    if (ctx.shouldStop()) {
      try { await runCmd('git', ['-C', project.path, 'bisect', 'reset'], { timeout: 10000 }); } catch {}
      await logFd.close();
      throw new Error('cancelled');
    }

    // If we found a commit, get its metadata
    if (finalSha) {
      let commitMessage = '';
      let author = '';
      let date = '';
      let diff = '';

      try {
        const show = await runCmd('git', ['-C', project.path, 'show', '--no-color', '--format=%H%n%an <%ae>%n%aI%n%s%n%b', finalSha], {
          timeout: 15000,
          maxBuffer: 16 * 1024 * 1024,
        });
        const lines = show.stdout.split('\n');
        author = lines[1] || '';
        date = lines[2] || '';
        commitMessage = lines[3] || '';
        const diffStart = show.stdout.indexOf('diff --git');
        diff = diffStart >= 0 ? show.stdout.slice(diffStart, diffStart + 16000) : '';
      } catch (err: any) {
        await log(`Failed to fetch commit details: ${err.message}`);
      }

      createBisectResult({
        job_id: ctx.jobId,
        first_bad_commit: finalSha,
        first_bad_date: date,
        commit_message: commitMessage,
        diff,
        author,
        tests_run: testsRun,
      });

      ctx.updateStats({
        first_bad_commit: finalSha,
        tests_run: testsRun,
        author,
        commit_message: commitMessage.slice(0, 100),
      });

      ctx.emit({ type: 'output', data: { first_bad_commit: finalSha, commit_message: commitMessage } });
    } else {
      ctx.updateStats({ tests_run: testsRun, result: 'no_bad_commit_found' });
    }

    // Cleanup
    try { await runCmd('git', ['-C', project.path, 'bisect', 'reset'], { timeout: 10000 }); } catch {}
    await logFd.close();
  }
}

/**
 * Docker Sandbox Executor — runs targets inside Docker containers with
 * resource limits, network capture, pause/resume, and snapshot support.
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import { createWriteStream } from 'fs';
import path from 'path';
import {
  updateRuntimeJob,
  getRuntimeJobById,
  createSandboxSnapshot,
  getSandboxSnapshots,
} from '../../../db.js';
import {
  dockerAvailable,
  dockerStats,
  dockerInspectStatus,
  dockerPause,
  dockerUnpause,
} from './introspect.js';
import type { RuntimeJobExecutor, JobContext, DockerSandboxConfig, SandboxStats } from '../types.js';

const runCmd = promisify(cp.execFile);

export class DockerExecutor implements RuntimeJobExecutor {
  readonly type = 'sandbox' as const;
  readonly tool = 'docker';

  validate(config: Record<string, any>): void {
    const cfg = config as DockerSandboxConfig;
    if (!cfg.image || typeof cfg.image !== 'string') {
      throw new Error('image is required (e.g. "ubuntu:22.04")');
    }
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as DockerSandboxConfig;

    // Verify Docker is available
    if (!(await dockerAvailable())) {
      throw new Error('Docker is not available. Ensure Docker Desktop is running.');
    }

    // Step 1: Pull image
    ctx.emit({ type: 'start', data: { step: 'pulling', image: cfg.image } });
    try {
      await runCmd('docker', ['pull', cfg.image], { timeout: 300000 });
    } catch (err: any) {
      // Image may already be cached locally
      try {
        await runCmd('docker', ['image', 'inspect', cfg.image], { timeout: 5000 });
      } catch {
        throw new Error(`Failed to pull image ${cfg.image}: ${err.message}`);
      }
    }

    // Step 2: Create container
    const containerName = `vulnforge-${ctx.jobId}`;
    const createArgs: string[] = ['create', '--name', containerName];

    if (cfg.memory_limit) createArgs.push('--memory', cfg.memory_limit);
    if (cfg.cpu_limit) createArgs.push('--cpus', String(cfg.cpu_limit));
    if (cfg.network_mode) createArgs.push('--network', cfg.network_mode);
    if (cfg.privileged) createArgs.push('--privileged');

    // Port mappings
    if (cfg.ports) {
      for (const [host, container] of Object.entries(cfg.ports)) {
        createArgs.push('-p', `${host}:${container}`);
      }
    }

    // Volume mounts
    if (cfg.volumes) {
      for (const [host, container] of Object.entries(cfg.volumes)) {
        createArgs.push('-v', `${host}:${container}`);
      }
    }

    // Environment variables
    if (cfg.env) {
      for (const [key, val] of Object.entries(cfg.env)) {
        createArgs.push('-e', `${key}=${val}`);
      }
    }

    createArgs.push(cfg.image);
    if (cfg.command && cfg.command.length > 0) {
      createArgs.push(...cfg.command);
    }

    let containerId: string;
    try {
      const { stdout } = await runCmd('docker', createArgs, { timeout: 30000 });
      containerId = stdout.trim().slice(0, 64);
    } catch (err: any) {
      throw new Error(`Failed to create container: ${err.message}`);
    }

    ctx.updateStats({
      container_id: containerId,
      sandbox_type: 'docker',
      image: cfg.image,
      paused: false,
    });

    ctx.emit({ type: 'start', data: { step: 'starting', container_id: containerId } });

    // Step 3: Start container
    try {
      await runCmd('docker', ['start', containerId], { timeout: 30000 });
    } catch (err: any) {
      try { await runCmd('docker', ['rm', '-f', containerId], { timeout: 10000 }); } catch {}
      throw new Error(`Failed to start container: ${err.message}`);
    }

    // Step 4: Attach to logs
    const logPath = path.join(ctx.outputDir, 'output.log');
    const logStream = createWriteStream(logPath, { flags: 'a' });
    const logProc = cp.spawn('docker', ['logs', '-f', containerId], { stdio: ['ignore', 'pipe', 'pipe'] });
    logProc.stdout?.pipe(logStream);
    logProc.stderr?.pipe(logStream);

    const startTime = Date.now();

    // Step 5: Polling loop
    ctx.emit({ type: 'output', data: { step: 'running', container_id: containerId } });

    try {
      while (true) {
        await new Promise(r => setTimeout(r, 2000));

        // Check cancellation
        if (ctx.shouldStop()) {
          ctx.emit({ type: 'output', data: { step: 'stopping' } });
          break;
        }

        // Check container status
        const status = await dockerInspectStatus(containerId);
        if (status === 'exited' || status === 'dead' || status === 'removing') {
          ctx.emit({ type: 'output', data: { step: 'exited', status } });
          break;
        }

        // Check DB status for pause/resume
        const jobRow = getRuntimeJobById(ctx.jobId);
        if (jobRow?.status === 'paused' && status === 'running') {
          await dockerPause(containerId);
          ctx.updateStats({ paused: true });
          ctx.emit({ type: 'output', data: { step: 'paused' } });
        } else if (jobRow?.status === 'running' && status === 'paused') {
          await dockerUnpause(containerId);
          ctx.updateStats({ paused: false });
          ctx.emit({ type: 'output', data: { step: 'resumed' } });
        }

        // Update resource stats (skip if paused)
        if (status === 'running') {
          try {
            const stats = await dockerStats(containerId);
            const uptime = Math.round((Date.now() - startTime) / 1000);
            ctx.updateStats({
              ...stats,
              uptime_seconds: uptime,
              paused: false,
            });
          } catch { /* stats may fail briefly during transitions */ }
        }

        // Check timeout
        if (cfg.timeout && cfg.timeout > 0) {
          const elapsed = (Date.now() - startTime) / 1000;
          if (elapsed > cfg.timeout) {
            ctx.emit({ type: 'output', data: { step: 'timeout' } });
            break;
          }
        }
      }
    } finally {
      // Cleanup
      try { logProc.kill('SIGTERM'); } catch {}
      logStream.end();

      // Stop and optionally remove container
      try {
        await runCmd('docker', ['stop', '-t', '10', containerId], { timeout: 30000 });
      } catch { /* may already be stopped */ }

      if (cfg.auto_remove !== false) {
        try {
          await runCmd('docker', ['rm', '-f', containerId], { timeout: 10000 });
        } catch { /* ignore */ }
      }
    }
  }
}

/**
 * Unified Runtime Job Runner (Theme 3)
 *
 * Manages the lifecycle of all runtime analysis jobs (fuzzers, debuggers,
 * network capture, port scans). Each tool implements RuntimeJobExecutor and
 * gets plugged in via registerExecutor(). The runner creates DB rows, builds
 * the JobContext, runs executors asynchronously, and exposes cancel hooks.
 *
 * Pattern mirrors server/pipeline/orchestrator.ts — an internal Map of active
 * jobs with per-job cancel closures, plus broadcastProgress() for live updates.
 */

import crypto from 'crypto';
import path from 'path';
import { promises as fs } from 'fs';
import {
  getRuntimeJobs,
  getRuntimeJobById,
  createRuntimeJob,
  updateRuntimeJob,
  type RuntimeJobRow,
  type RuntimeJobFilters,
} from '../../db.js';
import { broadcastProgress } from '../../ws.js';
import type {
  RuntimeJobSpec,
  RuntimeJobExecutor,
  JobContext,
  JobEvent,
} from './types.js';

const RUNTIME_DATA_ROOT = 'X:/vulnforge/data/runtime';

// ── Runner ─────────────────────────────────────────────────────────────────

export class RuntimeJobRunner {
  private activeJobs: Map<string, { cancel: () => void }> = new Map();
  private executors: Map<string, RuntimeJobExecutor> = new Map();

  /** Register a tool executor keyed by "<type>:<tool>". */
  registerExecutor(executor: RuntimeJobExecutor): void {
    const key = `${executor.type}:${executor.tool}`;
    this.executors.set(key, executor);
    console.log(`[Runtime] Registered executor: ${key}`);
  }

  /** Look up a registered executor for a given type/tool pair. */
  getExecutor(type: string, tool: string): RuntimeJobExecutor | null {
    return this.executors.get(`${type}:${tool}`) || null;
  }

  /** Dynamic-import all known executor modules, tolerating missing files. */
  async registerAllExecutors(): Promise<void> {
    const modules: Array<{ path: string; exportName: string; label: string }> = [
      { path: './fuzzers/libfuzzer.js', exportName: 'LibFuzzerExecutor', label: 'libFuzzer' },
      { path: './debuggers/gdb.js', exportName: 'GdbExecutor', label: 'gdb' },
      { path: './network/pcap.js', exportName: 'PcapExecutor', label: 'pcap' },
      { path: './network/nmap.js', exportName: 'NmapExecutor', label: 'nmap' },
      { path: './git/bisect.js', exportName: 'GitBisectExecutor', label: 'git-bisect' },
      { path: './symexec/angr.js', exportName: 'AngrExecutor', label: 'angr' },
      { path: './memory/core-dump.js', exportName: 'CoreDumpExecutor', label: 'core-dump' },
      { path: './binary/radare2.js', exportName: 'Radare2Executor', label: 'radare2' },
      { path: './sandbox/docker.js', exportName: 'DockerExecutor', label: 'docker-sandbox' },
    ];

    for (const mod of modules) {
      try {
        const loaded: any = await import(mod.path);
        const Ctor = loaded[mod.exportName];
        if (!Ctor) {
          console.warn(`[Runtime] Module ${mod.path} loaded but no ${mod.exportName} export`);
          continue;
        }
        const instance: RuntimeJobExecutor = new Ctor();
        this.registerExecutor(instance);
      } catch (err: any) {
        console.warn(`[Runtime] Executor ${mod.label} unavailable: ${err.message}`);
      }
    }
  }

  /** Get a job row by id (thin wrapper around DB). */
  getStatus(jobId: string): RuntimeJobRow | null {
    return getRuntimeJobById(jobId);
  }

  /** List jobs with optional filters. */
  list(filters: RuntimeJobFilters = {}): RuntimeJobRow[] {
    return getRuntimeJobs(filters);
  }

  /** Signal a running job to stop. Returns true if the job was active. */
  async stop(jobId: string): Promise<boolean> {
    const active = this.activeJobs.get(jobId);
    if (!active) {
      // Allow stopping a queued row that hasn't flipped to running yet
      const row = getRuntimeJobById(jobId);
      if (row && (row.status === 'queued' || row.status === 'running' || row.status === 'starting')) {
        updateRuntimeJob(jobId, {
          status: 'cancelled',
          completed_at: new Date().toISOString(),
        });
        return true;
      }
      return false;
    }
    active.cancel();
    updateRuntimeJob(jobId, { status: 'cancelled' });
    return true;
  }

  /**
   * Start a runtime job: validate spec, create output dir, insert DB row,
   * then execute asynchronously. Returns the job id immediately.
   */
  async start(spec: RuntimeJobSpec): Promise<string> {
    if (!spec || !spec.type || !spec.tool) {
      throw new Error('Job spec must include type and tool');
    }

    const executor = this.getExecutor(spec.type, spec.tool);
    if (!executor) {
      throw new Error(
        `No executor registered for ${spec.type}:${spec.tool}. ` +
          `Make sure the executor module is present and registerAllExecutors() ran.`
      );
    }

    const jobId = `rt-${crypto.randomBytes(6).toString('hex')}`;
    const outputDir = path.join(RUNTIME_DATA_ROOT, jobId);

    // Create per-job output directory under the canonical root.
    await fs.mkdir(outputDir, { recursive: true });

    // Validate config — executor throws on invalid input.
    const config = spec.config || {};
    try {
      executor.validate(config);
    } catch (err: any) {
      throw new Error(`Invalid config for ${spec.type}:${spec.tool}: ${err.message}`);
    }

    // Create DB row in queued state.
    createRuntimeJob({
      id: jobId,
      project_id: spec.projectId,
      finding_id: spec.findingId,
      type: spec.type,
      tool: spec.tool,
      config: JSON.stringify(config),
      output_dir: outputDir,
      status: 'queued',
      stats: '{}',
    });

    // Register cancellation for the running executor.
    let cancelled = false;
    this.activeJobs.set(jobId, {
      cancel: () => {
        cancelled = true;
      },
    });

    const ctx: JobContext = {
      jobId,
      outputDir,
      config,
      projectId: spec.projectId,
      findingId: spec.findingId,

      emit: (ev: Omit<JobEvent, 'timestamp'>): void => {
        try {
          broadcastProgress('runtime', jobId, {
            step: ev.type,
            detail: JSON.stringify(ev.data ?? {}),
            status: 'running',
          });
        } catch {
          // Non-fatal: WebSocket emit failures must not break a job.
        }
      },

      updateStats: (stats: Record<string, any>): void => {
        try {
          const current = getRuntimeJobById(jobId);
          let merged: Record<string, any> = {};
          if (current?.stats) {
            try {
              merged = JSON.parse(current.stats);
            } catch {
              merged = {};
            }
          }
          merged = { ...merged, ...stats };
          updateRuntimeJob(jobId, { stats: JSON.stringify(merged) });
        } catch (err: any) {
          console.warn(`[Runtime ${jobId}] updateStats failed: ${err.message}`);
        }
      },

      shouldStop: (): boolean => cancelled,
    };

    // Kick off async execution — do NOT await.
    this.runAsync(jobId, executor, ctx).catch((err: any) => {
      console.error(`[Runtime ${jobId}] Fatal runner error:`, err);
    });

    return jobId;
  }

  /** Internal async executor that manages status transitions + cleanup. */
  private async runAsync(
    jobId: string,
    executor: RuntimeJobExecutor,
    ctx: JobContext
  ): Promise<void> {
    try {
      updateRuntimeJob(jobId, { status: 'running' });
      broadcastProgress('runtime', jobId, {
        step: 'start',
        detail: `${executor.type}:${executor.tool}`,
        status: 'running',
      });

      await executor.execute(ctx);

      // If cancelled during execute, prefer 'cancelled' state.
      if (ctx.shouldStop()) {
        updateRuntimeJob(jobId, {
          status: 'cancelled',
          completed_at: new Date().toISOString(),
        });
        broadcastProgress('runtime', jobId, {
          step: 'cancelled',
          detail: 'Job was cancelled',
          status: 'complete',
        });
      } else {
        updateRuntimeJob(jobId, {
          status: 'completed',
          completed_at: new Date().toISOString(),
        });
        broadcastProgress('runtime', jobId, {
          step: 'complete',
          detail: `${executor.type}:${executor.tool} finished`,
          status: 'complete',
        });
      }
    } catch (err: any) {
      console.error(`[Runtime ${jobId}] executor failed:`, err);
      updateRuntimeJob(jobId, {
        status: 'failed',
        error: err?.message || String(err),
        completed_at: new Date().toISOString(),
      });
      broadcastProgress('runtime', jobId, {
        step: 'error',
        detail: err?.message || String(err),
        status: 'error',
      });
    } finally {
      this.activeJobs.delete(jobId);
    }
  }
}

// Singleton instance used throughout the server.
export const runtimeJobRunner = new RuntimeJobRunner();

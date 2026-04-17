/**
 * Server-mode scan worker. One child process per worker.
 *
 * Claims `pipeline_jobs` rows atomically, runs the pipeline, streams
 * progress over the main process's WebSocket fabric via IPC, and
 * updates the job row as it advances.
 *
 * Spawned from server/workers/pool.ts in server mode only.
 *
 * Claim protocol (SQLite has no FOR UPDATE SKIP LOCKED):
 *   BEGIN IMMEDIATE
 *     SELECT id FROM pipeline_jobs
 *       WHERE status='queued' AND worker_id IS NULL
 *       ORDER BY priority DESC, queued_at ASC
 *       LIMIT 1
 *     UPDATE pipeline_jobs
 *       SET status='claimed', worker_id=?, claimed_at=?
 *       WHERE id=?
 *   COMMIT
 * BEGIN IMMEDIATE takes the reserved lock so two workers serialize.
 */
import { initDb, getDb, persistDb } from '../db.js';
import { ulid } from '../utils/ulid.js';

export interface WorkerConfig {
  worker_id?: string;
  poll_interval_ms?: number;
  user_fairness_cap?: number;
}

interface PipelineJobRow {
  id: number;
  sync_id: string;
  project_id: number | null;
  requested_by_user_id: number | null;
  executor: 'local' | 'server';
  status: string;
  priority: number;
  stages_json: string;
  worker_id: string | null;
  queued_at: number;
  claimed_at: number | null;
  finished_at: number | null;
  error: string | null;
}

export class ScanWorker {
  private readonly id: string;
  private readonly pollMs: number;
  private readonly fairnessCap: number;
  private stopping = false;
  private loopPromise: Promise<void> | null = null;

  constructor(cfg: WorkerConfig = {}) {
    this.id = cfg.worker_id ?? `worker-${ulid()}`;
    this.pollMs = cfg.poll_interval_ms ?? 500;
    this.fairnessCap = cfg.user_fairness_cap ?? 0; // 0 = disabled
  }

  /** Start the claim/run loop. Resolves only when stop() is called. */
  async run(): Promise<void> {
    this.loopPromise = this.loop();
    await this.loopPromise;
  }

  stop(): void {
    this.stopping = true;
  }

  private async loop(): Promise<void> {
    while (!this.stopping) {
      const job = this.claimOne();
      if (!job) {
        await sleep(this.pollMs);
        continue;
      }
      await this.executeJob(job);
    }
  }

  private claimOne(): PipelineJobRow | null {
    const db = getDb();
    try {
      db.run('BEGIN IMMEDIATE');
      const findStmt = db.prepare(
        `SELECT * FROM pipeline_jobs
         WHERE status = 'queued' AND worker_id IS NULL
         ORDER BY priority DESC, queued_at ASC
         LIMIT 1`,
      );
      if (!findStmt.step()) { findStmt.free(); db.run('COMMIT'); return null; }
      const cols = findStmt.getColumnNames();
      const vals = findStmt.get();
      const row: Record<string, any> = {};
      cols.forEach((c: string, i: number) => { row[c] = vals[i]; });
      findStmt.free();

      // Fairness check — optional, enabled by fairnessCap>0
      if (this.fairnessCap > 0 && row.requested_by_user_id) {
        const countStmt = db.prepare(
          `SELECT COUNT(*) FROM pipeline_jobs
           WHERE requested_by_user_id = ? AND status IN ('claimed','running')`,
        );
        countStmt.bind([row.requested_by_user_id]);
        countStmt.step();
        const inflight = countStmt.get()[0] as number;
        countStmt.free();
        if (inflight >= this.fairnessCap) {
          db.run('COMMIT');
          return null;
        }
      }

      db.run(
        `UPDATE pipeline_jobs
         SET status = 'claimed', worker_id = ?, claimed_at = ?
         WHERE id = ?`,
        [this.id, Date.now(), row.id],
      );
      db.run('COMMIT');
      persistDb();
      return row as PipelineJobRow;
    } catch (e: any) {
      try { db.run('ROLLBACK'); } catch { /* ignore */ }
      console.error(`[scan-worker ${this.id}] claim error:`, e.message);
      return null;
    }
  }

  private async executeJob(job: PipelineJobRow): Promise<void> {
    const db = getDb();
    console.log(`[scan-worker ${this.id}] running job id=${job.id} sync=${job.sync_id}`);

    db.run(
      `UPDATE pipeline_jobs SET status = 'running' WHERE id = ?`,
      [job.id],
    );
    persistDb();

    try {
      // Delegate to the existing pipeline orchestrator. Lazy import to
      // avoid pulling the pipeline stack into test contexts.
      const pipelineModule = await import('../pipeline/orchestrator.js').catch(() => null);
      if (!pipelineModule) {
        throw new Error('pipeline orchestrator not found — compiled bundle incomplete');
      }

      const stages = safeParseStages(job.stages_json);
      const runFn = (pipelineModule as any).runPipelineJob;
      if (typeof runFn !== 'function') {
        throw new Error('pipeline orchestrator missing runPipelineJob');
      }

      await runFn({
        job_id: job.id,
        sync_id: job.sync_id,
        project_id: job.project_id,
        user_id: job.requested_by_user_id,
        stages,
        executor: 'server',
      });

      db.run(
        `UPDATE pipeline_jobs SET status = 'done', finished_at = ? WHERE id = ?`,
        [Date.now(), job.id],
      );
      persistDb();
      console.log(`[scan-worker ${this.id}] done id=${job.id}`);
    } catch (err: any) {
      console.error(`[scan-worker ${this.id}] job ${job.id} failed:`, err.message);
      db.run(
        `UPDATE pipeline_jobs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?`,
        [Date.now(), String(err.message || err), job.id],
      );
      persistDb();
    }
  }
}

function safeParseStages(raw: string): string[] {
  try {
    const v = JSON.parse(raw || '[]');
    return Array.isArray(v) ? v.map(String) : [];
  } catch { return []; }
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

// Standalone entrypoint — compiled worker runs as its own process.
if (process.argv[1]?.endsWith('scan-worker.js') || process.argv[1]?.endsWith('scan-worker.ts')) {
  (async () => {
    await initDb();
    const worker = new ScanWorker({
      worker_id: process.env.VULNFORGE_WORKER_ID,
      poll_interval_ms: Number(process.env.VULNFORGE_WORKER_POLL_MS || 500),
      user_fairness_cap: Number(process.env.VULNFORGE_WORKER_FAIRNESS_CAP || 0),
    });
    process.on('SIGTERM', () => worker.stop());
    process.on('SIGINT', () => worker.stop());
    await worker.run();
    process.exit(0);
  })().catch((err) => {
    console.error('[scan-worker] fatal:', err);
    process.exit(1);
  });
}

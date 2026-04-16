/**
 * Worker pool manager. Starts N scan-worker child processes in server mode,
 * supervises them, and exposes helpers to enqueue jobs from the API layer.
 *
 * In desktop mode this module is a no-op — desktop jobs run inline in
 * the existing pipeline code, same as before.
 *
 * Note: worker processes are launched via child_process.spawn with an
 * argv ARRAY (no shell). This is the safe form — no injection surface.
 */
import { cpus } from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { existsSync } from 'fs';
import cp from 'child_process';

import { getDb, persistDb } from '../db.js';
import { isServerMode } from '../deployment/mode.js';
import { ulid } from '../utils/ulid.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export interface PoolConfig {
  worker_count?: number;
  fairness_cap?: number;
}

interface WorkerHandle {
  id: string;
  child: cp.ChildProcess;
  startedAt: number;
}

const handles: WorkerHandle[] = [];
let started = false;

export function startWorkerPool(cfg: PoolConfig = {}): void {
  if (started) return;
  if (!isServerMode()) {
    console.log('[pool] not in server mode — worker pool disabled');
    return;
  }
  // Require the compiled worker script before spawning. In dev (tsx) the
  // .js doesn't exist and every spawn would fail with MODULE_NOT_FOUND;
  // set VULNFORGE_WORKERS=0 or run `npm run build:server` to enable.
  const scriptPath = path.resolve(__dirname, 'scan-worker.js');
  if (!existsSync(scriptPath)) {
    console.log(`[pool] compiled scan-worker.js not found at ${scriptPath} — worker pool disabled (run 'npm run build:server' for server-executor jobs)`);
    return;
  }
  const cores = Math.max(1, cpus().length - 1);
  const count = Math.max(0, cfg.worker_count ?? Number(process.env.VULNFORGE_WORKERS || cores));
  if (count === 0) {
    console.log('[pool] worker count is 0 — pool disabled');
    return;
  }
  const fairness = cfg.fairness_cap ?? Math.max(1, Math.floor(count / 2));

  for (let i = 0; i < count; i++) {
    startWorker(i, fairness);
  }
  started = true;
  console.log(`[pool] started ${count} scan workers (fairness cap=${fairness})`);
}

function startWorker(index: number, fairness: number): void {
  const workerId = `worker-${index}-${ulid()}`;
  const scriptPath = path.resolve(__dirname, 'scan-worker.js');
  // argv ARRAY form — no shell invocation, no injection surface.
  const child = cp.spawn(process.execPath, [scriptPath], {
    env: {
      ...process.env,
      VULNFORGE_WORKER_ID: workerId,
      VULNFORGE_WORKER_FAIRNESS_CAP: String(fairness),
    },
    stdio: ['ignore', 'inherit', 'inherit'],
    shell: false,
  });
  const handle: WorkerHandle = { id: workerId, child, startedAt: Date.now() };
  handles.push(handle);
  child.on('exit', (code, signal) => {
    const uptime = Date.now() - handle.startedAt;
    console.warn(`[pool] worker ${workerId} exited code=${code} signal=${signal} uptime=${uptime}ms`);
    const idx = handles.indexOf(handle);
    if (idx >= 0) handles.splice(idx, 1);
    // Auto-restart only if the pool is still active and the child lived
    // for >5 s. Prevents crash loops eating CPU.
    if (started && uptime > 5000) {
      setTimeout(() => startWorker(index, fairness), 1000);
    }
  });
}

export function stopWorkerPool(): void {
  started = false;
  for (const h of handles.splice(0)) {
    try { h.child.kill('SIGTERM'); } catch { /* noop */ }
  }
}

export function getPoolStatus(): {
  started: boolean;
  workers: Array<{ id: string; uptime_ms: number; pid: number | undefined }>;
} {
  return {
    started,
    workers: handles.map(h => ({ id: h.id, uptime_ms: Date.now() - h.startedAt, pid: h.child.pid })),
  };
}

// ── Enqueue helpers called by the pipeline route ───────────────────────────

export interface EnqueueArgs {
  project_id: number | null;
  requested_by_user_id: number | null;
  stages: string[];
  priority?: number;
}

export function enqueueServerJob(args: EnqueueArgs): { id: number; sync_id: string } {
  const db = getDb();
  const syncId = ulid();
  const now = Date.now();
  db.run(
    `INSERT INTO pipeline_jobs
       (sync_id, project_id, requested_by_user_id, executor, status, priority, stages_json, queued_at)
     VALUES (?, ?, ?, 'server', 'queued', ?, ?, ?)`,
    [syncId, args.project_id, args.requested_by_user_id, args.priority ?? 5, JSON.stringify(args.stages), now],
  );
  const idRow = db.exec('SELECT last_insert_rowid() AS id');
  const id = (idRow[0]?.values?.[0]?.[0] as number) ?? 0;
  persistDb();
  return { id, sync_id: syncId };
}

export function cancelServerJob(id: number): boolean {
  const db = getDb();
  db.run(
    `UPDATE pipeline_jobs
     SET status = 'cancelled', finished_at = ?
     WHERE id = ? AND status IN ('queued','claimed','running')`,
    [Date.now(), id],
  );
  persistDb();
  return true;
}

export function listServerJobs(limit = 100): Array<Record<string, any>> {
  const db = getDb();
  const stmt = db.prepare(
    `SELECT * FROM pipeline_jobs ORDER BY queued_at DESC LIMIT ?`,
  );
  stmt.bind([limit]);
  const rows: Array<Record<string, any>> = [];
  const cols = stmt.getColumnNames();
  while (stmt.step()) {
    const vals = stmt.get();
    const obj: Record<string, any> = {};
    cols.forEach((c, i) => { obj[c] = vals[i]; });
    rows.push(obj);
  }
  stmt.free();
  return rows;
}

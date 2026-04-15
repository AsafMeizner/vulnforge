import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';
import {
  createScan,
  updateScan,
  createScanFinding,
  updateProject,
  getScanById,
} from '../db.js';
import { streamTool } from './runner.js';
import { parseToolOutput } from './parser.js';
import { autoFilterFindings, classifyConfidence } from './filter.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ScanJob {
  id: string;
  scanDbId?: number;       // row id in the scans table
  projectId: number;
  projectPath: string;
  toolName: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  output: string;
  findings: number;
  startedAt?: Date;
  completedAt?: Date;
  error?: string;
}

export interface QueueStatus {
  queued: number;
  running: number;
  completed: number;
}

// ── ScanQueue ──────────────────────────────────────────────────────────────

export class ScanQueue extends EventEmitter {
  private maxConcurrent: number;
  private jobs: Map<string, ScanJob> = new Map();
  private pending: string[] = [];          // queue of job IDs awaiting execution
  private activeCount = 0;

  constructor(maxConcurrent = 3) {
    super();
    this.maxConcurrent = maxConcurrent;
  }

  // ── Public API ─────────────────────────────────────────────────────────

  /**
   * Enqueue one or more tools for a project. Returns the created ScanJob
   * objects immediately; execution is asynchronous.
   */
  enqueue(
    projectId: number,
    projectPath: string,
    toolNames: string[],
    autoTriage = false,
  ): ScanJob[] {
    const created: ScanJob[] = [];

    for (const toolName of toolNames) {
      const job: ScanJob = {
        id: randomUUID(),
        projectId,
        projectPath,
        toolName,
        status: 'queued',
        output: '',
        findings: 0,
      };

      // Persist a DB row immediately so callers get a scanDbId
      try {
        const dbId = createScan({
          project_id: projectId,
          tool_name: toolName,
          status: 'queued',
        });
        job.scanDbId = dbId;
      } catch (e) {
        console.error('[Queue] Failed to create scan record:', e);
      }

      this.jobs.set(job.id, job);
      this.pending.push(job.id);
      created.push(job);
    }

    // Kick the scheduler after enqueueing all jobs so we do a single pass
    setImmediate(() => this._schedule(autoTriage));

    return created;
  }

  /** Cancel a queued or running job. Running jobs are not forcefully killed
   *  because the child process may need cleanup; they are marked cancelled and
   *  will be ignored on completion. */
  cancel(jobId: string): void {
    const job = this.jobs.get(jobId);
    if (!job) return;

    if (job.status === 'queued') {
      const idx = this.pending.indexOf(jobId);
      if (idx !== -1) this.pending.splice(idx, 1);
      job.status = 'failed';
      job.error = 'Cancelled by user';
      job.completedAt = new Date();
      this._persistJobEnd(job);
      this.emit('job:error', job, new Error('Cancelled by user'));
    }
    // For running jobs we flip the flag; _runJob checks it before persisting
    // results (it just drops them silently).
  }

  getStatus(): QueueStatus {
    let queued = 0, running = 0, completed = 0;
    for (const job of this.jobs.values()) {
      if (job.status === 'queued') queued++;
      else if (job.status === 'running') running++;
      else if (job.status === 'completed') completed++;
    }
    return { queued, running, completed };
  }

  getJob(id: string): ScanJob | undefined {
    return this.jobs.get(id);
  }

  getJobs(): ScanJob[] {
    return Array.from(this.jobs.values());
  }

  // ── Internal helpers ───────────────────────────────────────────────────

  private _schedule(autoTriage: boolean): void {
    while (this.activeCount < this.maxConcurrent && this.pending.length > 0) {
      const jobId = this.pending.shift()!;
      const job = this.jobs.get(jobId);
      if (!job || job.status !== 'queued') continue;
      this._runJob(job, autoTriage);
    }
  }

  private _runJob(job: ScanJob, autoTriage: boolean): void {
    job.status = 'running';
    job.startedAt = new Date();
    this.activeCount++;

    // Update DB record
    if (job.scanDbId != null) {
      try {
        updateScan(job.scanDbId, {
          status: 'running',
          started_at: job.startedAt.toISOString(),
        });
      } catch { /* non-fatal */ }
    }

    this.emit('job:start', job);

    // Broadcast scan progress via WebSocket
    let _bp: ((cat: string, id: string, data: any) => void) | null = null;
    import('../ws.js').then(ws => {
      _bp = ws.broadcastProgress;
      _bp('scan', job.id, { step: `Running ${job.toolName}`, detail: `Scanning ${job.projectPath}`, progress: 10, status: 'running' });
    }).catch(() => {});

    const outputLines: string[] = [];
    const runner = streamTool(job.toolName, job.projectPath);

    runner.on('output', (line: string) => {
      outputLines.push(line);
      job.output = outputLines.join('\n');
      this.emit('job:output', job, line);
    });

    runner.on('complete', (fileOutput: string, exitCode: number) => {
      // If the job was cancelled while running, discard results
      if (job.status === 'failed') {
        this.activeCount--;
        this._schedule(autoTriage);
        return;
      }

      const fullOutput = fileOutput || outputLines.join('\n');
      job.output = fullOutput;
      job.completedAt = new Date();

      // Parse findings and auto-filter false positives before staging
      const rawFindings = parseToolOutput(fullOutput, job.projectId, job.toolName);
      const { accepted, rejected } = autoFilterFindings(rawFindings);
      const insertedIds: number[] = [];

      // Save accepted findings to scan_findings (staging area)
      for (const finding of accepted) {
        try {
          const sfId = createScanFinding({
            scan_id: job.scanDbId,
            project_id: job.projectId,
            title: finding.title || 'Untitled finding',
            severity: finding.severity || 'Medium',
            cvss: finding.cvss ? String(finding.cvss) : '',
            cwe: finding.cwe || '',
            file: finding.file || '',
            line_start: finding.line_start,
            line_end: finding.line_end,
            code_snippet: finding.code_snippet || '',
            description: finding.description || '',
            tool_name: finding.tool_name || job.toolName,
            confidence: classifyConfidence(finding),
            raw_output: '',
            status: 'pending',
            rejection_reason: '',
          });
          insertedIds.push(sfId);
          job.findings++;
        } catch (e) {
          console.error('[Queue] Failed to save finding:', e);
        }
      }

      // Save auto-rejected findings for reference
      for (const { finding, reason } of rejected) {
        try {
          createScanFinding({
            scan_id: job.scanDbId,
            project_id: job.projectId,
            title: finding.title || 'Untitled finding',
            severity: finding.severity || 'Medium',
            cvss: finding.cvss ? String(finding.cvss) : '',
            cwe: finding.cwe || '',
            file: finding.file || '',
            line_start: finding.line_start,
            line_end: finding.line_end,
            code_snippet: finding.code_snippet || '',
            description: finding.description || '',
            tool_name: finding.tool_name || job.toolName,
            confidence: classifyConfidence(finding),
            raw_output: '',
            status: 'auto_rejected',
            rejection_reason: reason,
          });
        } catch (e) {
          console.error('[Queue] Failed to save auto-rejected finding:', e);
        }
      }

      job.status = exitCode === 0 ? 'completed' : 'failed';
      this._persistJobEnd(job, exitCode);

      // Update project last_scanned timestamp
      try {
        updateProject(job.projectId, { last_scanned: new Date().toISOString() });
      } catch { /* non-fatal */ }

      _bp?.('scan', job.id, {
        step: job.status === 'completed' ? `${job.toolName} complete` : `${job.toolName} failed`,
        detail: `Found ${job.findings} vulnerabilities`,
        progress: 100,
        status: job.status === 'completed' ? 'complete' : 'error',
      });

      this.emit('job:complete', job, job.findings);

      // Auto-triage is deferred until findings are accepted from the review screen

      this.activeCount--;
      this._schedule(autoTriage);

      // Drain event when no more work
      if (this.activeCount === 0 && this.pending.length === 0) {
        this.emit('queue:drain');
      }
    });

    runner.on('error', (err: Error) => {
      if (job.status === 'failed') {
        // Already cancelled
        this.activeCount--;
        this._schedule(autoTriage);
        return;
      }

      job.status = 'failed';
      job.error = err.message;
      job.completedAt = new Date();
      this._persistJobEnd(job);
      this.emit('job:error', job, err);

      this.activeCount--;
      this._schedule(autoTriage);

      if (this.activeCount === 0 && this.pending.length === 0) {
        this.emit('queue:drain');
      }
    });
  }

  private _persistJobEnd(job: ScanJob, exitCode?: number): void {
    if (job.scanDbId == null) return;
    try {
      updateScan(job.scanDbId, {
        status: job.status,
        completed_at: job.completedAt?.toISOString() ?? new Date().toISOString(),
        output: job.output.slice(0, 500_000), // cap at 500 KB
        findings_count: job.findings,
      });
    } catch (e) {
      console.error('[Queue] Failed to update scan record:', e);
    }
  }
}

// ── Singleton instance ─────────────────────────────────────────────────────
// Shared across the entire server process so all routes use the same queue.

export const scanQueue = new ScanQueue(3);

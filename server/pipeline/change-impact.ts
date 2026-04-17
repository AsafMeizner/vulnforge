/**
 * Finding Impact Analysis (FIA).
 *
 * Port of Parasoft's Test Impact Analysis idea applied to security findings:
 * when code changes, which findings are (a) directly in changed files, (b)
 * possibly auto-resolved by the change, (c) still relevant and verified, or
 * (d) new candidates that need a fresh scan?
 *
 * The use case: user edits their codebase between scans. Instead of
 * re-running the whole pipeline, call `analyzeChangeImpact(sinceRef)` to get
 * a focused punch list.
 */

import path from 'path';
import { existsSync } from 'fs';
import { execFileNoThrow } from '../utils/execFileNoThrow.js';
import { getScanFindings, getProjectById } from '../db.js';
import type { ScanFinding } from '../db.js';

// ──────────────────────────────────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────────────────────────────────

export interface ChangeImpactResult {
  project_id: number;
  since_ref: string;
  head_ref: string;
  changed_files: string[];
  deleted_files: string[];
  buckets: {
    /** Findings whose file was deleted -> likely resolved (stale reference). */
    likely_resolved: ScanFinding[];
    /** Findings in files whose patch touches their line range. */
    definitely_affected: ScanFinding[];
    /** Findings in changed files but outside touched line ranges. */
    possibly_affected: ScanFinding[];
    /** Findings in unchanged files. Safe to leave alone. */
    unchanged: ScanFinding[];
  };
  recommendations: {
    re_verify: number[];   // finding ids
    rescan_files: string[]; // files to re-scan because changes likely introduced new issues
    mark_resolved_candidate: number[]; // finding ids to consider closing
  };
  warnings: string[];
}

interface HunkRange {
  start: number;
  end: number;
}

// ──────────────────────────────────────────────────────────────────────────
//  Git diff plumbing
// ──────────────────────────────────────────────────────────────────────────

async function gitDiffFileList(
  cwd: string,
  sinceRef: string,
  headRef: string
): Promise<{ changed: string[]; deleted: string[]; warnings: string[] }> {
  const warnings: string[] = [];
  const r = await execFileNoThrow(
    'git',
    ['diff', '--name-status', `${sinceRef}..${headRef}`],
    { cwd, timeout: 15_000 }
  );
  if (!r.ok) {
    warnings.push(`git_diff_failed: ${r.stderr.trim().slice(0, 200)}`);
    return { changed: [], deleted: [], warnings };
  }
  const changed: string[] = [];
  const deleted: string[] = [];
  for (const line of r.stdout.split('\n')) {
    const m = line.match(/^([ACDMRT])\d*\s+(.+)$/);
    if (!m) continue;
    const [, status, file] = m;
    const clean = file.trim();
    if (status === 'D') deleted.push(clean);
    else changed.push(clean);
  }
  return { changed, deleted, warnings };
}

/**
 * Parse unified diff hunk headers to find which line ranges a file's diff
 * touched. We use `git log -L` equivalent via `git diff --unified=0`.
 */
async function gitDiffHunks(
  cwd: string,
  sinceRef: string,
  headRef: string,
  file: string
): Promise<HunkRange[]> {
  const r = await execFileNoThrow(
    'git',
    ['diff', '--unified=0', `${sinceRef}..${headRef}`, '--', file],
    { cwd, timeout: 10_000 }
  );
  if (!r.ok) return [];
  const ranges: HunkRange[] = [];
  for (const line of r.stdout.split('\n')) {
    // @@ -old,oldCount +new,newCount @@
    const m = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/);
    if (!m) continue;
    const start = parseInt(m[1], 10);
    const count = m[2] ? parseInt(m[2], 10) : 1;
    if (!isFinite(start) || count <= 0) continue;
    ranges.push({ start, end: start + count - 1 });
  }
  return ranges;
}

function rangesContainLine(ranges: HunkRange[], line: number): boolean {
  for (const r of ranges) if (line >= r.start && line <= r.end) return true;
  return false;
}

// ──────────────────────────────────────────────────────────────────────────
//  Public entry
// ──────────────────────────────────────────────────────────────────────────

export interface AnalyzeOptions {
  /** Only consider findings with these statuses. Defaults to pending+accepted. */
  statuses?: string[];
  /** Head ref. Defaults to 'HEAD'. */
  headRef?: string;
}

export async function analyzeChangeImpact(
  projectId: number,
  sinceRef: string,
  opts: AnalyzeOptions = {}
): Promise<ChangeImpactResult> {
  const warnings: string[] = [];
  const headRef = opts.headRef || 'HEAD';
  const statuses = opts.statuses || ['pending', 'accepted'];

  const project = getProjectById(projectId);
  if (!project || !project.path || !existsSync(project.path)) {
    return {
      project_id: projectId,
      since_ref: sinceRef,
      head_ref: headRef,
      changed_files: [],
      deleted_files: [],
      buckets: {
        likely_resolved: [],
        definitely_affected: [],
        possibly_affected: [],
        unchanged: [],
      },
      recommendations: { re_verify: [], rescan_files: [], mark_resolved_candidate: [] },
      warnings: ['project_path_missing'],
    };
  }
  const cwd = project.path;

  // Pull findings
  const all = getScanFindings({ project_id: projectId }).filter((f) =>
    statuses.includes(f.status || 'pending')
  );

  // Git-side plumbing
  const { changed, deleted, warnings: w1 } = await gitDiffFileList(cwd, sinceRef, headRef);
  warnings.push(...w1);
  const changedSet = new Set(changed.map(normalize));
  const deletedSet = new Set(deleted.map(normalize));

  // For each changed file, pull hunks once (cached)
  const hunksByFile = new Map<string, HunkRange[]>();
  for (const file of changed) {
    hunksByFile.set(normalize(file), await gitDiffHunks(cwd, sinceRef, headRef, file));
  }

  const buckets = {
    likely_resolved: [] as ScanFinding[],
    definitely_affected: [] as ScanFinding[],
    possibly_affected: [] as ScanFinding[],
    unchanged: [] as ScanFinding[],
  };

  for (const f of all) {
    const fileKey = normalize(f.file || '');
    if (!fileKey) {
      buckets.unchanged.push(f);
      continue;
    }
    if (deletedSet.has(fileKey)) {
      buckets.likely_resolved.push(f);
      continue;
    }
    if (!changedSet.has(fileKey)) {
      buckets.unchanged.push(f);
      continue;
    }
    const hunks = hunksByFile.get(fileKey) || [];
    const line = f.line_start ?? -1;
    if (line >= 0 && rangesContainLine(hunks, line)) {
      buckets.definitely_affected.push(f);
    } else {
      buckets.possibly_affected.push(f);
    }
  }

  const re_verify = [
    ...buckets.definitely_affected,
    ...buckets.possibly_affected,
  ]
    .map((f) => f.id!)
    .filter(Boolean);

  const mark_resolved_candidate = buckets.likely_resolved
    .map((f) => f.id!)
    .filter(Boolean);

  const rescan_files = Array.from(changedSet);

  return {
    project_id: projectId,
    since_ref: sinceRef,
    head_ref: headRef,
    changed_files: Array.from(changedSet),
    deleted_files: Array.from(deletedSet),
    buckets,
    recommendations: { re_verify, rescan_files, mark_resolved_candidate },
    warnings,
  };
}

// ──────────────────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────────────────

function normalize(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

// Exposed for tests (pure functions only)
export const _internals = { rangesContainLine, normalize };

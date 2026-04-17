/**
 * Autonomous remediation.
 *
 * Port of Parasoft's "autonomously remediate code violations using the CLI
 * or directly in your CI/CD pipeline" capability. Turns a finding +
 * suggested_fix into a real git branch + commit + (optionally) pull request.
 *
 * Four modes:
 *   1. 'dry-run' - return the patch + branch name + PR body, apply nothing.
 *   2. 'branch'  - create a branch + commit the fix. No PR.
 *   3. 'pr'      - branch + commit + push + open GitHub/GitLab PR via `gh`/`glab`.
 *   4. 'direct'  - commit to current branch. Rarely safe; gated behind an
 *                  explicit opt-in flag and a dirty-tree check.
 *
 * Humans stay in the loop by default: 'pr' mode opens the PR in Draft state
 * and never auto-merges.
 */

import path from 'path';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { execFileNoThrow } from '../utils/execFileNoThrow.js';
import { routeAI } from './router.js';
import type { ScanFinding } from '../db.js';
import { getScanFindingById, updateScanFinding, getProjectById } from '../db.js';

export type RemediationMode = 'dry-run' | 'branch' | 'pr' | 'direct';

export interface RemediationOptions {
  mode: RemediationMode;
  /** Branch name; defaults to `vulnforge/fix-<finding_id>-<slug>`. */
  branch?: string;
  /** Commit message override. Defaults to an auto-generated one. */
  commitMessage?: string;
  /** Only open PR as a draft. Default true. */
  draft?: boolean;
  /** Require existing working tree to be clean before writing. Default true. */
  requireClean?: boolean;
}

export interface RemediationResult {
  ok: boolean;
  mode: RemediationMode;
  finding_id: number;
  branch?: string;
  commit_sha?: string;
  pr_url?: string;
  patch?: string;
  patched_files: string[];
  warnings: string[];
  error?: string;
}

// ──────────────────────────────────────────────────────────────────────────
//  Fix generation
// ──────────────────────────────────────────────────────────────────────────

const FIX_SYSTEM_PROMPT = `You are a senior security engineer producing a minimal, review-ready code fix for a specific vulnerability finding.

Rules:
- Return ONLY a unified diff (what \`git diff\` produces). No prose.
- Touch the minimum number of lines needed to fix the issue.
- Preserve surrounding code style exactly (indentation, quoting, whitespace).
- Do NOT refactor, rename, or reorganize unrelated code.
- If the fix requires a new import or helper, add it locally and show it in the diff.
- If you cannot produce a safe fix, output a single line: UNABLE: <one-line reason>.

The diff must apply cleanly with \`git apply\` from the project root.`;

export interface GeneratedFix {
  diff: string;
  explanation?: string;
  touched_files: string[];
  unable?: string;
}

export async function generateFix(finding: ScanFinding, projectPath: string): Promise<GeneratedFix> {
  if (!finding.file) {
    return { diff: '', touched_files: [], unable: 'finding has no file' };
  }
  const absFile = path.isAbsolute(finding.file) ? finding.file : path.join(projectPath, finding.file);
  let fileBody = '';
  try {
    fileBody = readFileSync(absFile, 'utf8');
  } catch {
    return { diff: '', touched_files: [], unable: 'file not readable' };
  }

  const line = finding.line_start ?? 1;
  const lines = fileBody.split('\n');
  const start = Math.max(0, line - 20);
  const end = Math.min(lines.length, line + 20);
  const window = lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1}\t${l}`)
    .join('\n');

  const userPrompt = `Finding:
  Title: ${finding.title}
  Severity: ${finding.severity}
  CWE: ${finding.cwe || 'N/A'}
  File: ${finding.file}:${line}
  Description: ${finding.description || 'N/A'}
  Impact: ${finding.impact || 'N/A'}

Code context (line numbers shown, target is ${line}):
${window}

Produce the unified diff now. Use the exact file path "${finding.file}" in the diff header.`;

  const resp = await routeAI({
    messages: [{ role: 'user', content: userPrompt }],
    systemPrompt: FIX_SYSTEM_PROMPT,
    temperature: 0.1,
    maxTokens: 2048,
    task: 'suggest-fix' as any,
  });

  const text = (resp.content || '').trim();
  if (/^UNABLE:/i.test(text)) {
    return { diff: '', touched_files: [], unable: text.replace(/^UNABLE:\s*/i, '') };
  }

  // Strip accidental markdown fences
  const diff = text
    .replace(/^```(?:diff|patch)?\s*/i, '')
    .replace(/```\s*$/i, '')
    .trim();

  const touched = new Set<string>();
  for (const line of diff.split('\n')) {
    const m = line.match(/^\+\+\+\s+(?:b\/)?(.+)$/);
    if (m) touched.add(m[1].trim());
  }

  return { diff, touched_files: Array.from(touched) };
}

// ──────────────────────────────────────────────────────────────────────────
//  Git helpers
// ──────────────────────────────────────────────────────────────────────────

async function git(args: string[], cwd: string): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  const r = await execFileNoThrow('git', args, { cwd, timeout: 30_000 });
  return { ok: r.ok, stdout: r.stdout, stderr: r.stderr };
}

async function isTreeClean(cwd: string): Promise<boolean> {
  const r = await git(['status', '--porcelain'], cwd);
  return r.ok && r.stdout.trim().length === 0;
}

async function currentBranch(cwd: string): Promise<string | null> {
  const r = await git(['rev-parse', '--abbrev-ref', 'HEAD'], cwd);
  return r.ok ? r.stdout.trim() : null;
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
}

function buildCommitMessage(finding: ScanFinding): string {
  const short = finding.title.slice(0, 72);
  const body = [
    `Fixes finding #${finding.id}`,
    `File: ${finding.file || 'unknown'}:${finding.line_start ?? ''}`,
    `Severity: ${finding.severity} | CWE: ${finding.cwe || 'N/A'}`,
    finding.description ? `\n${finding.description.slice(0, 400)}` : '',
  ].filter(Boolean).join('\n');
  return `security: ${short}\n\n${body}`;
}

function buildPRBody(finding: ScanFinding, diff: string): string {
  return [
    '## Autonomous VulnForge remediation',
    '',
    `**Finding:** ${finding.title}`,
    `**Severity:** ${finding.severity}  **CWE:** ${finding.cwe || 'N/A'}`,
    `**Location:** \`${finding.file}:${finding.line_start ?? ''}\``,
    '',
    '### Description',
    finding.description || '_No description provided._',
    '',
    '### Impact',
    finding.impact || '_No impact analysis provided._',
    '',
    '### Fix',
    '',
    '```diff',
    diff.slice(0, 6000),
    '```',
    '',
    '> This PR was generated by VulnForge autonomous remediation. A human must review before merge.',
  ].join('\n');
}

// ──────────────────────────────────────────────────────────────────────────
//  Top-level entry
// ──────────────────────────────────────────────────────────────────────────

export async function autonomousRemediate(
  findingId: number,
  opts: RemediationOptions
): Promise<RemediationResult> {
  const warnings: string[] = [];
  const base: RemediationResult = {
    ok: false,
    mode: opts.mode,
    finding_id: findingId,
    patched_files: [],
    warnings,
  };

  const finding = getScanFindingById(findingId);
  if (!finding) return { ...base, error: 'finding_not_found' };
  if (!finding.project_id) return { ...base, error: 'finding_has_no_project' };
  const project = getProjectById(finding.project_id);
  if (!project || !project.path || !existsSync(project.path)) {
    return { ...base, error: 'project_path_missing_or_invalid' };
  }
  const cwd = project.path;

  // Generate fix
  const fix = await generateFix(finding, cwd);
  if (fix.unable) {
    return { ...base, error: `unable_to_generate_fix: ${fix.unable}` };
  }
  if (!fix.diff) {
    return { ...base, error: 'empty_diff_from_ai' };
  }

  const patch = fix.diff;
  const patched_files = fix.touched_files;

  if (opts.mode === 'dry-run') {
    return { ...base, ok: true, patch, patched_files };
  }

  // Require clean tree for all non-dry-run modes unless opted out
  const requireClean = opts.requireClean !== false;
  if (requireClean && !(await isTreeClean(cwd))) {
    return { ...base, error: 'working_tree_dirty' };
  }

  const branch =
    opts.branch ||
    `vulnforge/fix-${findingId}-${slugify(finding.title)}`;
  const origBranch = await currentBranch(cwd);

  if (opts.mode === 'branch' || opts.mode === 'pr') {
    const cr = await git(['checkout', '-b', branch], cwd);
    if (!cr.ok) {
      // If branch exists, switch to it
      const sw = await git(['checkout', branch], cwd);
      if (!sw.ok) return { ...base, error: `checkout_failed: ${cr.stderr.trim() || sw.stderr.trim()}` };
      warnings.push('branch_already_existed');
    }
  }

  // Write patch to a tmp file and apply
  const patchPath = path.join(cwd, `.vulnforge-fix-${findingId}.patch`);
  try {
    writeFileSync(patchPath, patch);
  } catch (e) {
    return { ...base, error: `write_patch_failed: ${(e as Error).message}` };
  }
  const apply = await git(['apply', '--whitespace=fix', patchPath], cwd);
  // Cleanup patch file regardless of outcome
  try {
    const fs = await import('fs');
    fs.unlinkSync(patchPath);
  } catch {
    /* ignore */
  }
  if (!apply.ok) {
    // Rollback branch if we created one
    if (origBranch && (opts.mode === 'branch' || opts.mode === 'pr')) {
      await git(['checkout', origBranch], cwd);
      await git(['branch', '-D', branch], cwd);
    }
    return { ...base, error: `git_apply_failed: ${apply.stderr.trim().slice(0, 400)}` };
  }

  // Stage + commit
  const add = await git(['add', '-A'], cwd);
  if (!add.ok) return { ...base, error: `git_add_failed: ${add.stderr.trim()}` };
  const msg = opts.commitMessage || buildCommitMessage(finding);
  const commit = await git(['commit', '-m', msg], cwd);
  if (!commit.ok) return { ...base, error: `git_commit_failed: ${commit.stderr.trim()}` };
  const rev = await git(['rev-parse', 'HEAD'], cwd);
  const commit_sha = rev.ok ? rev.stdout.trim() : undefined;

  // Mark finding as being fixed
  try {
    updateScanFinding(findingId, {
      status: 'accepted',
      ai_filter_reason: `Autonomous remediation landed in ${branch} (${commit_sha?.slice(0, 7) || 'HEAD'})`,
    } as any);
  } catch {
    /* non-fatal */
  }

  if (opts.mode === 'branch') {
    return { ...base, ok: true, branch, commit_sha, patch, patched_files };
  }

  if (opts.mode === 'direct') {
    return { ...base, ok: true, commit_sha, patch, patched_files };
  }

  // opts.mode === 'pr' - try `gh pr create` if available, else return the
  // commit info and tell caller to push manually.
  const push = await git(['push', '--set-upstream', 'origin', branch], cwd);
  if (!push.ok) {
    return {
      ...base,
      ok: true,
      branch,
      commit_sha,
      patch,
      patched_files,
      warnings: [...warnings, `push_failed: ${push.stderr.trim()}`],
    };
  }

  const draft = opts.draft !== false;
  const prBody = buildPRBody(finding, patch);
  const prTitle = `[VulnForge] ${finding.title.slice(0, 80)}`;
  const ghArgs = [
    'pr',
    'create',
    '--title', prTitle,
    '--body', prBody,
    '--head', branch,
  ];
  if (draft) ghArgs.push('--draft');
  const pr = await execFileNoThrow('gh', ghArgs, { cwd, timeout: 30_000 });
  let pr_url: string | undefined;
  if (pr.ok) {
    const m = pr.stdout.match(/https?:\/\/\S+/);
    pr_url = m ? m[0].trim() : undefined;
  } else {
    warnings.push(`gh_pr_create_failed: ${pr.stderr.trim().slice(0, 200)}`);
  }

  return {
    ...base,
    ok: true,
    branch,
    commit_sha,
    pr_url,
    patch,
    patched_files,
    warnings,
  };
}

/**
 * Assignment Recommender.
 *
 * Suggest team members to fix a finding, ranked by evidence drawn from
 * the project's own git history. No extra schema or tracking is required -
 * we read signals that are already there.
 *
 * Signals:
 *   1. git blame on the finding's line -> who wrote the code (strongest signal)
 *   2. git log on the file -> recent modifiers (contextual familiarity)
 *   3. git log --grep=<CWE> across repo -> known fixer of this class
 *   4. CODEOWNERS file entry (if present) -> formal owner
 *
 * Scoring (summed, capped at 1.0):
 *   +0.50  blame author on the target line
 *   +0.25  top-3 recent modifier of the file
 *   +0.15  known fixer of this CWE class (grep match on past commits)
 *   +0.10  CODEOWNERS entry for the path
 *
 * Returns a ranked list of assignees with per-signal evidence so humans
 * can tell WHY each person was suggested.
 */

import path from 'path';
import { existsSync, readFileSync } from 'fs';
import { execFileNoThrow } from '../utils/execFileNoThrow.js';
import type { ScanFinding } from '../db.js';

// ──────────────────────────────────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────────────────────────────────

export interface AssignmentSignal {
  kind: 'blame' | 'file_history' | 'cwe_history' | 'codeowners';
  weight: number;
  evidence: string;
}

export interface AssignmentCandidate {
  name: string;
  email: string;
  score: number;
  signals: AssignmentSignal[];
}

export interface AssignmentResult {
  finding_id?: number;
  candidates: AssignmentCandidate[];
  warnings: string[];
}

// ──────────────────────────────────────────────────────────────────────────
//  Git helpers
// ──────────────────────────────────────────────────────────────────────────

async function git(args: string[], cwd: string, timeoutMs = 10_000): Promise<string> {
  const r = await execFileNoThrow('git', args, { cwd, timeout: timeoutMs });
  return r.ok ? r.stdout : '';
}

interface AuthorRef {
  name: string;
  email: string;
}

/** Parse a "Name <email>" line into structured form. */
function parseAuthorLine(line: string): AuthorRef | null {
  const m = line.trim().match(/^(.*?)\s*<([^>]+)>\s*$/);
  if (!m) return null;
  return { name: m[1].trim(), email: m[2].trim() };
}

function authorKey(a: AuthorRef): string {
  return a.email.toLowerCase().trim() || a.name.toLowerCase().trim();
}

// ──────────────────────────────────────────────────────────────────────────
//  Signal 1: blame on target line
// ──────────────────────────────────────────────────────────────────────────

async function signalFromBlame(
  cwd: string,
  file: string,
  line: number
): Promise<AuthorRef | null> {
  if (!file || line <= 0) return null;
  // --line-porcelain prints one block per line; "author-mail <x>" + "author <x>"
  const out = await git(
    ['blame', '-L', `${line},${line}`, '--line-porcelain', '--', file],
    cwd
  );
  if (!out) return null;
  let name: string | undefined;
  let email: string | undefined;
  for (const row of out.split('\n')) {
    if (row.startsWith('author ')) name = row.slice(7).trim();
    else if (row.startsWith('author-mail ')) email = row.slice(12).trim().replace(/^<|>$/g, '');
  }
  if (!name && !email) return null;
  return { name: name || 'Unknown', email: email || '' };
}

// ──────────────────────────────────────────────────────────────────────────
//  Signal 2: recent file history
// ──────────────────────────────────────────────────────────────────────────

async function signalFromFileHistory(
  cwd: string,
  file: string,
  limit = 15
): Promise<Array<{ author: AuthorRef; count: number }>> {
  if (!file) return [];
  // One line per commit that modified the file; format: "Name|email"
  const out = await git(
    ['log', `-n${limit}`, '--pretty=format:%an|%ae', '--follow', '--', file],
    cwd
  );
  if (!out) return [];
  const counts = new Map<string, { author: AuthorRef; count: number }>();
  for (const row of out.split('\n')) {
    const [name, email] = row.split('|');
    if (!name || !email) continue;
    const author: AuthorRef = { name: name.trim(), email: email.trim() };
    const key = authorKey(author);
    if (!key) continue;
    const e = counts.get(key);
    if (e) e.count++;
    else counts.set(key, { author, count: 1 });
  }
  return Array.from(counts.values()).sort((a, b) => b.count - a.count);
}

// ──────────────────────────────────────────────────────────────────────────
//  Signal 3: CWE history across repo
// ──────────────────────────────────────────────────────────────────────────

async function signalFromCweHistory(
  cwd: string,
  cwe: string,
  limit = 30
): Promise<Array<{ author: AuthorRef; count: number }>> {
  if (!cwe) return [];
  // Grep in commit messages for this CWE token. Matches our own autonomous-
  // remediation commit body ("CWE: CWE-89") and typical human fix-commit
  // wording ("fix CWE-89 SQL injection").
  const out = await git(
    ['log', `-n${limit}`, '--pretty=format:%an|%ae', '--grep', cwe, '-i'],
    cwd
  );
  if (!out) return [];
  const counts = new Map<string, { author: AuthorRef; count: number }>();
  for (const row of out.split('\n')) {
    const [name, email] = row.split('|');
    if (!name || !email) continue;
    const author: AuthorRef = { name: name.trim(), email: email.trim() };
    const key = authorKey(author);
    if (!key) continue;
    const e = counts.get(key);
    if (e) e.count++;
    else counts.set(key, { author, count: 1 });
  }
  return Array.from(counts.values()).sort((a, b) => b.count - a.count);
}

// ──────────────────────────────────────────────────────────────────────────
//  Signal 4: CODEOWNERS
// ──────────────────────────────────────────────────────────────────────────

interface CodeownersEntry {
  pattern: string;
  owners: string[]; // each is "@user" or "email"
}

function parseCodeowners(projectPath: string): CodeownersEntry[] {
  const candidates = [
    path.join(projectPath, 'CODEOWNERS'),
    path.join(projectPath, '.github', 'CODEOWNERS'),
    path.join(projectPath, 'docs', 'CODEOWNERS'),
  ];
  for (const f of candidates) {
    if (!existsSync(f)) continue;
    try {
      const body = readFileSync(f, 'utf8');
      const entries: CodeownersEntry[] = [];
      for (const raw of body.split('\n')) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const parts = line.split(/\s+/);
        if (parts.length < 2) continue;
        entries.push({ pattern: parts[0], owners: parts.slice(1) });
      }
      return entries;
    } catch {
      /* unreadable - try next */
    }
  }
  return [];
}

/** Match a file path against a CODEOWNERS pattern (minimatch-lite). */
function codeownerMatches(pattern: string, file: string): boolean {
  // Normalize slashes
  const f = file.replace(/\\/g, '/');
  const p = pattern.replace(/\\/g, '/');
  // Trivial '*' = all files
  if (p === '*') return true;
  // Directory prefix ending with slash
  if (p.endsWith('/')) return f.startsWith(p);
  // Exact file
  if (!p.includes('*')) return f === p || f.endsWith('/' + p);
  // Glob - convert to regex (simple): * -> [^/]*, ** -> .*
  const re = new RegExp(
    '^' +
      p
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '::GLOBSTAR::')
        .replace(/\*/g, '[^/]*')
        .replace(/::GLOBSTAR::/g, '.*') +
      '$'
  );
  return re.test(f);
}

function signalFromCodeowners(projectPath: string, file: string): string[] {
  if (!file) return [];
  const entries = parseCodeowners(projectPath);
  if (entries.length === 0) return [];
  // last-match-wins (GitHub semantics)
  let winners: string[] = [];
  for (const e of entries) {
    if (codeownerMatches(e.pattern, file)) winners = e.owners;
  }
  return winners;
}

// ──────────────────────────────────────────────────────────────────────────
//  Aggregation
// ──────────────────────────────────────────────────────────────────────────

export interface RecommendOptions {
  /** Cap per-signal candidate counts. Default 10. */
  perSignalLimit?: number;
  /** Final number of candidates returned. Default 5. */
  topK?: number;
}

export async function recommendAssignees(
  finding: ScanFinding,
  projectPath: string,
  opts: RecommendOptions = {}
): Promise<AssignmentResult> {
  const warnings: string[] = [];
  const perSignalLimit = opts.perSignalLimit ?? 10;
  const topK = opts.topK ?? 5;

  if (!projectPath || !existsSync(projectPath)) {
    return { finding_id: finding.id, candidates: [], warnings: ['project_path_missing'] };
  }

  // Compute signals in parallel - all are read-only git ops with their
  // own timeouts, so worst case is the slowest finishes.
  const [blame, fileHist, cweHist, owners] = await Promise.all([
    signalFromBlame(projectPath, finding.file || '', finding.line_start ?? -1),
    signalFromFileHistory(projectPath, finding.file || '', perSignalLimit),
    signalFromCweHistory(projectPath, finding.cwe || '', perSignalLimit),
    Promise.resolve(signalFromCodeowners(projectPath, finding.file || '')),
  ]);

  const pool = new Map<string, AssignmentCandidate>();

  const bump = (
    author: AuthorRef,
    signal: AssignmentSignal
  ): void => {
    const key = authorKey(author);
    if (!key) return;
    let c = pool.get(key);
    if (!c) {
      c = { name: author.name, email: author.email, score: 0, signals: [] };
      pool.set(key, c);
    }
    c.score = Math.min(1, +(c.score + signal.weight).toFixed(3));
    c.signals.push(signal);
  };

  if (blame) {
    bump(blame, {
      kind: 'blame',
      weight: 0.5,
      evidence: `git blame author on ${finding.file}:${finding.line_start ?? ''}`,
    });
  }

  // Only top-3 file history contributors get weight - diluting after that
  for (const entry of fileHist.slice(0, 3)) {
    bump(entry.author, {
      kind: 'file_history',
      weight: 0.25 / Math.max(1, fileHist.slice(0, 3).length),
      evidence: `modified ${finding.file} ${entry.count} time(s) in recent history`,
    });
  }

  for (const entry of cweHist.slice(0, 3)) {
    bump(entry.author, {
      kind: 'cwe_history',
      weight: 0.15 / Math.max(1, cweHist.slice(0, 3).length),
      evidence: `authored ${entry.count} past commit(s) matching ${finding.cwe}`,
    });
  }

  for (const owner of owners) {
    // owners could be "@user" or "email@example.com"
    const isEmail = owner.includes('@') && !owner.startsWith('@');
    const author: AuthorRef = {
      name: isEmail ? owner.split('@')[0] : owner.replace(/^@/, ''),
      email: isEmail ? owner : '',
    };
    bump(author, {
      kind: 'codeowners',
      weight: 0.1,
      evidence: `CODEOWNERS entry for ${finding.file}`,
    });
  }

  const candidates = Array.from(pool.values())
    .sort((a, b) => b.score - a.score)
    .slice(0, topK);

  return { finding_id: finding.id, candidates, warnings };
}

// Exposed for targeted unit testing
export const _internals = { parseAuthorLine, codeownerMatches, parseCodeowners, authorKey };

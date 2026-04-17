import { execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync } from 'fs';
import path from 'path';

const execFileAsync = promisify(execFile);

// ── Types ──────────────────────────────────────────────────────────────────

export interface SecurityCommit {
  hash: string;
  date: string;
  author: string;
  message: string;
  files_changed: string[];
  security_keywords: string[];
  severity_hint: 'critical' | 'high' | 'medium' | 'low';
}

export interface GitAnalysis {
  total_commits_analyzed: number;
  security_commits: SecurityCommit[];
  recently_changed_files: RecentlyChanged[];
  hot_files: string[];          // Files with most security-relevant changes
  has_full_history: boolean;
}

export interface RecentlyChanged {
  file: string;
  change_count: number;
  last_changed: string;
  is_security_sensitive: boolean;
}

export interface BlameResult {
  line: number;
  commit_hash: string;
  author: string;
  date: string;
  commit_message: string;
  age_days: number;
}

// ── Constants ──────────────────────────────────────────────────────────────

const SECURITY_KEYWORDS = [
  'fix', 'vuln', 'cve', 'security', 'overflow', 'injection', 'bypass',
  'crash', 'heap', 'buffer', 'race', 'use-after', 'null', 'auth',
  'sanitize', 'xss', 'csrf', 'sqli', 'rce', 'dos', 'denial',
  'privilege', 'escalat', 'traversal', 'deserializ', 'leak', 'expose',
  'patch', 'hardening', 'mitigation', 'exploit',
];

const CRITICAL_KEYWORDS = ['cve', 'rce', 'exploit', 'arbitrary code', 'remote code'];
const HIGH_KEYWORDS = ['overflow', 'use-after', 'injection', 'bypass', 'privilege', 'escalat'];

const SECURITY_SENSITIVE_PATHS = [
  /auth/i, /crypto/i, /ssl/i, /tls/i, /login/i, /password/i, /session/i,
  /token/i, /key/i, /cert/i, /pars(e|ing|er)/i, /deserializ/i,
  /network/i, /socket/i, /http/i, /request/i, /handler/i,
  /privilege/i, /permission/i, /access/i, /acl/i, /sandbox/i,
  /signal/i, /malloc/i, /free/i, /alloc/i, /buffer/i, /memory/i,
];

// ── Git History Analysis ───────────────────────────────────────────────────

/**
 * Analyze recent git commits for security-relevant changes.
 * Works with both shallow and full clones.
 */
export async function analyzeRecentCommits(
  projectPath: string,
  maxCommits = 200,
): Promise<GitAnalysis> {
  if (!existsSync(path.join(projectPath, '.git'))) {
    return { total_commits_analyzed: 0, security_commits: [], recently_changed_files: [], hot_files: [], has_full_history: false };
  }

  // Try to get more history if shallow
  let hasFullHistory = true;
  try {
    const { stdout } = await execFileAsync('git', ['rev-parse', '--is-shallow-repository'], { cwd: projectPath });
    if (stdout.trim() === 'true') {
      hasFullHistory = false;
      // Try to deepen history - don't fail if it doesn't work
      try {
        await execFileAsync('git', ['fetch', '--deepen=200'], { cwd: projectPath, timeout: 30_000 });
      } catch { /* shallow clone with no remote, that's OK */ }
    }
  } catch { /* not a git repo or git not available */ }

  // Get commit log
  const securityCommits: SecurityCommit[] = [];
  try {
    const { stdout } = await execFileAsync('git', [
      'log', `--max-count=${maxCommits}`, '--format=%H|%aI|%an|%s', '--name-only',
    ], { cwd: projectPath, timeout: 15_000 });

    let currentCommit: Partial<SecurityCommit> | null = null;
    let currentFiles: string[] = [];

    for (const line of stdout.split('\n')) {
      if (line.includes('|') && line.split('|').length >= 4) {
        // Flush previous commit
        if (currentCommit?.hash) {
          currentCommit.files_changed = currentFiles;
          const keywords = findSecurityKeywords(currentCommit.message || '');
          if (keywords.length > 0 || currentFiles.some(f => isSecuritySensitivePath(f))) {
            currentCommit.security_keywords = keywords;
            currentCommit.severity_hint = classifySeverity(keywords, currentCommit.message || '');
            securityCommits.push(currentCommit as SecurityCommit);
          }
        }
        const [hash, date, author, ...msgParts] = line.split('|');
        currentCommit = { hash, date, author, message: msgParts.join('|') };
        currentFiles = [];
      } else if (line.trim() && currentCommit) {
        currentFiles.push(line.trim());
      }
    }
    // Flush last commit
    if (currentCommit?.hash) {
      currentCommit.files_changed = currentFiles;
      const keywords = findSecurityKeywords(currentCommit.message || '');
      if (keywords.length > 0 || currentFiles.some(f => isSecuritySensitivePath(f))) {
        currentCommit.security_keywords = keywords;
        currentCommit.severity_hint = classifySeverity(keywords, currentCommit.message || '');
        securityCommits.push(currentCommit as SecurityCommit);
      }
    }
  } catch { /* ignore git log errors */ }

  // Get recently changed files
  const recentFiles = await getRecentlyChangedFiles(projectPath, 90);

  // Identify hot files: frequently changed + security sensitive
  const hotFiles = recentFiles
    .filter(f => f.is_security_sensitive && f.change_count >= 2)
    .map(f => f.file)
    .slice(0, 20);

  return {
    total_commits_analyzed: maxCommits,
    security_commits: securityCommits.slice(0, 50),
    recently_changed_files: recentFiles,
    hot_files: hotFiles,
    has_full_history: hasFullHistory,
  };
}

/**
 * Get files changed in the last N days, ranked by frequency.
 */
export async function getRecentlyChangedFiles(
  projectPath: string,
  days = 90,
): Promise<RecentlyChanged[]> {
  try {
    const since = new Date(Date.now() - days * 86400_000).toISOString().split('T')[0];
    const { stdout } = await execFileAsync('git', [
      'log', `--since=${since}`, '--format=', '--name-only', '--diff-filter=AMRC',
    ], { cwd: projectPath, timeout: 15_000 });

    const fileCounts = new Map<string, number>();
    for (const line of stdout.split('\n')) {
      const file = line.trim();
      if (file && !file.startsWith('.git')) {
        fileCounts.set(file, (fileCounts.get(file) || 0) + 1);
      }
    }

    return [...fileCounts.entries()]
      .map(([file, count]) => ({
        file,
        change_count: count,
        last_changed: '', // Could be enriched with per-file log
        is_security_sensitive: isSecuritySensitivePath(file),
      }))
      .sort((a, b) => b.change_count - a.change_count)
      .slice(0, 100);
  } catch {
    return [];
  }
}

/**
 * Find security-relevant commits (those mentioning CVEs or security terms).
 */
export async function findSecurityCommits(projectPath: string): Promise<SecurityCommit[]> {
  const analysis = await analyzeRecentCommits(projectPath, 500);
  return analysis.security_commits;
}

/**
 * Run git blame on a specific line to find when it was introduced.
 */
export async function blameVulnerableLine(
  projectPath: string,
  file: string,
  line: number,
): Promise<BlameResult | null> {
  try {
    const filePath = path.isAbsolute(file) ? path.relative(projectPath, file) : file;
    const { stdout } = await execFileAsync('git', [
      'blame', '-L', `${line},${line}`, '--porcelain', '--', filePath,
    ], { cwd: projectPath, timeout: 10_000 });

    const lines = stdout.split('\n');
    const hashLine = lines[0]?.split(' ');
    const hash = hashLine?.[0] || '';

    let author = '', date = '', message = '';
    for (const l of lines) {
      if (l.startsWith('author ')) author = l.slice(7);
      if (l.startsWith('author-time ')) {
        const ts = parseInt(l.slice(12));
        date = new Date(ts * 1000).toISOString();
      }
      if (l.startsWith('summary ')) message = l.slice(8);
    }

    const ageDays = Math.floor((Date.now() - new Date(date).getTime()) / 86400_000);

    return { line, commit_hash: hash, author, date, commit_message: message, age_days: ageDays };
  } catch {
    return null;
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

function findSecurityKeywords(message: string): string[] {
  const lower = message.toLowerCase();
  return SECURITY_KEYWORDS.filter(kw => lower.includes(kw));
}

function classifySeverity(keywords: string[], message: string): 'critical' | 'high' | 'medium' | 'low' {
  const lower = message.toLowerCase();
  if (CRITICAL_KEYWORDS.some(k => lower.includes(k))) return 'critical';
  if (HIGH_KEYWORDS.some(k => lower.includes(k))) return 'high';
  if (keywords.length >= 3) return 'high';
  if (keywords.length >= 1) return 'medium';
  return 'low';
}

function isSecuritySensitivePath(filePath: string): boolean {
  return SECURITY_SENSITIVE_PATHS.some(p => p.test(filePath));
}

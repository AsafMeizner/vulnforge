/**
 * Patch Analyzer — parses unified diffs to identify security-relevant
 * changes and extract grep patterns for variant hunting.
 */
import cp from 'child_process';
import { promisify } from 'util';

const runCmd = promisify(cp.execFile);

export interface PatchAnalysis {
  files_changed: string[];
  lines_added: number;
  lines_removed: number;
  added_snippets: string[];
  removed_snippets: string[];
  security_indicators: string[];   // which patterns triggered
  likely_category: string;         // 'auth' | 'parsing' | 'crypto' | 'memory' | 'input' | 'other'
  variant_patterns: string[];      // grep patterns to hunt variants across other projects
}

const SECURITY_PATTERNS: Record<string, { regex: RegExp; category: string }[]> = {
  added_boundscheck: [
    { regex: /\b(if|while)\s*\([^)]*(?:size|len|length|count|n|i)\s*[<>=!]+/i, category: 'memory' },
    { regex: /\bmemcpy_s|strcpy_s|strncpy|snprintf\b/, category: 'memory' },
  ],
  removed_auth: [
    { regex: /\b(auth|authentic|authoriz|verify|check_)/i, category: 'auth' },
    { regex: /\bpermission|role|ACL|access/i, category: 'auth' },
  ],
  type_change: [
    { regex: /\b(int|unsigned|size_t|ssize_t|uint\d+_t|int\d+_t)\s+\w+/, category: 'memory' },
  ],
  crypto: [
    { regex: /\b(AES|DES|RSA|HMAC|SHA|MD5|cipher|crypt|random|prng)/i, category: 'crypto' },
  ],
  parsing: [
    { regex: /\b(parse|deserial|strtok|sscanf|atoi|atol)/i, category: 'parsing' },
  ],
  input_validation: [
    { regex: /\b(sanitize|escape|validate|filter|clean)/i, category: 'input' },
  ],
};

/** Run `git show` on a commit and return the diff. */
export async function fetchCommitDiff(projectPath: string, sha: string): Promise<string> {
  try {
    const res = await runCmd('git', ['-C', projectPath, 'show', '--no-color', sha], {
      timeout: 15000,
      maxBuffer: 16 * 1024 * 1024,
    });
    return res.stdout;
  } catch (err: any) {
    throw new Error(`git show failed: ${err.message}`);
  }
}

/** Parse a unified diff into structured form and analyze for security indicators. */
export function analyzePatch(diff: string): PatchAnalysis {
  const filesChanged: string[] = [];
  const addedSnippets: string[] = [];
  const removedSnippets: string[] = [];
  let linesAdded = 0;
  let linesRemoved = 0;

  const lines = diff.split('\n');
  let currentFile: string | null = null;

  for (const line of lines) {
    if (line.startsWith('+++ b/')) {
      currentFile = line.slice(6);
      if (currentFile && !filesChanged.includes(currentFile)) {
        filesChanged.push(currentFile);
      }
      continue;
    }
    if (line.startsWith('--- ')) continue;
    if (line.startsWith('diff ')) continue;
    if (line.startsWith('@@')) continue;
    if (line.startsWith('index ')) continue;

    if (line.startsWith('+') && !line.startsWith('+++')) {
      linesAdded++;
      const content = line.slice(1);
      if (content.trim().length > 3) addedSnippets.push(content);
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      linesRemoved++;
      const content = line.slice(1);
      if (content.trim().length > 3) removedSnippets.push(content);
    }
  }

  // Scan for security indicators
  const indicators: string[] = [];
  const categoryCounts: Record<string, number> = {};
  const variantPatterns: string[] = [];

  const allChanges = [...addedSnippets, ...removedSnippets];
  for (const [name, patterns] of Object.entries(SECURITY_PATTERNS)) {
    for (const { regex, category } of patterns) {
      for (const snippet of allChanges) {
        if (regex.test(snippet)) {
          if (!indicators.includes(name)) indicators.push(name);
          categoryCounts[category] = (categoryCounts[category] || 0) + 1;

          // Derive a grep pattern from this snippet — keep significant identifiers
          const pattern = snippet.trim().replace(/\s+/g, ' ').slice(0, 80);
          if (!variantPatterns.includes(pattern) && variantPatterns.length < 10) {
            variantPatterns.push(pattern);
          }
          break;
        }
      }
    }
  }

  // Pick the top category
  let likelyCategory = 'other';
  let maxCount = 0;
  for (const [cat, count] of Object.entries(categoryCounts)) {
    if (count > maxCount) { likelyCategory = cat; maxCount = count; }
  }

  return {
    files_changed: filesChanged,
    lines_added: linesAdded,
    lines_removed: linesRemoved,
    added_snippets: addedSnippets.slice(0, 30),
    removed_snippets: removedSnippets.slice(0, 30),
    security_indicators: indicators,
    likely_category: likelyCategory,
    variant_patterns: variantPatterns,
  };
}

/** End-to-end: fetch a commit and analyze its patch. */
export async function analyzeCommit(projectPath: string, sha: string): Promise<PatchAnalysis> {
  const diff = await fetchCommitDiff(projectPath, sha);
  return analyzePatch(diff);
}

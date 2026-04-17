/**
 * Track F - Supply-chain & Backdoor Detection
 *
 * Entry point: runSupplyChainScan(projectPath, metadata) -> SupplyChainFinding[]
 *
 * Orchestrates five sub-scanners over the project tree:
 *   - Malicious / typosquatted packages
 *   - Secrets added then removed in git history
 *   - Weak or backdoored crypto
 *   - Hidden admin / debug-gate / time-bomb routes
 *   - Obfuscated or suspicious payloads
 *
 * All patterns live in `server/data/supply-chain-patterns.json` so the
 * ruleset can evolve without code changes.
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ──────────────────────────────────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────────────────────────────────

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export interface SupplyChainFinding {
  category:
    | 'malicious_package'
    | 'secret_in_history'
    | 'weak_crypto'
    | 'hidden_route'
    | 'obfuscation';
  subcategory: string;
  title: string;
  severity: Severity;
  file?: string;
  line_start?: number;
  evidence: string;
  confidence: number;
  cwe?: string;
  remediation?: string;
}

export interface ProjectMeta {
  language?: string;
  languages?: string[];
  dependencies?: string[];
  hasGit?: boolean;
}

interface SupplyChainPatterns {
  severityMap: Record<string, Severity>;
  entropyThresholds: { base64Blob: number; hexBlob: number; minBlobLength: number };
  skipDirs: string[];
  codeExtensions: string[];
  binaryExtensions: string[];
  topPackages: Record<string, string[]>;
  postinstallRedFlags?: Array<{ id: string; pattern: string; severity: Severity; reason: string }>;
  secretRegexes?: Array<{
    id: string;
    pattern: string;
    description: string;
    severity: Severity;
    cwe?: string;
  }>;
  cryptoRedFlags?: Array<{
    id: string;
    pattern: string;
    description: string;
    severity: Severity;
    cwe?: string;
    languages?: string[];
    remediation?: string;
  }>;
  backdoorRoutePatterns?: Array<{
    id: string;
    pattern: string;
    description: string;
    severity: Severity;
    cwe?: string;
    frameworks?: string[];
    remediation?: string;
  }>;
  obfuscationPatterns?: Array<{
    id: string;
    pattern: string;
    description: string;
    severity: Severity;
    cwe?: string;
    remediation?: string;
  }>;
}

// ──────────────────────────────────────────────────────────────────────────
//  Pattern loader
// ──────────────────────────────────────────────────────────────────────────

let _patternsCache: SupplyChainPatterns | null = null;

function loadPatterns(): SupplyChainPatterns {
  if (_patternsCache) return _patternsCache;
  const candidates = [
    path.resolve(__dirname, '..', '..', 'data', 'supply-chain-patterns.json'),
    path.resolve(__dirname, '..', '..', '..', 'server', 'data', 'supply-chain-patterns.json'),
    path.resolve(process.cwd(), 'server', 'data', 'supply-chain-patterns.json'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      _patternsCache = JSON.parse(readFileSync(p, 'utf8')) as SupplyChainPatterns;
      return _patternsCache;
    }
  }
  // Minimal fallback so the module never crashes on missing data file.
  _patternsCache = {
    severityMap: {},
    entropyThresholds: { base64Blob: 4.5, hexBlob: 3.8, minBlobLength: 1024 },
    skipDirs: ['.git', 'node_modules'],
    codeExtensions: ['.js', '.ts', '.py'],
    binaryExtensions: [],
    topPackages: {},
  };
  return _patternsCache;
}

// ──────────────────────────────────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────────────────────────────────

function walkCodeFiles(root: string, skipDirs: Set<string>, codeExts: Set<string>): string[] {
  const files: string[] = [];
  function walk(dir: string): void {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(dir, e);
      if (skipDirs.has(e)) continue;
      let st;
      try {
        st = statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) walk(p);
      else if (st.isFile() && codeExts.has(path.extname(e).toLowerCase())) files.push(p);
    }
  }
  walk(root);
  return files;
}

function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (Math.abs(m - n) > 3) return Math.abs(m - n); // early bail for perf
  const dp: number[] = new Array(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a[i - 1] === b[j - 1] ? prev : Math.min(prev, dp[j - 1], dp[j]) + 1;
      prev = tmp;
    }
  }
  return dp[n];
}

function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const k of Object.keys(freq)) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function readFileSafe(p: string): string {
  try {
    return readFileSync(p, 'utf8');
  } catch {
    return '';
  }
}

// ──────────────────────────────────────────────────────────────────────────
//  Sub-scanners
// ──────────────────────────────────────────────────────────────────────────

/** F2 - Malicious package detection: typosquatting + postinstall red flags. */
function scanPackages(projectPath: string, patterns: SupplyChainPatterns): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];

  const pj = path.join(projectPath, 'package.json');
  if (existsSync(pj)) {
    const raw = readFileSafe(pj);
    try {
      const pkg = JSON.parse(raw);
      const npmTop = new Set(patterns.topPackages.npm || []);
      const deps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
        ...(pkg.optionalDependencies || {}),
      };
      for (const depName of Object.keys(deps)) {
        if (npmTop.has(depName)) continue;
        for (const top of npmTop) {
          const d = editDistance(depName.toLowerCase(), top.toLowerCase());
          if (d > 0 && d <= 2) {
            findings.push({
              category: 'malicious_package',
              subcategory: 'typosquat',
              title: `Potential typosquat: "${depName}" is ${d} edit(s) from popular package "${top}"`,
              severity: 'Critical',
              file: pj,
              evidence: `${depName} vs ${top}`,
              confidence: d === 1 ? 0.85 : 0.65,
              cwe: 'CWE-1357',
              remediation:
                'Verify this package is the intended one. Check the registry for the canonical name.',
            });
            break;
          }
        }
      }

      // Postinstall red flags
      const scripts: Record<string, string> = pkg.scripts || {};
      const lifecycleHooks = ['preinstall', 'install', 'postinstall', 'prepare'];
      const redFlags =
        patterns.postinstallRedFlags && patterns.postinstallRedFlags.length > 0
          ? patterns.postinstallRedFlags
          : [
              { id: 'curl', pattern: '\\bcurl\\b', severity: 'High' as Severity, reason: 'Network fetch in install hook' },
              { id: 'wget', pattern: '\\bwget\\b', severity: 'High' as Severity, reason: 'Network fetch in install hook' },
              { id: 'base64-decode', pattern: 'base64\\s+-d', severity: 'High' as Severity, reason: 'Base64-decoding payload in install hook' },
              { id: 'node-eval', pattern: '\\beval\\s*\\(', severity: 'High' as Severity, reason: 'Dynamic code evaluation in install hook' },
              { id: 'rm-rf', pattern: '\\brm\\s+-rf\\s+/', severity: 'High' as Severity, reason: 'Destructive filesystem operation in install hook' },
            ];
      for (const hook of lifecycleHooks) {
        const cmd = scripts[hook];
        if (!cmd) continue;
        for (const rf of redFlags) {
          if (new RegExp(rf.pattern, 'i').test(cmd)) {
            findings.push({
              category: 'malicious_package',
              subcategory: 'postinstall_red_flag',
              title: `Suspicious ${hook} script: ${rf.reason}`,
              severity: rf.severity,
              file: pj,
              evidence: `"${hook}": "${cmd}"`,
              confidence: 0.8,
              cwe: 'CWE-506',
              remediation: 'Audit the install script; lifecycle hooks should not fetch or run arbitrary code.',
            });
          }
        }
      }
    } catch {
      /* malformed package.json - ignore */
    }
  }

  // requirements.txt (pypi) - typosquat only for brevity
  const reqTxt = path.join(projectPath, 'requirements.txt');
  if (existsSync(reqTxt)) {
    const pypiTop = new Set(patterns.topPackages.pypi || []);
    for (const line of readFileSafe(reqTxt).split(/\r?\n/)) {
      const name = line.split(/[<=>!~\s]/)[0]?.trim().toLowerCase();
      if (!name || name.startsWith('#') || pypiTop.has(name)) continue;
      for (const top of pypiTop) {
        const d = editDistance(name, top);
        if (d > 0 && d <= 2) {
          findings.push({
            category: 'malicious_package',
            subcategory: 'typosquat',
            title: `Potential typosquat: "${name}" is ${d} edit(s) from popular package "${top}"`,
            severity: 'Critical',
            file: reqTxt,
            evidence: `${name} vs ${top}`,
            confidence: d === 1 ? 0.85 : 0.65,
            cwe: 'CWE-1357',
          });
          break;
        }
      }
    }
  }

  return findings;
}

/** F3 - Secrets added then removed in git history. */
async function scanSecretsHistory(
  projectPath: string,
  patterns: SupplyChainPatterns
): Promise<SupplyChainFinding[]> {
  const findings: SupplyChainFinding[] = [];
  const gitDir = path.join(projectPath, '.git');
  if (!existsSync(gitDir)) return findings;

  const regexes =
    patterns.secretRegexes && patterns.secretRegexes.length > 0
      ? patterns.secretRegexes
      : [
          { id: 'aws-akid', pattern: 'AKIA[0-9A-Z]{16}', description: 'AWS access key', severity: 'Critical' as Severity, cwe: 'CWE-798' },
          { id: 'gh-pat', pattern: 'gh[pousr]_[A-Za-z0-9]{36,}', description: 'GitHub personal access token', severity: 'Critical' as Severity, cwe: 'CWE-798' },
          { id: 'slack-token', pattern: 'xox[baprs]-[A-Za-z0-9-]+', description: 'Slack token', severity: 'High' as Severity, cwe: 'CWE-798' },
          { id: 'pk-block', pattern: '-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----', description: 'Private key block', severity: 'Critical' as Severity, cwe: 'CWE-798' },
          { id: 'jwt', pattern: 'eyJ[A-Za-z0-9_=-]+\\.eyJ[A-Za-z0-9_=-]+\\.[A-Za-z0-9_.+/=-]+', description: 'JWT-shaped blob', severity: 'Medium' as Severity, cwe: 'CWE-798' },
        ];

  const result = await execFileNoThrow(
    'git',
    ['log', '--all', '-p', '--no-color', '--since=1 year ago'],
    { cwd: projectPath, maxBuffer: 50 * 1024 * 1024, timeout: 30_000 }
  );
  if (!result.ok) return findings;
  const stdout = result.stdout;

  for (const re of regexes) {
    const rx = new RegExp(re.pattern, 'g');
    const matches = stdout.match(rx);
    if (!matches) continue;
    const unique = Array.from(new Set(matches)).slice(0, 10);
    for (const m of unique) {
      findings.push({
        category: 'secret_in_history',
        subcategory: re.id,
        title: `${re.description} present in git history`,
        severity: re.severity,
        evidence: `${m.slice(0, 20)}... (redacted)`,
        confidence: 0.9,
        cwe: re.cwe,
        remediation:
          'Rotate this secret immediately. History rewrite (git filter-repo) + force-push only removes it from the origin you control; assume external copies exist.',
      });
    }
  }

  return findings;
}

/** F4 - Weak / backdoored crypto. */
function scanCrypto(
  files: string[],
  patterns: SupplyChainPatterns
): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  const rules =
    patterns.cryptoRedFlags && patterns.cryptoRedFlags.length > 0
      ? patterns.cryptoRedFlags
      : [
          { id: 'math-random-token', pattern: 'Math\\.random\\s*\\(\\s*\\).*?(token|secret|nonce|session)', description: 'Math.random() used for security-sensitive value', severity: 'High' as Severity, cwe: 'CWE-338' },
          { id: 'md5-password', pattern: '(md5|MD5)\\s*\\(.*?(password|passwd|pwd)', description: 'MD5 used for password hashing', severity: 'High' as Severity, cwe: 'CWE-328' },
          { id: 'sha1-password', pattern: '(sha1|SHA1|SHA-1)\\s*\\(.*?(password|passwd|pwd)', description: 'SHA1 used for password hashing', severity: 'High' as Severity, cwe: 'CWE-328' },
          { id: 'ecb-mode', pattern: 'AES[-_/ ]?(ECB)|\\bMODE_ECB\\b|\\bECB\\b', description: 'ECB cipher mode (deterministic)', severity: 'High' as Severity, cwe: 'CWE-327' },
          { id: 'des-cipher', pattern: '\\bDES(?!Keys?)\\b|createCipher\\s*\\(\\s*["\\\']des', description: 'DES cipher (broken)', severity: 'High' as Severity, cwe: 'CWE-327' },
          { id: 'rc4-cipher', pattern: '\\bRC4\\b|createCipher\\s*\\(\\s*["\\\']rc4', description: 'RC4 cipher (broken)', severity: 'High' as Severity, cwe: 'CWE-327' },
          { id: 'weak-seed', pattern: 'srand\\s*\\(\\s*time\\s*\\(', description: 'Seeding PRNG with time() is predictable', severity: 'Medium' as Severity, cwe: 'CWE-338' },
        ];

  for (const file of files) {
    const body = readFileSafe(file);
    if (!body) continue;
    const lines = body.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const rule of rules) {
        if (new RegExp(rule.pattern).test(line)) {
          findings.push({
            category: 'weak_crypto',
            subcategory: rule.id,
            title: rule.description,
            severity: rule.severity,
            file,
            line_start: i + 1,
            evidence: line.trim().slice(0, 200),
            confidence: 0.7,
            cwe: rule.cwe,
            remediation: rule.remediation,
          });
        }
      }
    }
  }
  return findings;
}

/** F5 - Hidden admin / debug-gate / time-bomb routes. */
function scanHiddenRoutes(
  files: string[],
  patterns: SupplyChainPatterns
): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  const rules =
    patterns.backdoorRoutePatterns && patterns.backdoorRoutePatterns.length > 0
      ? patterns.backdoorRoutePatterns
      : [
          { id: 'header-equality-bypass', pattern: 'headers\\[[\\\'"]x-(admin|debug|internal|secret)[\\\'"]\\]\\s*===?\\s*[\\\'"][^\\\'"]+[\\\'"]', description: 'Header-equality auth bypass', severity: 'High' as Severity, cwe: 'CWE-287' },
          { id: 'debug-flag-bypass', pattern: 'process\\.env\\.(DEBUG|DEV|NODE_ENV)\\s*[=!]==?\\s*["\\\']', description: 'Debug-flag gates auth-sensitive code', severity: 'Medium' as Severity, cwe: 'CWE-489' },
          { id: 'localhost-bypass', pattern: 'req\\.(ip|connection\\.remoteAddress)\\s*===?\\s*[\\\'"]127\\.0\\.0\\.1[\\\'"]', description: 'Localhost-only check without X-Forwarded-For guard', severity: 'Medium' as Severity, cwe: 'CWE-290' },
          { id: 'date-guard', pattern: '(Date\\.now\\(\\)|new Date\\(\\))\\s*[<>]\\s*[0-9]{10,}', description: 'Time-bomb: date comparison near security-sensitive code', severity: 'High' as Severity, cwe: 'CWE-367' },
        ];

  for (const file of files) {
    const body = readFileSafe(file);
    if (!body) continue;
    const lines = body.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const rule of rules) {
        if (new RegExp(rule.pattern).test(line)) {
          findings.push({
            category: 'hidden_route',
            subcategory: rule.id,
            title: rule.description,
            severity: rule.severity,
            file,
            line_start: i + 1,
            evidence: line.trim().slice(0, 200),
            confidence: 0.65,
            cwe: rule.cwe,
            remediation: rule.remediation,
          });
        }
      }
    }
  }
  return findings;
}

/** F6 - Obfuscated / suspicious payloads. */
function scanObfuscation(
  files: string[],
  patterns: SupplyChainPatterns
): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];
  const threshold = patterns.entropyThresholds;
  const rules =
    patterns.obfuscationPatterns && patterns.obfuscationPatterns.length > 0
      ? patterns.obfuscationPatterns
      : [
          { id: 'eval-atob', pattern: 'eval\\s*\\(\\s*atob\\s*\\(', description: 'eval(atob(...)) - decode then evaluate', severity: 'Critical' as Severity, cwe: 'CWE-94' },
          { id: 'function-ctor', pattern: 'Function\\s*\\([^)]*\\)\\s*\\(\\s*\\)', description: 'Dynamic Function() constructor invocation', severity: 'High' as Severity, cwe: 'CWE-94' },
          { id: 'python-dyn-compile', pattern: '(^|\\W)(?:exec|eval)\\s*\\(\\s*(compile\\s*\\(|base64\\.b64decode)', description: 'Python dynamic-compile or decode-then-run', severity: 'Critical' as Severity, cwe: 'CWE-94' },
          { id: 'jvm-runtime-shell', pattern: 'Runtime\\.getRuntime\\s*\\(\\s*\\)\\.\\w+', description: 'JVM Runtime.getRuntime() shell-spawn primitive', severity: 'High' as Severity, cwe: 'CWE-78' },
        ];

  for (const file of files) {
    const body = readFileSafe(file);
    if (!body) continue;

    // Entropy-flagged long base64/hex blobs
    const blobRe = /["'`]([A-Za-z0-9+/=]{512,}|[A-Fa-f0-9]{512,})["'`]/g;
    let m: RegExpExecArray | null;
    while ((m = blobRe.exec(body)) !== null) {
      const blob = m[1];
      if (blob.length < threshold.minBlobLength) continue;
      const e = shannonEntropy(blob);
      const isB64 = /^[A-Za-z0-9+/=]+$/.test(blob);
      const limit = isB64 ? threshold.base64Blob : threshold.hexBlob;
      if (e >= limit) {
        const lineIdx = body.slice(0, m.index).split('\n').length;
        findings.push({
          category: 'obfuscation',
          subcategory: isB64 ? 'high_entropy_base64' : 'high_entropy_hex',
          title: `High-entropy ${isB64 ? 'base64' : 'hex'} blob (${blob.length} chars, H=${e.toFixed(2)})`,
          severity: 'Medium',
          file,
          line_start: lineIdx,
          evidence: `${blob.slice(0, 50)}...`,
          confidence: 0.6,
          cwe: 'CWE-506',
          remediation: 'Verify this is not an obfuscated payload. Large high-entropy strings in source are a common staging technique.',
        });
      }
    }

    const lines = body.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const rule of rules) {
        if (new RegExp(rule.pattern).test(line)) {
          findings.push({
            category: 'obfuscation',
            subcategory: rule.id,
            title: rule.description,
            severity: rule.severity,
            file,
            line_start: i + 1,
            evidence: line.trim().slice(0, 200),
            confidence: 0.75,
            cwe: rule.cwe,
            remediation: rule.remediation,
          });
        }
      }
    }
  }
  return findings;
}

// ──────────────────────────────────────────────────────────────────────────
//  Public entry point
// ──────────────────────────────────────────────────────────────────────────

export async function runSupplyChainScan(
  projectPath: string,
  _metadata: ProjectMeta = {}
): Promise<SupplyChainFinding[]> {
  if (!projectPath || !existsSync(projectPath)) return [];
  const patterns = loadPatterns();
  const skip = new Set(patterns.skipDirs);
  const exts = new Set(patterns.codeExtensions.map((e) => e.toLowerCase()));

  const files = walkCodeFiles(projectPath, skip, exts);

  const results: SupplyChainFinding[] = [];
  const runSafe = async <T>(name: string, category: SupplyChainFinding['category'], fn: () => Promise<T[]> | T[]): Promise<T[]> => {
    try {
      const out = await fn();
      return out as T[];
    } catch (e) {
      results.push({
        category,
        subcategory: 'scanner_error',
        title: `${name} scanner errored`,
        severity: 'Info',
        evidence: String((e as Error).message || e),
        confidence: 1.0,
      });
      return [] as T[];
    }
  };

  results.push(...(await runSafe('Package', 'malicious_package', () => scanPackages(projectPath, patterns))));
  results.push(...(await runSafe('Secrets-history', 'secret_in_history', () => scanSecretsHistory(projectPath, patterns))));
  results.push(...(await runSafe('Crypto', 'weak_crypto', () => scanCrypto(files, patterns))));
  results.push(...(await runSafe('Hidden-route', 'hidden_route', () => scanHiddenRoutes(files, patterns))));
  results.push(...(await runSafe('Obfuscation', 'obfuscation', () => scanObfuscation(files, patterns))));

  return results;
}

// Utility exports for tests
export const _internals = { editDistance, shannonEntropy, loadPatterns, walkCodeFiles };

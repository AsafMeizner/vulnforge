import { readdirSync, readFileSync, existsSync } from 'fs';
import path from 'path';
import type { ProjectMeta } from './git.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface EntryPoint {
  type: 'network' | 'api_endpoint' | 'file_parser' | 'cli_arg' | 'env_var' | 'signal' | 'ipc' | 'timer' | 'exported_func';
  file: string;
  line: number;
  function_name: string;
  match: string;          // The matched line of code
  exposure: 'internet' | 'local_network' | 'local_user' | 'internal';
}

export interface TrustBoundary {
  entry_point: EntryPoint;
  auth_check_file?: string;
  auth_check_line?: number;
  pre_auth_functions: string[];  // Functions callable before auth
  validation_present: boolean;
}

export interface AttackSurface {
  entry_points: EntryPoint[];
  trust_boundaries: TrustBoundary[];
  pre_auth_files: string[];           // Files with code reachable before authentication
  network_exposed_functions: string[];
  total_entry_points: number;
  exposure_summary: Record<string, number>;
}

// ── Entry Point Patterns ───────────────────────────────────────────────────

interface PatternDef {
  type: EntryPoint['type'];
  patterns: RegExp[];
  exposure: EntryPoint['exposure'];
  languages?: string[];
}

const ENTRY_PATTERNS: PatternDef[] = [
  // Network listeners
  {
    type: 'network',
    exposure: 'internet',
    patterns: [
      /\b(socket|bind|listen|accept)\s*\(/,
      /\baccept4?\s*\(/,
      /\bcreateServer\s*\(/,
      /\bhttp\.createServer/,
      /\bnet\.createServer/,
      /\bhttp\.ListenAndServe/,
      /\bgin\.Default\(\)|fiber\.New\(\)|echo\.New\(\)/,
      /\bapp\s*=\s*express\(\)/,
      /\bFlask\s*\(__name__\)/,
      /\bDjango/i,
      /\bServerSocket\s*\(/,
      /\bTcpListener::bind/,
    ],
  },
  // API endpoints
  {
    type: 'api_endpoint',
    exposure: 'internet',
    patterns: [
      /\bapp\.(get|post|put|delete|patch|all|use)\s*\(\s*['"]/,
      /\brouter\.(get|post|put|delete|patch)\s*\(\s*['"]/,
      /\b@(Get|Post|Put|Delete|Patch|RequestMapping)\b/,
      /\bfunc\s+\w+Handler\b/,
      /\b@app\.route\s*\(/,
      /\b@api_view\b/,
      /\bdef\s+(get|post|put|delete|patch)\s*\(self/,
      /\b#\[(?:get|post|put|delete)\s*\("/,
    ],
  },
  // File/input parsers
  {
    type: 'file_parser',
    exposure: 'local_user',
    patterns: [
      /\bfopen\s*\(|fread\s*\(|read\s*\(/,
      /\bfs\.readFile|readFileSync/,
      /\bopen\s*\([^)]*['"]/,
      /\bxml\.parse|json\.load|yaml\.safe_load/,
      /\bJSON\.parse\s*\(/,
      /\bcsv\.reader|csv\.DictReader/,
      /\bImage\.open|PIL\.Image/,
      /\bpdf|docx|xlsx/i,
    ],
  },
  // CLI argument handling
  {
    type: 'cli_arg',
    exposure: 'local_user',
    patterns: [
      /\bgetopt\s*\(|getopt_long\s*\(/,
      /\bargv\[|sys\.argv|process\.argv/,
      /\bargparse\.ArgumentParser/,
      /\bcobra\.Command|flag\.String|pflag\./,
      /\bclap::App|structopt/,
      /\bOptionParser\.new/,
    ],
  },
  // Environment variables
  {
    type: 'env_var',
    exposure: 'local_user',
    patterns: [
      /\bgetenv\s*\(/,
      /\bos\.environ|os\.getenv/,
      /\bprocess\.env\./,
      /\bos\.Getenv\(/,
      /\bstd::env::var/,
      /\bENV\[/,
    ],
  },
  // Signal handlers
  {
    type: 'signal',
    exposure: 'local_network',
    patterns: [
      /\bsignal\s*\(\s*SIG/,
      /\bsigaction\s*\(/,
      /\bprocess\.on\s*\(\s*['"]SIG/,
      /\bsignal\.signal\s*\(/,
    ],
  },
  // IPC / shared memory
  {
    type: 'ipc',
    exposure: 'local_network',
    patterns: [
      /\bpipe\s*\(|mkfifo\s*\(/,
      /\bmmap\s*\(|shm_open\s*\(/,
      /\bshmget\s*\(|msgget\s*\(/,
      /\bUnixSocket|unix\.Listen/,
      /\bdbus|d-bus/i,
    ],
  },
];

// ── Skip patterns ──────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', '__pycache__', 'target',
  'build', 'dist', '.next', '.cache', 'test', 'tests', 'docs',
]);

const CODE_EXTENSIONS = new Set([
  '.c', '.h', '.cpp', '.cc', '.hpp', '.py', '.js', '.ts', '.jsx', '.tsx',
  '.go', '.rs', '.java', '.rb', '.php', '.cs', '.swift', '.kt', '.scala',
  '.ex', '.erl',
]);

// ── Main Functions ─────────────────────────────────────────────────────────

/**
 * Map all entry points in a project — network listeners, API endpoints,
 * file parsers, CLI handlers, environment readers, signal handlers, IPC.
 */
export function mapEntryPoints(projectPath: string, _meta?: ProjectMeta): EntryPoint[] {
  const entryPoints: EntryPoint[] = [];

  function scanDir(dir: string, depth: number): void {
    if (depth > 5) return;
    let entries: import('fs').Dirent[];
    try { entries = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' }); } catch { return; }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;

      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        scanDir(fullPath, depth + 1);
      } else if (entry.isFile() && CODE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        scanFile(fullPath, projectPath, entryPoints);
      }
    }
  }

  scanDir(projectPath, 0);
  return entryPoints;
}

function scanFile(filePath: string, projectPath: string, results: EntryPoint[]): void {
  let content: string;
  try { content = readFileSync(filePath, 'utf-8'); } catch { return; }

  const relPath = path.relative(projectPath, filePath);
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const patDef of ENTRY_PATTERNS) {
      for (const pattern of patDef.patterns) {
        if (pattern.test(line)) {
          // Extract function name from context
          const funcName = extractFunctionName(lines, i);
          results.push({
            type: patDef.type,
            file: relPath,
            line: i + 1,
            function_name: funcName,
            match: line.trim().slice(0, 120),
            exposure: patDef.exposure,
          });
          break; // Only one match per pattern group per line
        }
      }
    }
  }
}

/**
 * Map trust boundaries — find where authentication/validation happens
 * relative to entry points.
 */
export function mapTrustBoundaries(
  entryPoints: EntryPoint[],
  projectPath: string,
): TrustBoundary[] {
  const boundaries: TrustBoundary[] = [];

  // Auth/validation patterns
  const authPatterns = [
    /\bauth(enticate|orize|_check|_verify|_required)\b/i,
    /\bcheck_permission|has_permission|is_authenticated\b/i,
    /\bverify_token|validate_token|check_token\b/i,
    /\brequire_login|login_required|@auth\b/i,
    /\bpassword_verify|bcrypt|argon2\b/i,
    /\bJWT|bearer|oauth\b/i,
    /\bmiddleware.*auth/i,
  ];

  const validationPatterns = [
    /\bvalidate|sanitize|escape|filter_input\b/i,
    /\bbounds_check|range_check|length_check\b/i,
    /\binput_validation|param_check\b/i,
  ];

  for (const ep of entryPoints) {
    if (ep.type !== 'network' && ep.type !== 'api_endpoint') {
      boundaries.push({ entry_point: ep, pre_auth_functions: [], validation_present: false });
      continue;
    }

    const filePath = path.join(projectPath, ep.file);
    let content: string;
    try { content = readFileSync(filePath, 'utf-8'); } catch { continue; }

    const lines = content.split('\n');
    let authFound = false;
    let authLine = 0;
    let authFile = '';
    let validationFound = false;
    const preAuthFuncs: string[] = [];

    // Scan lines after the entry point for auth/validation
    for (let i = ep.line; i < Math.min(ep.line + 100, lines.length); i++) {
      const line = lines[i];

      if (!authFound) {
        // Track function calls before auth as pre-auth surface
        const funcCall = line.match(/\b(\w+)\s*\(/);
        if (funcCall && funcCall[1].length > 2) preAuthFuncs.push(funcCall[1]);
      }

      for (const p of authPatterns) {
        if (p.test(line)) {
          authFound = true;
          authLine = i + 1;
          authFile = ep.file;
          break;
        }
      }

      for (const p of validationPatterns) {
        if (p.test(line)) {
          validationFound = true;
          break;
        }
      }
    }

    boundaries.push({
      entry_point: ep,
      auth_check_file: authFound ? authFile : undefined,
      auth_check_line: authFound ? authLine : undefined,
      pre_auth_functions: preAuthFuncs.slice(0, 20),
      validation_present: validationFound,
    });
  }

  return boundaries;
}

/**
 * Score a finding's exposure level based on attack surface analysis.
 */
export function scoreExposure(
  findingFile: string,
  findingLine: number,
  entryPoints: EntryPoint[],
  trustBoundaries: TrustBoundary[],
): { exposure: string; reachable_from: string[]; in_pre_auth: boolean } {
  const reachableFrom: string[] = [];
  let inPreAuth = false;

  // Check if finding is in a file with entry points
  for (const ep of entryPoints) {
    if (ep.file === findingFile) {
      reachableFrom.push(`${ep.type}: ${ep.function_name}`);
    }
  }

  // Check if finding is in pre-auth code
  for (const tb of trustBoundaries) {
    if (tb.entry_point.file === findingFile && !tb.auth_check_line) {
      inPreAuth = true;
    }
    if (tb.auth_check_line && findingLine < tb.auth_check_line && tb.entry_point.file === findingFile) {
      inPreAuth = true;
    }
  }

  let exposure = 'internal';
  if (inPreAuth) exposure = 'pre_auth_critical';
  else if (reachableFrom.some(r => r.includes('network') || r.includes('api_endpoint'))) exposure = 'internet';
  else if (reachableFrom.length > 0) exposure = 'local';

  return { exposure, reachable_from: reachableFrom, in_pre_auth: inPreAuth };
}

/**
 * Generate full attack surface report.
 */
export function generateAttackSurface(projectPath: string, meta?: ProjectMeta): AttackSurface {
  const entryPoints = mapEntryPoints(projectPath, meta);
  const trustBoundaries = mapTrustBoundaries(entryPoints, projectPath);

  const preAuthFiles = [...new Set(
    trustBoundaries
      .filter(tb => !tb.auth_check_line || tb.pre_auth_functions.length > 5)
      .map(tb => tb.entry_point.file)
  )];

  const networkFuncs = entryPoints
    .filter(ep => ep.type === 'network' || ep.type === 'api_endpoint')
    .map(ep => ep.function_name)
    .filter(Boolean);

  const exposureSummary: Record<string, number> = {};
  for (const ep of entryPoints) {
    exposureSummary[ep.type] = (exposureSummary[ep.type] || 0) + 1;
  }

  return {
    entry_points: entryPoints,
    trust_boundaries: trustBoundaries,
    pre_auth_files: preAuthFiles,
    network_exposed_functions: networkFuncs,
    total_entry_points: entryPoints.length,
    exposure_summary: exposureSummary,
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────

function extractFunctionName(lines: string[], lineIdx: number): string {
  // Look backward for function definition
  for (let i = lineIdx; i >= Math.max(0, lineIdx - 10); i--) {
    const line = lines[i];
    // C/C++: type funcname(
    const cMatch = line.match(/\b(\w+)\s*\([^)]*\)\s*\{?\s*$/);
    if (cMatch) return cMatch[1];
    // Python: def funcname(
    const pyMatch = line.match(/\bdef\s+(\w+)\s*\(/);
    if (pyMatch) return pyMatch[1];
    // JS/TS: function name( or const name = (
    const jsMatch = line.match(/\bfunction\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=/);
    if (jsMatch) return jsMatch[1] || jsMatch[2];
    // Go: func Name(
    const goMatch = line.match(/\bfunc\s+(?:\([^)]+\)\s+)?(\w+)\s*\(/);
    if (goMatch) return goMatch[1];
  }
  return 'unknown';
}

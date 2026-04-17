// Shared helpers for injection detectors.
//
// Pure functions, no external deps beyond Node stdlib. Kept intentionally
// small so each detector stays self-contained and easy to unit test.

import { readdirSync, readFileSync, statSync, existsSync } from 'fs';
import path from 'path';

// Directories we never recurse into — big and noisy, and rarely contain
// the taint sinks we're looking for.
export const SKIP_DIRS = new Set<string>([
  '.git', 'node_modules', 'vendor', '__pycache__', 'target',
  'build', 'dist', 'dist-server', '.next', '.cache', '.venv',
  'venv', '.tox', '.mypy_cache', '.pytest_cache', 'coverage',
  '.nuxt', '.output', 'out',
]);

/**
 * Recursively find files under `projectPath` whose lowercased extension
 * matches one of `exts` (which should include the leading dot, e.g. `.py`).
 *
 * Depth-bounded to avoid runaway walks on pathological repos.
 */
export function findFilesByExt(
  projectPath: string,
  exts: string[],
  maxDepth = 8,
): string[] {
  const wanted = new Set(exts.map((e) => e.toLowerCase()));
  const out: string[] = [];
  if (!existsSync(projectPath)) return out;

  function walk(dir: string, depth: number): void {
    if (depth > maxDepth) return;
    let entries: import('fs').Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      if (entry.name.startsWith('.') && entry.name !== '.') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full, depth + 1);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (wanted.has(ext)) out.push(full);
      }
    }
  }

  try {
    const st = statSync(projectPath);
    if (st.isDirectory()) walk(projectPath, 0);
    else if (st.isFile()) {
      const ext = path.extname(projectPath).toLowerCase();
      if (wanted.has(ext)) out.push(projectPath);
    }
  } catch {
    /* ignore */
  }
  return out;
}

/**
 * Read a file as UTF-8 text. Returns null on any error (missing file,
 * encoding issue, etc) so callers can skip cleanly.
 */
export function readFileText(file: string): string | null {
  try {
    return readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Test whether `source` imports (or requires) any of the given module
 * names. Matches common forms across Python, JS/TS, Ruby, PHP, Java, C#,
 * Go. The comparison is substring-based per-line after extracting the
 * module-name position, so it intentionally errs on the side of
 * recall — callers always pair this with a sink check.
 */
export function hasImport(source: string, modules: string[]): boolean {
  if (!source || !modules.length) return false;
  const mods = modules.map((m) => m.toLowerCase());

  // Fast early reject: if none of the module names appear at all, done.
  const lower = source.toLowerCase();
  if (!mods.some((m) => lower.includes(m))) return false;

  const lines = source.split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    // Python: `import X`, `from X import ...`, `from X.Y import ...`
    const py = line.match(/^(?:from\s+([\w.]+)\s+import\b|import\s+([\w.,\s]+))/);
    if (py) {
      const names = (py[1] ?? py[2] ?? '')
        .split(/[,\s]+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      for (const m of mods) {
        if (names.includes(m) || names.some((n) => n.startsWith(m + '.') || m.startsWith(n + '.'))) return true;
      }
    }
    // JS/TS ESM: `import ... from 'X'` or `import 'X'`
    const js = line.match(/^import\s+(?:[^'"`]+\s+from\s+)?['"`]([^'"`]+)['"`]/);
    if (js) {
      const n = js[1].toLowerCase();
      if (mods.some((m) => n === m || n.startsWith(m + '/') || n.endsWith('/' + m))) return true;
    }
    // CommonJS: `require('X')`
    const cjs = line.match(/require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/);
    if (cjs) {
      const n = cjs[1].toLowerCase();
      if (mods.some((m) => n === m || n.startsWith(m + '/') || n.endsWith('/' + m))) return true;
    }
    // Ruby: `require 'X'`, `require_relative 'X'`
    const rb = line.match(/^\s*require(?:_relative)?\s+['"`]([^'"`]+)['"`]/);
    if (rb) {
      const n = rb[1].toLowerCase();
      if (mods.some((m) => n === m || n.endsWith('/' + m))) return true;
    }
    // PHP: `use X\Y`
    const php = line.match(/^\s*use\s+([\w\\]+)/i);
    if (php) {
      const n = php[1].toLowerCase().replace(/\\/g, '.');
      if (mods.some((m) => n === m || n.startsWith(m + '.'))) return true;
    }
    // Java / Kotlin: `import X.Y.Z;`
    const jv = line.match(/^\s*import\s+(?:static\s+)?([\w.]+)\s*;?/);
    if (jv) {
      const n = jv[1].toLowerCase();
      if (mods.some((m) => n === m || n.startsWith(m + '.'))) return true;
    }
    // C#: `using X.Y;`
    const cs = line.match(/^\s*using\s+([\w.]+)\s*;/);
    if (cs) {
      const n = cs[1].toLowerCase();
      if (mods.some((m) => n === m || n.startsWith(m + '.'))) return true;
    }
  }
  return false;
}

/**
 * Split source into lines and yield (lineNumber, lineText) pairs.
 * Line numbers are 1-based to match editor/IDE conventions and the
 * `line_start` convention used elsewhere in the pipeline.
 */
export function* enumerateLines(source: string): Generator<[number, string]> {
  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) yield [i + 1, lines[i]];
}

/**
 * Is the line a comment-only line in common languages? Cheap heuristic
 * — we strip leading whitespace then check for `#`, `//`, `/*`, or `*`
 * (for C-style continuation).
 */
export function isCommentLine(line: string): boolean {
  const t = line.trim();
  if (!t) return true;
  return t.startsWith('#') || t.startsWith('//') || t.startsWith('/*') || t.startsWith('*') || t.startsWith('--');
}

/**
 * Heuristic: does this line look like it touches a "tainted" source
 * (request, body, query, params, etc.)? Used as a source-confidence
 * boost when combined with a sink match on the same line or function.
 */
export function looksTainted(line: string): boolean {
  return TAINTED_SOURCE_RE.test(line);
}

// Broad taint source regex — covers HTTP request objects, IO reads, CLI
// args, env vars, and WebSocket/socket receives. Kept as a single regex
// for fast per-line checks.
export const TAINTED_SOURCE_RE =
  /\b(?:req(?:uest)?\.(?:body|query|params|headers|cookies|url|path|raw)|request\.(?:GET|POST|form|args|values|files|json|data)|params\[|Request\.(?:Form|QueryString|Params|InputStream|Body)|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|input\(|readline\(|stdin\b|sys\.argv|process\.argv|os\.environ|process\.env|getenv\(|recv\(|readFile|read\(\)|urlopen|http\.get|fetch\(|ws\.on\s*\(\s*['"]message['"]|socket\.on\s*\(\s*['"](?:data|message)['"])/i;

/**
 * Return a short 1-based line snippet for evidence. Strips to 200 chars
 * and collapses tabs to single spaces so it fits nicely in UI panels
 * and JSON reports.
 */
export function snippet(line: string, max = 200): string {
  const s = line.replace(/\t/g, ' ').trim();
  return s.length > max ? s.slice(0, max) + '…' : s;
}

/**
 * Return path relative to project root, using forward slashes. Keeps
 * the UI and DB consistent across platforms.
 */
export function relPath(projectPath: string, file: string): string {
  const rel = path.relative(projectPath, file);
  return rel.split(path.sep).join('/');
}

/**
 * Parse a simple semver-ish version string. Returns [major, minor, patch]
 * or null if unparseable. Strips leading `^`, `~`, `>=`, `=`, `v` so we
 * can compare against a declared package.json range.
 */
export function parseSemver(v: string | null | undefined): [number, number, number] | null {
  if (!v) return null;
  const cleaned = v.trim().replace(/^[\^~><=vV\s]+/, '');
  const m = cleaned.match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

/**
 * Compare two semvers. Returns -1 if a < b, 0 if equal, 1 if a > b.
 */
export function semverCmp(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

/**
 * Stable deterministic ID for a finding so the orchestrator and chain
 * detector can reference it. Derived from (subcategory, file, line, sink).
 */
export function findingId(
  subcategory: string,
  file: string,
  line: number | undefined,
  sink: string,
): string {
  return `inj:${subcategory}:${file}:${line ?? 0}:${sink}`.slice(0, 180);
}

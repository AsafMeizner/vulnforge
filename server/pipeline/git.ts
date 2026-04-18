import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import path from 'path';
import crypto from 'crypto';

const execFileAsync = promisify(execFile);

// ── Types ──────────────────────────────────────────────────────────────────

export interface CloneOptions {
  branch?: string;
  depth?: number;     // default 1 (shallow)
  /**
   * Total timeout in ms. Default 30 minutes. The single biggest cause of
   * the "pipeline stuck at 5%" complaint is that cloning a large repo
   * (Linux kernel, Chromium) takes longer than a 5-minute execFile cap.
   */
  timeoutMs?: number;
  /**
   * If set, called with every progress line git emits on stderr plus a
   * parsed 0-100 percent when the line looks like "Receiving objects:
   * NN% (x/y)" or "Resolving deltas: NN%". Caller typically wires this
   * to broadcastProgress so the UI can see live bytes/percent and
   * doesn't look frozen for multi-minute clones.
   */
  onProgress?: (line: string, percent?: number) => void;
  /**
   * If set, we emit a heartbeat via onProgress at least every N ms,
   * even if git hasn't logged anything. Protects against the "UI looks
   * dead" problem when git is doing slow local work (resolving deltas,
   * writing files).
   */
  heartbeatMs?: number;
}

export interface CloneResult {
  localPath: string;
  branch: string;
  commitHash: string;
}

export interface ProjectMeta {
  languages: string[];          // e.g. ['C', 'C++']
  primaryLanguage: string;
  buildSystems: string[];       // e.g. ['CMake', 'Makefile']
  dependencyFiles: string[];    // e.g. ['package.json', 'requirements.txt']
  hasTests: boolean;
  estimatedSize: 'small' | 'medium' | 'large';
}

export interface DependencyInfo {
  ecosystem: string;            // 'npm' | 'pypi' | 'cargo' | 'go' | 'maven' | 'gem'
  file: string;                 // path to the dep file
  packages: { name: string; version: string }[];
}

// ── Constants ──────────────────────────────────────────────────────────────

// Cloned repos land here. Env-configurable so a packaged install on a
// different drive/OS isn't forced onto the dev's X:/ drive. Default
// follows the rest of the data dirs under the server's working dir.
const REPOS_DIR = process.env.VULNFORGE_REPOS_DIR || path.join(process.cwd(), 'data/repos');

const LANG_EXT_MAP: Record<string, string> = {
  '.c': 'C', '.h': 'C', '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++', '.hpp': 'C++',
  '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.jsx': 'JavaScript',
  '.tsx': 'TypeScript', '.go': 'Go', '.rs': 'Rust', '.java': 'Java', '.rb': 'Ruby',
  '.php': 'PHP', '.cs': 'C#', '.swift': 'Swift', '.kt': 'Kotlin', '.zig': 'Zig',
  '.lua': 'Lua', '.pl': 'Perl', '.r': 'R', '.scala': 'Scala', '.ex': 'Elixir',
  '.erl': 'Erlang', '.hs': 'Haskell', '.ml': 'OCaml',
};

const BUILD_SYSTEM_FILES: Record<string, string> = {
  'Makefile': 'Make', 'GNUmakefile': 'Make', 'makefile': 'Make',
  'CMakeLists.txt': 'CMake', 'configure': 'Autotools', 'configure.ac': 'Autotools',
  'meson.build': 'Meson', 'BUILD': 'Bazel', 'BUILD.bazel': 'Bazel', 'WORKSPACE': 'Bazel',
  'Cargo.toml': 'Cargo', 'go.mod': 'Go Modules', 'package.json': 'npm',
  'pom.xml': 'Maven', 'build.gradle': 'Gradle', 'build.gradle.kts': 'Gradle',
  'Gemfile': 'Bundler', 'setup.py': 'setuptools', 'pyproject.toml': 'pyproject',
  'requirements.txt': 'pip', 'Pipfile': 'Pipenv',
  'composer.json': 'Composer', 'mix.exs': 'Mix', 'stack.yaml': 'Stack',
  'SConstruct': 'SCons', 'vcpkg.json': 'vcpkg', 'conanfile.txt': 'Conan',
};

const DEP_FILES: Record<string, string> = {
  'package.json': 'npm', 'package-lock.json': 'npm', 'yarn.lock': 'npm',
  'requirements.txt': 'pypi', 'Pipfile': 'pypi', 'pyproject.toml': 'pypi', 'setup.py': 'pypi',
  'Cargo.toml': 'cargo', 'Cargo.lock': 'cargo',
  'go.mod': 'go', 'go.sum': 'go',
  'pom.xml': 'maven', 'build.gradle': 'maven', 'build.gradle.kts': 'maven',
  'Gemfile': 'gem', 'Gemfile.lock': 'gem',
  'composer.json': 'composer', 'composer.lock': 'composer',
  'vcpkg.json': 'vcpkg', 'conanfile.txt': 'conan',
};

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', '__pycache__', '.tox', '.venv',
  'target', 'build', 'dist', '.next', '.cache', 'coverage',
]);

// ── Git Clone ──────────────────────────────────────────────────────────────

/**
 * Validates and normalizes a git repo URL.
 * Accepts: https://github.com/org/repo, git@github.com:org/repo.git, etc.
 */
export function validateRepoUrl(url: string): boolean {
  const patterns = [
    /^https?:\/\/(github|gitlab|bitbucket)\.\w+\/[\w.\-]+\/[\w.\-]+/i,
    /^https?:\/\/[\w.\-]+\/[\w.\-]+\/[\w.\-]+/i,  // generic HTTPS
    /^git@[\w.\-]+:[\w.\-]+\/[\w.\-]+/i,           // SSH
  ];
  return patterns.some(p => p.test(url.trim()));
}

/**
 * Extract a human-readable repo name from a URL.
 */
export function repoNameFromUrl(url: string): string {
  const cleaned = url.replace(/\.git$/, '').replace(/\/$/, '');
  const parts = cleaned.split('/');
  return parts[parts.length - 1] || 'unknown-repo';
}

/**
 * Parse a git stderr line like "Receiving objects: 42% (123/456), 12 MiB | 3 MiB/s"
 * into a 0-100 percent. Returns undefined for unparseable lines.
 *
 * Git's progress lines are the *only* way to know what's happening
 * during a clone of a multi-gigabyte repo - without them the UI just
 * sees `stage=cloning progress=5` for 20 minutes, which is what
 * triggered the "it just didn't progress" complaint.
 */
function parseGitProgress(line: string): number | undefined {
  // Receiving objects: 12% (23432/195000)  <-- network download
  // Resolving deltas: 89% (12345/15000)    <-- local work
  const m = line.match(/(?:Receiving objects|Resolving deltas|Unpacking objects|Checking out files):\s+(\d{1,3})%/);
  if (!m) return undefined;
  const n = Number(m[1]);
  return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : undefined;
}

/**
 * Clone a git repo into the local repos directory with live progress
 * streamed back via `opts.onProgress`. Uses `spawn` (not execFileAsync)
 * so stderr is readable line-by-line as git emits it.
 *
 * Git only emits progress when it thinks it's on a TTY, so we force it
 * with --progress. Without that flag, a clone of a large repo is
 * completely silent on stderr until it finishes or fails.
 */
export async function cloneRepo(url: string, opts: CloneOptions = {}): Promise<CloneResult> {
  const name = repoNameFromUrl(url);
  const hash = crypto.randomBytes(4).toString('hex');
  const localPath = path.join(REPOS_DIR, `${name}-${hash}`);

  const args = ['clone', '--progress'];
  if (opts.depth) args.push('--depth', String(opts.depth));
  else args.push('--depth', '1');  // shallow by default
  if (opts.branch) args.push('--branch', opts.branch);
  args.push('--', url, localPath);

  const totalTimeout = opts.timeoutMs ?? 30 * 60_000; // 30 min default
  const heartbeat = opts.heartbeatMs ?? 3_000;

  await new Promise<void>((resolve, reject) => {
    const child = spawn('git', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let lastErr = '';
    let lastEmit = Date.now();
    let lastLine = 'starting clone';

    // Overall watchdog. If git hangs for the full timeout, kill it and
    // reject with a human-readable message instead of letting the
    // pipeline sit in `cloning` state until the heat death of the drive.
    const killTimer = setTimeout(() => {
      try { child.kill('SIGTERM'); } catch { /* ignore */ }
      reject(new Error(`Git clone timed out after ${Math.round(totalTimeout / 60_000)}m (last: ${lastLine})`));
    }, totalTimeout);

    // Heartbeat. If stderr has been quiet for too long, emit the last
    // known line again so the UI at least shows "still working".
    const heartbeatTimer = setInterval(() => {
      if (Date.now() - lastEmit > heartbeat && opts.onProgress) {
        opts.onProgress(`still working: ${lastLine}`, parseGitProgress(lastLine));
      }
    }, heartbeat);

    const onLine = (buf: Buffer) => {
      // Git uses \r to overwrite a progress line and \n for final line.
      // Split on either so we see each progress update as its own event.
      const text = buf.toString('utf8');
      for (const raw of text.split(/[\r\n]+/)) {
        const line = raw.trim();
        if (!line) continue;
        lastErr += line + '\n';
        lastLine = line;
        lastEmit = Date.now();
        if (opts.onProgress) opts.onProgress(line, parseGitProgress(line));
      }
    };
    child.stderr?.on('data', onLine);
    child.stdout?.on('data', onLine);
    child.on('error', (err) => {
      clearTimeout(killTimer); clearInterval(heartbeatTimer);
      reject(new Error(`Git clone failed to start: ${err.message}`));
    });
    child.on('close', (code) => {
      clearTimeout(killTimer); clearInterval(heartbeatTimer);
      if (code === 0) resolve();
      else reject(new Error(`Git clone failed (exit ${code}): ${lastErr.slice(-400).trim()}`));
    });
  });

  // Get branch and commit hash
  let branch = opts.branch || 'main';
  let commitHash = '';
  try {
    const branchResult = await execFileAsync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: localPath });
    branch = branchResult.stdout.trim();
  } catch { /* use default */ }
  try {
    const hashResult = await execFileAsync('git', ['rev-parse', '--short', 'HEAD'], { cwd: localPath });
    commitHash = hashResult.stdout.trim();
  } catch { /* leave empty */ }

  return { localPath, branch, commitHash };
}

// ── Project Analysis ───────────────────────────────────────────────────────

/**
 * Detect languages, build systems, and dependencies in a project directory.
 */
export function detectProjectMeta(dirPath: string): ProjectMeta {
  const langCounts: Record<string, number> = {};
  const buildSystems = new Set<string>();
  const depFiles: string[] = [];
  let hasTests = false;
  let fileCount = 0;

  function scan(dir: string, depth: number): void {
    if (depth > 4) return;
    let entries: import('fs').Dirent[];
    try { entries = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' }); } catch { return; }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;

      const fullPath = path.join(dir, entry.name);
      if (entry.isFile()) {
        fileCount++;
        const ext = path.extname(entry.name).toLowerCase();
        const lang = LANG_EXT_MAP[ext];
        if (lang) langCounts[lang] = (langCounts[lang] || 0) + 1;

        // Build system detection
        if (BUILD_SYSTEM_FILES[entry.name]) {
          buildSystems.add(BUILD_SYSTEM_FILES[entry.name]);
        }

        // Dependency file detection
        if (DEP_FILES[entry.name]) {
          depFiles.push(path.relative(dirPath, fullPath));
        }

        // Test detection
        if (!hasTests && (entry.name.includes('test') || entry.name.includes('spec'))) {
          hasTests = true;
        }
      } else if (entry.isDirectory()) {
        if (entry.name === 'test' || entry.name === 'tests' || entry.name === '__tests__') {
          hasTests = true;
        }
        scan(fullPath, depth + 1);
      }
    }
  }

  scan(dirPath, 0);

  const sorted = Object.entries(langCounts).sort(([, a], [, b]) => b - a);
  const languages = sorted.map(([lang]) => lang);
  const primaryLanguage = languages[0] || 'unknown';

  const estimatedSize = fileCount < 100 ? 'small' : fileCount < 5000 ? 'medium' : 'large';

  return {
    languages,
    primaryLanguage,
    buildSystems: [...buildSystems],
    dependencyFiles: depFiles,
    hasTests,
    estimatedSize,
  };
}

// ── Dependency Extraction ──────────────────────────────────────────────────

/**
 * Parse dependency files to extract package lists.
 */
export function extractDependencies(dirPath: string): DependencyInfo[] {
  const results: DependencyInfo[] = [];

  function tryParse(relFile: string, ecosystem: string): void {
    const fullPath = path.join(dirPath, relFile);
    if (!existsSync(fullPath)) return;

    try {
      const content = readFileSync(fullPath, 'utf-8');
      const packages: { name: string; version: string }[] = [];

      switch (ecosystem) {
        case 'npm': {
          const pkg = JSON.parse(content);
          for (const [name, ver] of Object.entries(pkg.dependencies || {})) {
            packages.push({ name, version: String(ver) });
          }
          for (const [name, ver] of Object.entries(pkg.devDependencies || {})) {
            packages.push({ name, version: String(ver) });
          }
          break;
        }
        case 'pypi': {
          if (relFile.endsWith('requirements.txt')) {
            for (const line of content.split('\n')) {
              const trimmed = line.trim();
              if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
              const match = trimmed.match(/^([\w\-_.]+)\s*([=<>!~]+.+)?/);
              if (match) packages.push({ name: match[1], version: match[2] || '*' });
            }
          } else if (relFile.endsWith('pyproject.toml')) {
            // Basic TOML dep extraction - handles common format
            const depMatch = content.match(/\[project\]\s*[\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
            if (depMatch) {
              for (const line of depMatch[1].split('\n')) {
                const m = line.match(/"([\w\-_.]+)([^"]*)?"/);
                if (m) packages.push({ name: m[1], version: m[2] || '*' });
              }
            }
          }
          break;
        }
        case 'cargo': {
          // Basic Cargo.toml dep parsing
          const depsSection = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
          if (depsSection) {
            for (const line of depsSection[1].split('\n')) {
              const m = line.match(/^([\w\-_]+)\s*=\s*"?([^"\n]+)"?/);
              if (m) packages.push({ name: m[1], version: m[2] });
            }
          }
          break;
        }
        case 'go': {
          // go.mod parsing
          const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
          if (requireBlock) {
            for (const line of requireBlock[1].split('\n')) {
              const m = line.trim().match(/^([\w./\-]+)\s+(v[\w.\-+]+)/);
              if (m) packages.push({ name: m[1], version: m[2] });
            }
          }
          // Single-line require
          for (const line of content.split('\n')) {
            const m = line.match(/^require\s+([\w./\-]+)\s+(v[\w.\-+]+)/);
            if (m) packages.push({ name: m[1], version: m[2] });
          }
          break;
        }
        case 'gem': {
          // Gemfile parsing
          for (const line of content.split('\n')) {
            const m = line.match(/gem\s+['"](\S+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/);
            if (m) packages.push({ name: m[1], version: m[2] || '*' });
          }
          break;
        }
        case 'maven': {
          if (relFile.endsWith('pom.xml')) {
            // Basic XML dep extraction
            const depBlocks = content.matchAll(/<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>(?:\s*<version>([^<]+)<\/version>)?/g);
            for (const m of depBlocks) {
              packages.push({ name: `${m[1]}:${m[2]}`, version: m[3] || '*' });
            }
          }
          break;
        }
      }

      if (packages.length > 0) {
        results.push({ ecosystem, file: relFile, packages });
      }
    } catch {
      // Skip unparseable files
    }
  }

  // Scan root directory for known dependency files
  try {
    const entries = readdirSync(dirPath);
    for (const name of entries) {
      const eco = DEP_FILES[name];
      if (eco) tryParse(name, eco);
    }
  } catch { /* ignore */ }

  return results;
}

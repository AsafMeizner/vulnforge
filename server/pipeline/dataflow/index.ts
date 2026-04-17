/**
 * Track I - Multi-hop dataflow & taint analysis
 *
 * Entry: analyzeDataflow(projectPath, finding) -> DataflowResult
 *
 * Given a finding (with file + line), walks backward through a regex-based
 * call graph to find the nearest untrusted source. Returns a best-effort
 * TaintStep[] path + confidence. This is NOT a precise dataflow engine; it
 * surfaces likely-tainted findings for AI verification rather than proving
 * taint formally.
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import path from 'path';
import {
  matchSource,
  matchSink,
  hasSanitizer,
  langFromExt,
  type Lang,
} from './sources-sinks.js';

// ──────────────────────────────────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────────────────────────────────

export type TaintKind = 'source' | 'propagator' | 'sink';

export interface TaintStep {
  file: string;
  line: number;
  fn?: string;
  kind: TaintKind;
  code: string;
  variable?: string;
}

export interface DataflowResult {
  tainted: boolean;
  confidence: number;
  path: TaintStep[];
  reason: string;
}

export interface DataflowFinding {
  file: string;
  line_start?: number;
  title?: string;
  code_snippet?: string;
}

interface CallGraphNode {
  file: string;
  line: number;
  name: string;
  body: string;
  calls: string[];
}

// ──────────────────────────────────────────────────────────────────────────
//  Call graph (lightweight, regex-based)
// ──────────────────────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', '__pycache__', 'target',
  'build', 'dist', '.next', '.cache', 'coverage',
]);

const CODE_EXTS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.py', '.go', '.java', '.rb', '.php',
]);

const _graphCache = new Map<string, { fingerprint: string; nodes: CallGraphNode[] }>();

function walkFiles(root: string): string[] {
  const out: string[] = [];
  function walk(dir: string): void {
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      if (SKIP_DIRS.has(e)) continue;
      const p = path.join(dir, e);
      let st;
      try { st = statSync(p); } catch { continue; }
      if (st.isDirectory()) walk(p);
      else if (st.isFile() && CODE_EXTS.has(path.extname(e).toLowerCase())) out.push(p);
    }
  }
  walk(root);
  return out;
}

/**
 * Extract function-like declarations per language. Best-effort regex — gets
 * the common cases right without a full parser. Missing functions simply
 * produce no flow through them.
 */
function parseFunctionsInFile(file: string, body: string): CallGraphNode[] {
  const nodes: CallGraphNode[] = [];
  const ext = path.extname(file).toLowerCase();
  const lines = body.split('\n');

  const patterns: Array<{ re: RegExp; nameIdx: number }> = [];
  if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'].includes(ext)) {
    patterns.push({ re: /^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(/, nameIdx: 1 });
    patterns.push({ re: /^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(/, nameIdx: 1 });
    patterns.push({ re: /^\s*(\w+)\s*:\s*(?:async\s+)?function/, nameIdx: 1 });
  } else if (ext === '.py') {
    patterns.push({ re: /^\s*(?:async\s+)?def\s+(\w+)\s*\(/, nameIdx: 1 });
  } else if (ext === '.go') {
    patterns.push({ re: /^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(/, nameIdx: 1 });
  } else if (ext === '.java') {
    patterns.push({ re: /^\s*(?:public|private|protected|static|\s)*\s*[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*\{/, nameIdx: 1 });
  }

  for (let i = 0; i < lines.length; i++) {
    for (const { re, nameIdx } of patterns) {
      const m = lines[i].match(re);
      if (!m) continue;
      const name = m[nameIdx];
      if (!name) continue;
      const startLine = i;
      let endLine = i;
      if (ext === '.py') {
        const indent = (lines[i].match(/^\s*/) || [''])[0].length;
        for (let j = i + 1; j < lines.length; j++) {
          const trimmed = lines[j].trim();
          if (!trimmed) continue;
          const jIndent = (lines[j].match(/^\s*/) || [''])[0].length;
          if (jIndent <= indent) { endLine = j - 1; break; }
          endLine = j;
        }
      } else {
        let depth = 0;
        let sawOpen = false;
        for (let j = i; j < lines.length; j++) {
          for (const ch of lines[j]) {
            if (ch === '{') { depth++; sawOpen = true; }
            else if (ch === '}') { depth--; }
          }
          if (sawOpen && depth <= 0) { endLine = j; break; }
        }
      }
      const fnBody = lines.slice(startLine, endLine + 1).join('\n');
      const calls = extractCallSites(fnBody);
      nodes.push({ file, line: startLine + 1, name, body: fnBody, calls });
      break;
    }
  }
  return nodes;
}

function extractCallSites(body: string): string[] {
  const keywords = new Set([
    'if', 'for', 'while', 'switch', 'return', 'function', 'await', 'async',
    'new', 'typeof', 'instanceof', 'in', 'of', 'try', 'catch', 'throw',
    'def', 'class', 'lambda', 'import', 'from', 'print', 'else', 'elif',
  ]);
  const calls = new Set<string>();
  const re = /(\b[A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const name = m[1];
    if (!keywords.has(name)) calls.add(name);
  }
  return Array.from(calls);
}

/**
 * Compute a coarse fingerprint of a file set that changes whenever ANY
 * tracked source file is added, removed, or modified. Previously we
 * sampled only the first 20 files' mtimes - that missed edits further
 * into the tree. This hash covers the full set at O(n) file stat cost.
 */
function projectFingerprint(files: string[]): string {
  let count = 0;
  let totalSize = 0;
  let maxMtime = 0;
  for (const f of files) {
    try {
      const st = statSync(f);
      count++;
      totalSize += st.size;
      if (st.mtimeMs > maxMtime) maxMtime = st.mtimeMs;
    } catch {
      /* unreadable - skip */
    }
  }
  return `${count}:${totalSize}:${maxMtime}`;
}

function buildCallGraph(projectPath: string): CallGraphNode[] {
  const files = walkFiles(projectPath);
  const fingerprint = projectFingerprint(files);
  const cached = _graphCache.get(projectPath);
  if (cached && cached.fingerprint === fingerprint) return cached.nodes;
  const all: CallGraphNode[] = [];
  for (const f of files) {
    const body = safeRead(f);
    if (!body) continue;
    all.push(...parseFunctionsInFile(f, body));
  }
  _graphCache.set(projectPath, { fingerprint, nodes: all });
  return all;
}

function safeRead(p: string): string {
  try { return readFileSync(p, 'utf8'); } catch { return ''; }
}

// ──────────────────────────────────────────────────────────────────────────
//  Walk
// ──────────────────────────────────────────────────────────────────────────

const MAX_HOPS = 10;
const MAX_NODES = 100;

function findEnclosingFn(
  nodes: CallGraphNode[],
  file: string,
  line: number
): CallGraphNode | undefined {
  const candidates = nodes.filter((n) => path.resolve(n.file) === path.resolve(file));
  let best: CallGraphNode | undefined;
  for (const n of candidates) {
    const bodyLines = n.body.split('\n').length;
    if (line >= n.line && line <= n.line + bodyLines) {
      if (!best || n.line > best.line) best = n;
    }
  }
  return best;
}

function callersOf(nodes: CallGraphNode[], fnName: string): CallGraphNode[] {
  return nodes.filter((n) => n.calls.includes(fnName));
}

function scanBodyForSource(node: CallGraphNode, lang: Lang): TaintStep | null {
  const lines = node.body.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const hit = matchSource(lines[i], lang);
    if (hit) {
      return {
        file: node.file,
        line: node.line + i,
        kind: 'source',
        code: lines[i].trim().slice(0, 200),
        fn: node.name,
        variable: hit.variable,
      };
    }
  }
  return null;
}

// ──────────────────────────────────────────────────────────────────────────
//  Public entry
// ──────────────────────────────────────────────────────────────────────────

export async function analyzeDataflow(
  projectPath: string,
  finding: DataflowFinding
): Promise<DataflowResult> {
  if (!projectPath || !finding?.file) {
    return { tainted: false, confidence: 0, path: [], reason: 'missing_input' };
  }

  const absFile = path.isAbsolute(finding.file)
    ? finding.file
    : path.join(projectPath, finding.file);
  if (!existsSync(absFile)) {
    return { tainted: false, confidence: 0, path: [], reason: 'file_not_found' };
  }

  const lang = langFromExt(path.extname(absFile).toLowerCase());
  if (!lang) {
    return { tainted: false, confidence: 0.1, path: [], reason: 'unsupported_language' };
  }

  const body = safeRead(absFile);
  const lines = body.split('\n');
  const line = finding.line_start ?? 1;
  const sinkLine = lines[line - 1] || '';
  const sinkHit = matchSink(sinkLine, lang);

  const graph = buildCallGraph(projectPath);
  const enclosing = findEnclosingFn(graph, absFile, line);

  const path_: TaintStep[] = [];
  if (sinkHit) {
    path_.push({
      file: absFile,
      line,
      kind: 'sink',
      code: sinkLine.trim().slice(0, 200),
      fn: enclosing?.name,
      variable: sinkHit.arg,
    });
  }

  // 1. Direct source in the same function body
  let sanitized = false;
  if (enclosing) {
    for (const bl of enclosing.body.split('\n')) {
      if (hasSanitizer(bl, lang)) { sanitized = true; break; }
    }
    const sourceStep = scanBodyForSource(enclosing, lang);
    if (sourceStep) {
      path_.unshift(sourceStep);
      return {
        tainted: !sanitized,
        confidence: sanitized ? 0.3 : 0.9,
        path: path_,
        reason: sanitized ? 'sanitizer_possibly_bypassable' : 'direct_flow',
      };
    }
  }

  // 2. Transitive search: walk caller chain, look for source
  if (enclosing) {
    const visited = new Set<string>([enclosing.name]);
    const queue: Array<{ node: CallGraphNode; depth: number; trail: TaintStep[] }> = [
      { node: enclosing, depth: 0, trail: [...path_] },
    ];
    let nodesVisited = 0;
    while (queue.length > 0 && nodesVisited < MAX_NODES) {
      const { node, depth, trail } = queue.shift()!;
      nodesVisited++;
      if (depth >= MAX_HOPS) continue;
      const callers = callersOf(graph, node.name);
      for (const caller of callers) {
        if (visited.has(caller.name)) continue;
        visited.add(caller.name);
        const callerLang = langFromExt(path.extname(caller.file).toLowerCase()) || lang;
        const src = scanBodyForSource(caller, callerLang);
        const step: TaintStep = {
          file: caller.file,
          line: caller.line,
          fn: caller.name,
          kind: 'propagator',
          code: `calls ${node.name}(...)`,
        };
        const newTrail = [step, ...trail];
        if (src) {
          return {
            tainted: true,
            confidence: Math.max(0.4, 0.9 - depth * 0.1),
            path: [src, ...newTrail],
            reason: `multi_hop_${depth + 1}`,
          };
        }
        queue.push({ node: caller, depth: depth + 1, trail: newTrail });
      }
    }
  }

  return {
    tainted: false,
    confidence: 0.1,
    path: path_,
    reason: 'no_source_found',
  };
}

// For tests
export const _internals = { parseFunctionsInFile, extractCallSites, buildCallGraph, walkFiles };

import { readFileSync, readdirSync, existsSync } from 'fs';
import path from 'path';
import type { ScanFinding } from '../db.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface CallGraphEdge {
  caller_file: string;
  callee_module: string;
  callee_function: string;
  line: number;
}

export interface ReachabilityResult {
  dep_name: string;
  reachable: boolean;
  call_sites: string[];
  confidence: 'definite' | 'possible' | 'unreachable';
}

// ── Constants ──────────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', '__pycache__', 'target',
  'build', 'dist', 'test', 'tests',
]);

// ── Import/Include Extraction ──────────────────────────────────────────────

/** Patterns for extracting imports/includes by language */
const IMPORT_PATTERNS: Array<{
  extensions: string[];
  patterns: RegExp[];
  extractModule: (match: RegExpMatchArray) => string;
}> = [
  {
    // C/C++: #include <dep/header.h> or #include "dep/header.h"
    extensions: ['.c', '.h', '.cpp', '.cc', '.hpp'],
    patterns: [/^\s*#include\s*[<"]([^>"]+)[>"]/],
    extractModule: (m) => {
      const parts = m[1].split('/');
      return parts[0]; // Top-level directory = module name
    },
  },
  {
    // Python: import X, from X import Y
    extensions: ['.py'],
    patterns: [
      /^\s*import\s+([\w.]+)/,
      /^\s*from\s+([\w.]+)\s+import/,
    ],
    extractModule: (m) => m[1].split('.')[0],
  },
  {
    // JavaScript/TypeScript: import X from 'Y', require('Y')
    extensions: ['.js', '.ts', '.jsx', '.tsx', '.mjs'],
    patterns: [
      /\bimport\s+.*?from\s+['"]([^'"]+)['"]/,
      /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/,
    ],
    extractModule: (m) => {
      const mod = m[1];
      if (mod.startsWith('.') || mod.startsWith('/')) return ''; // Local import
      // Scoped package: @org/pkg → @org/pkg
      if (mod.startsWith('@')) return mod.split('/').slice(0, 2).join('/');
      return mod.split('/')[0];
    },
  },
  {
    // Go: import "github.com/org/pkg"
    extensions: ['.go'],
    patterns: [/\bimport\s*(?:\(\s*)?["']([^"']+)["']/],
    extractModule: (m) => {
      const parts = m[1].split('/');
      return parts.length >= 3 ? parts.slice(0, 3).join('/') : m[1];
    },
  },
  {
    // Java: import com.org.pkg.Class
    extensions: ['.java', '.kt', '.scala'],
    patterns: [/^\s*import\s+([\w.]+)/],
    extractModule: (m) => {
      const parts = m[1].split('.');
      return parts.length >= 2 ? `${parts[0]}.${parts[1]}` : parts[0];
    },
  },
  {
    // Ruby: require 'gem'
    extensions: ['.rb'],
    patterns: [/\brequire\s+['"]([^'"]+)['"]/],
    extractModule: (m) => m[1].split('/')[0],
  },
];

// ── Call Graph Builder ─────────────────────────────────────────────────────

/**
 * Build a simplified call graph showing which external modules are imported
 * and what functions from them are called.
 */
export function buildCallGraph(projectPath: string): CallGraphEdge[] {
  const edges: CallGraphEdge[] = [];

  function scanDir(dir: string, depth: number): void {
    if (depth > 5) return;
    let entries: import('fs').Dirent[];
    try { entries = readdirSync(dir, { withFileTypes: true, encoding: 'utf8' }); } catch { return; }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        scanDir(full, depth + 1);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        scanFileImports(full, ext, projectPath, edges);
      }
    }
  }

  scanDir(projectPath, 0);
  return edges;
}

function scanFileImports(
  filePath: string,
  ext: string,
  projectPath: string,
  edges: CallGraphEdge[],
): void {
  const matcher = IMPORT_PATTERNS.find(p => p.extensions.includes(ext));
  if (!matcher) return;

  let content: string;
  try { content = readFileSync(filePath, 'utf-8'); } catch { return; }

  const relPath = path.relative(projectPath, filePath);
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    for (const pattern of matcher.patterns) {
      const match = lines[i].match(pattern);
      if (match) {
        const module = matcher.extractModule(match);
        if (module) {
          edges.push({
            caller_file: relPath,
            callee_module: module,
            callee_function: '', // Would need AST for precise function tracking
            line: i + 1,
          });
        }
      }
    }
  }
}

// ── Reachability Checker ───────────────────────────────────────────────────

/**
 * Check if a vulnerable dependency is actually imported/used by the project.
 */
export function checkDepReachability(
  projectPath: string,
  depName: string,
): ReachabilityResult {
  const callGraph = buildCallGraph(projectPath);
  const depLower = depName.toLowerCase();

  const callSites = callGraph.filter(edge => {
    const modLower = edge.callee_module.toLowerCase();
    return modLower === depLower ||
      modLower.includes(depLower) ||
      depLower.includes(modLower);
  });

  if (callSites.length === 0) {
    return {
      dep_name: depName,
      reachable: false,
      call_sites: [],
      confidence: 'unreachable',
    };
  }

  return {
    dep_name: depName,
    reachable: true,
    call_sites: callSites.map(cs => `${cs.caller_file}:${cs.line} imports ${cs.callee_module}`),
    confidence: callSites.length >= 3 ? 'definite' : 'possible',
  };
}

/**
 * Filter dependency-related findings by reachability.
 * Findings for unreachable deps get marked as auto_rejected.
 */
export function filterUnreachableDeps(
  findings: ScanFinding[],
  projectPath: string,
): { kept: ScanFinding[]; rejected: Array<{ finding: ScanFinding; reason: string }> } {
  const kept: ScanFinding[] = [];
  const rejected: Array<{ finding: ScanFinding; reason: string }> = [];
  const cache = new Map<string, ReachabilityResult>();

  for (const f of findings) {
    // Identify dependency-related findings by tool name or heuristics
    const isDepFinding = isDependencyFinding(f);
    if (!isDepFinding) {
      kept.push(f);
      continue;
    }

    const depName = extractDepName(f);
    if (!depName) {
      kept.push(f); // Can't determine dep name, keep conservatively
      continue;
    }

    // Check reachability (cached)
    if (!cache.has(depName)) {
      cache.set(depName, checkDepReachability(projectPath, depName));
    }
    const reachability = cache.get(depName)!;

    if (reachability.reachable) {
      kept.push(f);
    } else {
      rejected.push({
        finding: f,
        reason: `Dependency "${depName}" is not imported/used by the project (${reachability.confidence})`,
      });
    }
  }

  return { kept, rejected };
}

// ── Helpers ────────────────────────────────────────────────────────────────

function isDependencyFinding(f: ScanFinding): boolean {
  const tool = (f.tool_name || '').toLowerCase();
  if (['trivy', 'grype', 'osv-scanner', 'safety', 'npm audit', 'dependency_tree_auditor'].includes(tool)) return true;

  const title = (f.title || '').toLowerCase();
  if (title.includes('dependency') || title.includes('package') || title.includes('library')) return true;
  if (title.includes('cve-') && !f.file) return true; // CVE with no file = likely dep vuln

  return false;
}

function extractDepName(f: ScanFinding): string | null {
  // Try to extract from title: "CVE-2024-XXXX in package-name@1.2.3"
  const titleMatch = (f.title || '').match(/\bin\s+([\w\-@/.]+?)(?:@|\s|$)/i);
  if (titleMatch) return titleMatch[1];

  // Try from description
  const descMatch = (f.description || '').match(/package[:\s]+([\w\-@/.]+)/i);
  if (descMatch) return descMatch[1];

  // Try the tool_name if it's specific
  if (f.tool_name === 'trivy' || f.tool_name === 'grype') {
    const fileMatch = (f.file || '').match(/([\w\-]+)\.(lock|json|txt|toml)/);
    if (fileMatch) return null; // Can't determine specific dep from lock file
  }

  return null;
}

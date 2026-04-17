/**
 * Shared helpers for the web detector family: file walking, framework
 * detection, evidence trimming.
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'fs';
import path from 'path';

// ── Walking ───────────────────────────────────────────────────────────────

const DEFAULT_SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', '__pycache__', 'target', 'build',
  'dist', 'dist-server', 'out', '.next', '.venv', 'venv', 'env',
  'coverage', '.nuxt', '.cache', '.svelte-kit', 'bower_components',
]);

export interface WalkOptions {
  /** Max recursion depth. Defaults to 8 (enough for most repos). */
  maxDepth?: number;
  /** Max bytes we'll read for any single file. */
  maxFileBytes?: number;
  /** Additional dirs to skip by name. */
  skipDirs?: Iterable<string>;
}

/**
 * Walk a project directory and yield absolute file paths whose basename
 * or path matches `match` (regexp tested against the relative path). Binary
 * and overly large files are skipped.
 */
export function walkFiles(
  projectPath: string,
  match: RegExp,
  opts: WalkOptions = {},
): string[] {
  const maxDepth = opts.maxDepth ?? 8;
  const maxBytes = opts.maxFileBytes ?? 2_000_000; // 2 MB
  const skip = new Set([...DEFAULT_SKIP_DIRS, ...(opts.skipDirs ?? [])]);
  const out: string[] = [];

  function rec(dir: string, depth: number) {
    if (depth > maxDepth) return;
    let entries: import('fs').Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (skip.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        rec(full, depth + 1);
      } else if (e.isFile()) {
        const rel = path.relative(projectPath, full).replace(/\\/g, '/');
        if (!match.test(rel) && !match.test(e.name)) continue;
        try {
          const st = statSync(full);
          if (st.size > maxBytes) continue;
        } catch {
          continue;
        }
        out.push(full);
      }
    }
  }

  rec(projectPath, 0);
  return out;
}

/**
 * Read a file as UTF-8, returning null on failure.
 */
export function readText(file: string): string | null {
  try {
    return readFileSync(file, 'utf-8');
  } catch {
    return null;
  }
}

/**
 * Convert an absolute path to a forward-slash path relative to the project.
 */
export function relPath(projectPath: string, file: string): string {
  return path.relative(projectPath, file).replace(/\\/g, '/');
}

/**
 * Trim an evidence line to a single, short, safe snippet.
 */
export function trimEvidence(s: string, max = 160): string {
  const collapsed = s.replace(/\s+/g, ' ').trim();
  if (collapsed.length <= max) return collapsed;
  return collapsed.slice(0, max - 1) + '…';
}

/**
 * Locate the 1-based line number for the start of a given string/regex in
 * content. Returns `undefined` if no match.
 */
export function findLine(content: string, needle: string | RegExp): number | undefined {
  const lines = content.split(/\r?\n/);
  if (typeof needle === 'string') {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(needle)) return i + 1;
    }
    return undefined;
  }
  const flags = needle.flags.includes('g') ? needle.flags : needle.flags + 'g';
  const re = new RegExp(needle.source, flags);
  for (let i = 0; i < lines.length; i++) {
    re.lastIndex = 0;
    if (re.test(lines[i])) return i + 1;
  }
  return undefined;
}

// ── Framework detection ───────────────────────────────────────────────────

export type Framework =
  | 'express' | 'koa' | 'fastify' | 'nestjs' | 'hapi'
  | 'flask' | 'django' | 'fastapi' | 'tornado'
  | 'rails' | 'sinatra'
  | 'gin' | 'echo' | 'chi' | 'fiber'
  | 'aspnet'
  | 'spring' | 'springboot'
  | 'laravel' | 'symfony';

/**
 * Detect web frameworks referenced by a project's manifest files. Best-effort
 * — returns whatever signals are visible without walking source code.
 *
 * Results are returned in a stable order (insertion order of detection).
 */
export function detectFrameworks(projectPath: string): Framework[] {
  const found = new Set<Framework>();

  // package.json — Node ecosystem
  const pkgFile = path.join(projectPath, 'package.json');
  if (existsSync(pkgFile)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgFile, 'utf-8'));
      const deps = {
        ...(pkg.dependencies ?? {}),
        ...(pkg.devDependencies ?? {}),
        ...(pkg.peerDependencies ?? {}),
      };
      if ('express' in deps) found.add('express');
      if ('koa' in deps) found.add('koa');
      if ('fastify' in deps) found.add('fastify');
      if ('@nestjs/core' in deps || '@nestjs/common' in deps) found.add('nestjs');
      if ('@hapi/hapi' in deps || 'hapi' in deps) found.add('hapi');
    } catch {
      /* ignore malformed */
    }
  }

  // Python: requirements.txt / pyproject.toml / Pipfile
  const reqFiles = [
    'requirements.txt',
    'requirements-dev.txt',
    'pyproject.toml',
    'Pipfile',
    'setup.py',
  ];
  for (const name of reqFiles) {
    const p = path.join(projectPath, name);
    if (!existsSync(p)) continue;
    const body = readText(p) ?? '';
    if (/\bflask\b/i.test(body)) found.add('flask');
    if (/\bdjango\b/i.test(body)) found.add('django');
    if (/\bfastapi\b/i.test(body)) found.add('fastapi');
    if (/\btornado\b/i.test(body)) found.add('tornado');
  }

  // Ruby: Gemfile
  const gemfile = path.join(projectPath, 'Gemfile');
  if (existsSync(gemfile)) {
    const body = readText(gemfile) ?? '';
    if (/\brails\b/i.test(body)) found.add('rails');
    if (/\bsinatra\b/i.test(body)) found.add('sinatra');
  }

  // Go: go.mod
  const goMod = path.join(projectPath, 'go.mod');
  if (existsSync(goMod)) {
    const body = readText(goMod) ?? '';
    if (/gin-gonic\/gin/.test(body)) found.add('gin');
    if (/labstack\/echo/.test(body)) found.add('echo');
    if (/go-chi\/chi/.test(body)) found.add('chi');
    if (/gofiber\/fiber/.test(body)) found.add('fiber');
  }

  // .NET / ASP.NET Core: *.csproj
  const csproj = walkFiles(projectPath, /\.csproj$/i, { maxDepth: 3 });
  for (const f of csproj) {
    const body = readText(f) ?? '';
    if (/Microsoft\.AspNetCore/i.test(body)) {
      found.add('aspnet');
      break;
    }
  }

  // Java: pom.xml / build.gradle
  const pom = path.join(projectPath, 'pom.xml');
  if (existsSync(pom)) {
    const body = readText(pom) ?? '';
    if (/spring-boot/i.test(body)) found.add('springboot');
    else if (/springframework/i.test(body)) found.add('spring');
  }
  const gradle = path.join(projectPath, 'build.gradle');
  if (existsSync(gradle)) {
    const body = readText(gradle) ?? '';
    if (/spring-boot/i.test(body)) found.add('springboot');
    else if (/springframework/i.test(body)) found.add('spring');
  }

  // PHP: composer.json
  const composer = path.join(projectPath, 'composer.json');
  if (existsSync(composer)) {
    try {
      const pkg = JSON.parse(readFileSync(composer, 'utf-8'));
      const deps = { ...(pkg.require ?? {}), ...(pkg['require-dev'] ?? {}) };
      if ('laravel/framework' in deps || 'laravel/laravel' in deps) found.add('laravel');
      if (Object.keys(deps).some(k => k.startsWith('symfony/'))) found.add('symfony');
    } catch {
      /* ignore */
    }
  }

  return Array.from(found);
}

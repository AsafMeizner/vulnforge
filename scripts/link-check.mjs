#!/usr/bin/env node
/**
 * link-check - walk every committed .md file and verify that each
 * relative markdown link points at a file (or anchor-bearing file)
 * that actually exists.
 *
 * Catches the specific kind of doc rot that the `superpowers/specs/`
 * purge had to clean up: pages that reference a path which has since
 * been removed. Runs in CI on every PR so the regression can't sneak
 * back in.
 *
 * Out of scope:
 *  - External http(s) links (needs network, flaky in CI).
 *  - Anchor validation inside the target file (a follow-up pass could
 *    grep for heading slugs, but "the file exists" catches 95% of
 *    breakage).
 *  - Mail / tel / javascript links.
 *
 * Exit codes: 0 = all links resolvable, 1 = at least one dead link.
 */
import { readFileSync, statSync } from 'fs';
import { spawnSync } from 'child_process';
import path from 'path';

const ROOT = process.cwd();

/**
 * Return all .md files currently tracked by git. Using `git ls-files`
 * instead of a filesystem walk means we skip everything under
 * .gitignored dirs (node_modules, release*, todo/, .playwright-mcp/,
 * release10/, etc.) without having to maintain a manual blocklist.
 */
function trackedMarkdownFiles() {
  const r = spawnSync('git', ['ls-files', '*.md', '**/*.md'], {
    shell: false,
    encoding: 'utf8',
  });
  if (r.status !== 0) {
    console.error('[link-check] failed to list git-tracked files');
    process.exit(2);
  }
  return r.stdout.split('\n').filter(Boolean);
}

/** Extract [text](target) links via String.matchAll. */
function extractLinks(body) {
  // Markdown inline link: [label](target "optional title")
  const re = /\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g;
  const out = [];
  for (const m of body.matchAll(re)) {
    out.push(m[1]);
  }
  return out;
}

function isExternal(target) {
  return /^(https?:|mailto:|tel:|javascript:|#)/i.test(target);
}

function cleanTarget(target) {
  // Strip GitHub image-fragment suffix (#gh-dark-mode-only etc) and
  // plain anchor fragments - we only care about file existence.
  return target.split('#')[0].split('?')[0];
}

const errors = [];
let checked = 0;
let fileCount = 0;

for (const file of trackedMarkdownFiles()) {
  fileCount++;
  const body = readFileSync(file, 'utf8');
  const links = extractLinks(body);

  for (const raw of links) {
    if (isExternal(raw)) continue;
    const cleaned = cleanTarget(raw);
    if (!cleaned) continue; // pure anchor (#foo)

    // Resolve relative to the file that contains the link.
    const base = path.dirname(path.resolve(ROOT, file));
    const resolved = path.resolve(base, cleaned);
    checked++;

    try {
      statSync(resolved);
    } catch {
      errors.push({ file, target: raw, resolved: path.relative(ROOT, resolved) });
    }
  }
}

console.log(`[link-check] scanned ${fileCount} markdown files, checked ${checked} internal links`);

if (errors.length > 0) {
  console.error(`[link-check] \u274c  ${errors.length} dead internal link(s):`);
  for (const e of errors) {
    console.error(`  - ${e.file}  ->  ${e.target}`);
  }
  process.exit(1);
}

console.log('[link-check] \u2713  no dead internal links');

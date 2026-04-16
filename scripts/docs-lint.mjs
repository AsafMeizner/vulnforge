#!/usr/bin/env node
/**
 * docs-lint — enforce that changes to load-bearing server dirs come with
 * corresponding doc updates.
 *
 * Runs against the set of paths changed since origin/main (or an explicit
 * base ref via BASE_REF env var). Fails with non-zero exit if a change in
 * a watched area isn't accompanied by any docs/ edit, unless `[skip-docs]`
 * appears in the commit range's commit messages.
 *
 * Usage:
 *   node scripts/docs-lint.mjs                     # compare HEAD to origin/main
 *   BASE_REF=main node scripts/docs-lint.mjs       # custom base
 *   node scripts/docs-lint.mjs --staged            # only staged files
 */
import { spawnSync } from 'child_process';

const WATCHED = [
  'server/sync/',
  'server/auth/',
  'server/integrations/',
  'server/workers/',
  'server/deployment/',
  'electron/',
  'Dockerfile.server',
  'scripts/install-server',
];

function run(cmd, args) {
  const r = spawnSync(cmd, args, { shell: false, encoding: 'utf8' });
  if (r.status !== 0) return '';
  return r.stdout ?? '';
}

function changedFiles() {
  if (process.argv.includes('--staged')) {
    return run('git', ['diff', '--name-only', '--cached']).split('\n').filter(Boolean);
  }
  const base = process.env.BASE_REF || 'origin/main';
  // Fall back to HEAD~1 if the base ref isn't available (e.g. first push).
  const resolveBase = run('git', ['merge-base', base, 'HEAD']).trim();
  const ref = resolveBase || 'HEAD~1';
  return run('git', ['diff', '--name-only', ref, 'HEAD']).split('\n').filter(Boolean);
}

function commitMessagesSinceBase() {
  const base = process.env.BASE_REF || 'origin/main';
  const resolveBase = run('git', ['merge-base', base, 'HEAD']).trim();
  const ref = resolveBase || 'HEAD~1';
  return run('git', ['log', `${ref}..HEAD`, '--pretty=%B']);
}

const changed = changedFiles();
if (changed.length === 0) {
  console.log('[docs-lint] no changed files');
  process.exit(0);
}

const watchedTouched = changed.filter(f => WATCHED.some(w => f.startsWith(w)));
const docsTouched = changed.some(f => f.startsWith('docs/') || f === 'README.md');

if (watchedTouched.length === 0) {
  console.log('[docs-lint] no watched paths changed — skip');
  process.exit(0);
}

if (docsTouched) {
  console.log(`[docs-lint] ok — ${watchedTouched.length} watched file(s) changed; docs were updated`);
  process.exit(0);
}

const messages = commitMessagesSinceBase();
if (/\[skip-docs\]/i.test(messages)) {
  console.log('[docs-lint] ok — [skip-docs] marker present in commit range');
  process.exit(0);
}

console.error('[docs-lint] ❌  changes in watched paths without docs/ updates:');
for (const f of watchedTouched) console.error(`  - ${f}`);
console.error('');
console.error('Either:');
console.error('  1. Update the relevant doc page under docs/ to reflect your change.');
console.error('  2. Add [skip-docs] to a commit message if this is genuinely doc-less.');
process.exit(1);

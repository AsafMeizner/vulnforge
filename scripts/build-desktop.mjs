#!/usr/bin/env node
/**
 * Build the desktop installer via electron-builder.
 *
 * Targets:
 *   node scripts/build-desktop.mjs                 # current platform
 *   node scripts/build-desktop.mjs --win --mac --linux
 *   node scripts/build-desktop.mjs --publish       # publish via configured provider
 */
import { spawnSync } from 'child_process';

function run(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', shell: false });
  if (r.status !== 0) {
    console.error(`[build] failed: ${cmd} ${args.join(' ')}`);
    process.exit(r.status ?? 1);
  }
}

// Compile frontend first.
console.log('[build] vite build (frontend)…');
run('npx', ['vite', 'build']);

// electron-builder flags.
const args = ['electron-builder'];
if (process.argv.includes('--win'))     args.push('--win');
if (process.argv.includes('--mac'))     args.push('--mac');
if (process.argv.includes('--linux'))   args.push('--linux');
if (process.argv.includes('--publish')) args.push('--publish', 'always');

console.log(`[build] electron-builder ${args.slice(1).join(' ')}`);
run('npx', args);

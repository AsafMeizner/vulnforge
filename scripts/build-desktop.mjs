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

// On Windows, spawnSync with shell:false and cmd="npx" fails because npx
// resolves to npx.cmd (a shell wrapper). shell:true lets Windows look up
// .cmd/.bat files; on POSIX we keep shell:false for predictable argv
// handling and a smaller shell-injection surface.
const IS_WIN = process.platform === 'win32';

function run(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', shell: IS_WIN });
  if (r.status !== 0) {
    console.error(`[build] failed: ${cmd} ${args.join(' ')}`);
    process.exit(r.status ?? 1);
  }
}

// Compile frontend, server, and electron main/preload before packaging.
// Order matters - electron-builder asserts against compiled outputs in
// dist/, dist-server/, and electron/*.js.
console.log('[build] vite build (frontend)…');
run('npx', ['vite', 'build']);

console.log('[build] tsc server (dist-server/)…');
run('npx', ['tsc', '-p', 'tsconfig.server.json']);

console.log('[build] tsc electron main (ESM)…');
run('npx', ['tsc', '-p', 'tsconfig.electron.json']);

// preload.ts MUST compile to CommonJS. Electron's preload sandbox
// context rejects ESM `import` statements with
// "Cannot use import statement outside a module", and that breaks
// every IPC bridge the renderer needs. The dedicated tsconfig emits
// CJS with `require("electron")`.
console.log('[build] tsc electron preload (CJS)…');
run('npx', ['tsc', '-p', 'tsconfig.electron-preload.json']);

// electron-builder flags.
const args = ['electron-builder'];
if (process.argv.includes('--win'))     args.push('--win');
if (process.argv.includes('--mac'))     args.push('--mac');
if (process.argv.includes('--linux'))   args.push('--linux');
if (process.argv.includes('--publish')) args.push('--publish', 'always');

console.log(`[build] electron-builder ${args.slice(1).join(' ')}`);
run('npx', args);

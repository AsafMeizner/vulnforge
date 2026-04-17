#!/usr/bin/env node
/**
 * End-to-end release automation.
 *
 * Runs the full test suite, then builds every shipping artifact and
 * gathers them under `release-artifacts/<version>/` so a maintainer has
 * one folder to upload to GitHub Releases.
 *
 * Usage:
 *   npm run release                    # current platform + all server artifacts
 *   npm run release -- --platform=win  # only Windows installer
 *   npm run release -- --platform=all  # try win + linux on this host
 *                                      # (mac DMG can only be produced on macOS)
 *   npm run release -- --skip-tests    # dangerous; only for re-packaging
 *
 * The default is strict: test failure aborts the whole pipeline. No
 * artifact is produced unless every test passed.
 *
 * Artifacts produced:
 *   VulnForge Setup <ver>.exe        Windows NSIS installer (+ block-map, latest.yml)
 *   VulnForge-<ver>.AppImage         Linux AppImage (when --platform=linux|all)
 *   VulnForge-<ver>.dmg              macOS DMG (macOS-only host)
 *   vulnforge-server-<ver>.tar.gz    Bare-metal server tarball (all hosts)
 *   vulnforge-server-<ver>.docker    Server Docker image tar (requires docker)
 *   SHA256SUMS                       Hashes for every artifact above
 */

import { spawnSync } from 'child_process';
import {
  mkdirSync, rmSync, cpSync, readFileSync, writeFileSync, readdirSync, existsSync, statSync,
} from 'fs';
import { join, basename } from 'path';
import { createHash } from 'crypto';

const IS_WIN = process.platform === 'win32';

// ── CLI -----------------------------------------------------------------
const args = process.argv.slice(2);
const flag = (name, def = false) => {
  const match = args.find((a) => a === `--${name}` || a.startsWith(`--${name}=`));
  if (!match) return def;
  const eq = match.indexOf('=');
  return eq === -1 ? true : match.slice(eq + 1);
};
const skipTests = flag('skip-tests');
const platformArg = flag('platform', process.platform === 'darwin' ? 'mac' : process.platform === 'linux' ? 'linux' : 'win');
const doDocker = flag('docker', false);
// --- helpers -----------------------------------------------------------

function log(msg) {
  console.log(`\x1b[36m[release]\x1b[0m ${msg}`);
}

function fail(msg, code = 1) {
  console.error(`\x1b[31m[release:fail]\x1b[0m ${msg}`);
  process.exit(code);
}

function run(cmd, cmdArgs, opts = {}) {
  // Windows uses .cmd wrappers for npm/npx/tsc; shell:true so lookup works.
  // POSIX uses shell:false for a smaller injection surface.
  const r = spawnSync(cmd, cmdArgs, {
    stdio: 'inherit',
    shell: IS_WIN,
    ...opts,
  });
  if (r.status !== 0) {
    fail(`command failed (${r.status}): ${cmd} ${cmdArgs.join(' ')}`);
  }
}

function sha256(file) {
  const h = createHash('sha256');
  h.update(readFileSync(file));
  return h.digest('hex');
}

function copyIfExists(src, destDir) {
  if (!existsSync(src)) return null;
  const name = basename(src);
  const dest = join(destDir, name);
  cpSync(src, dest, { recursive: statSync(src).isDirectory() });
  return { name, dest, size: statSync(dest).size };
}

// ── Body -----------------------------------------------------------------

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const version = pkg.version || '0.0.0';
const outDir = join('release-artifacts', version);

log(`VulnForge release pipeline for v${version}`);
log(`platform flag: ${platformArg} | skip-tests: ${skipTests} | docker: ${doDocker}`);

// 1. Tests ---------------------------------------------------------------
if (skipTests) {
  log('SKIP tests (--skip-tests)');
} else {
  log('Running full test suite...');
  run('npm', ['test']);
  log('Tests passed.');
}

// 2. Clean output --------------------------------------------------------
log(`Preparing ${outDir}/`);
try { rmSync(outDir, { recursive: true, force: true }); } catch { /* ignore */ }
mkdirSync(outDir, { recursive: true });

// 3. Frontend + server + electron builds --------------------------------
log('Compiling frontend (vite build)...');
run('npx', ['vite', 'build']);
log('Compiling server (tsc)...');
run('npx', ['tsc', '-p', 'tsconfig.server.json']);
log('Compiling electron main + preload (tsc)...');
run('npx', ['tsc', '-p', 'tsconfig.electron.json']);

// 4. Electron installers -------------------------------------------------
const builderOut = 'release-artifacts/.electron-builder';
try { rmSync(builderOut, { recursive: true, force: true }); } catch { /* ignore */ }
mkdirSync(builderOut, { recursive: true });

const wantWin = platformArg === 'win' || platformArg === 'all';
const wantLinux = platformArg === 'linux' || platformArg === 'all';
const wantMac = platformArg === 'mac' || platformArg === 'all';

const electronFlags = [];
if (wantWin) electronFlags.push('--win');
if (wantLinux) electronFlags.push('--linux');
if (wantMac) {
  if (process.platform === 'darwin') electronFlags.push('--mac');
  else log('SKIP --mac: DMG can only be produced on a macOS host');
}

if (electronFlags.length > 0) {
  log(`electron-builder ${electronFlags.join(' ')}...`);
  run('npx', [
    'electron-builder',
    ...electronFlags,
    `--config.directories.output=${builderOut}`,
  ]);
} else {
  log('No desktop target selected - skipping electron-builder');
}

// 5. Server tarball ------------------------------------------------------
log('Building server tarball...');
run('node', ['scripts/build-server-tar.mjs']);

// 6. Docker image (optional) --------------------------------------------
if (doDocker) {
  log('Building server Docker image...');
  try {
    run('node', ['scripts/build-server-docker.mjs']);
  } catch {
    log('Docker build failed or docker not available - continuing');
  }
} else {
  log('Docker image SKIPPED (pass --docker to include)');
}

// 7. Collect artifacts ---------------------------------------------------
log('Collecting artifacts into release-artifacts/...');
const collected = [];
const electronOutputs = existsSync(builderOut) ? readdirSync(builderOut) : [];
for (const f of electronOutputs) {
  // Skip unpacked directories + block-map noise; we want the shippable files.
  const full = join(builderOut, f);
  const st = statSync(full);
  if (st.isDirectory()) continue;
  // Keep installers + block-maps (auto-updater needs them) + latest*.yml
  if (/\.(exe|AppImage|deb|rpm|dmg|zip|blockmap)$/i.test(f) || /^latest.*\.ya?ml$/i.test(f)) {
    const got = copyIfExists(full, outDir);
    if (got) collected.push(got);
  }
}

// Server tarball lands next to package.json by the existing script.
const tarCandidates = readdirSync('.').filter((f) => /^vulnforge-server-.*\.tar\.gz$/.test(f));
for (const f of tarCandidates) {
  const got = copyIfExists(f, outDir);
  if (got) collected.push(got);
}
// Docker image tar
const dockerTars = readdirSync('.').filter((f) => /^vulnforge-server-.*\.docker$/.test(f) || /^vulnforge-server-.*\.tar$/.test(f));
for (const f of dockerTars) {
  if (f.endsWith('.tar.gz')) continue; // already copied above
  const got = copyIfExists(f, outDir);
  if (got) collected.push(got);
}

if (collected.length === 0) {
  fail('No artifacts were produced; something went wrong upstream.');
}

// 8. Hashes --------------------------------------------------------------
log('Computing SHA256SUMS...');
const sums = collected
  .map((a) => `${sha256(a.dest)}  ${a.name}`)
  .join('\n') + '\n';
writeFileSync(join(outDir, 'SHA256SUMS'), sums);

// 9. Report --------------------------------------------------------------
const padRight = (s, n) => s + ' '.repeat(Math.max(0, n - s.length));
const humanSize = (b) => {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
};

log('');
log('Release ready:');
log(`  folder: ${outDir}`);
for (const a of collected) {
  log(`  - ${padRight(a.name, 40)} ${humanSize(a.size)}`);
}
log(`  - SHA256SUMS                             (hashes)`);
log('');
log('Done.');

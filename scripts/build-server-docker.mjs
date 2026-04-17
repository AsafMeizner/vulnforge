#!/usr/bin/env node
/**
 * Build the server Docker image. Multi-arch when buildx is available.
 *
 * Usage:
 *   node scripts/build-server-docker.mjs           # local image, current arch
 *   node scripts/build-server-docker.mjs --push    # multi-arch + push
 */
import { spawnSync } from 'child_process';
import { readFileSync, existsSync } from 'fs';

// Windows resolves npx/docker to .cmd wrappers; need shell:true there.
// POSIX keeps shell:false for predictable argv + smaller attack surface.
const IS_WIN = process.platform === 'win32';
function run(cmd, args) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', shell: IS_WIN });
  if (r.status !== 0) {
    console.error(`[build] failed: ${cmd} ${args.join(' ')}`);
    process.exit(r.status ?? 1);
  }
}

if (!existsSync('Dockerfile.server')) {
  console.error('[build] Dockerfile.server not found. Run from repo root.');
  process.exit(1);
}

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const version = pkg.version ?? '0.0.0';
const push = process.argv.includes('--push');
const image = 'vulnforge/server';

const tagArgs = [
  '-t', `${image}:${version}`,
  '-t', `${image}:latest`,
];

if (push) {
  console.log(`[build] buildx multi-arch push for ${image}:${version}`);
  run('docker', [
    'buildx', 'build',
    '-f', 'Dockerfile.server',
    '--platform', 'linux/amd64,linux/arm64',
    ...tagArgs,
    '--push',
    '.',
  ]);
} else {
  console.log(`[build] local build for ${image}:${version}`);
  run('docker', ['build', '-f', 'Dockerfile.server', ...tagArgs, '.']);
  console.log(`[build] done. Run with:`);
  console.log(`  docker run -d -p 3001:3001 -v vulnforge-data:/data \\`);
  console.log(`    -e VULNFORGE_JWT_SECRET=$(openssl rand -base64 48) \\`);
  console.log(`    ${image}:${version}`);
}

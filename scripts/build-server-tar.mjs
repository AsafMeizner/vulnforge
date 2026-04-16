#!/usr/bin/env node
/**
 * Build the bare-metal server tarball.
 *
 * Produces: vulnforge-server-<version>.tar.gz containing
 *   dist-server/      compiled server JS
 *   plugins/          plugin manifests (scanners still need their tools
 *                     installed separately by the admin)
 *   package.json      prod deps only
 *   scripts/          install + bootstrap + migrate scripts
 *   README-server.md  quickstart
 *   systemd/          optional unit file
 *
 * All child processes use spawnSync with an argv array — no shell,
 * no injection surface. Inputs here are all constants from this file
 * and the top-level package.json, but belt-and-braces anyway.
 */
import { spawnSync } from 'child_process';
import { mkdirSync, copyFileSync, rmSync, cpSync, readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', shell: false, ...opts });
  if (r.status !== 0) {
    console.error(`[build] command failed (${r.status}): ${cmd} ${args.join(' ')}`);
    process.exit(r.status ?? 1);
  }
}

const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
const version = pkg.version ?? '0.0.0';
const stageDir = 'dist-tarball-stage';
const finalName = `vulnforge-server-${version}.tar.gz`;

console.log(`[build] staging → ${stageDir}`);
if (existsSync(stageDir)) rmSync(stageDir, { recursive: true, force: true });
mkdirSync(stageDir, { recursive: true });

// 1. tsc server code → dist-server/
console.log('[build] compiling TS…');
const tsConfigPath = 'tsconfig.server.json';
if (existsSync(tsConfigPath)) {
  run('npx', ['tsc', '--project', tsConfigPath]);
} else {
  run('npx', [
    'tsc', '--outDir', 'dist-server',
    '--module', 'esnext', '--target', 'es2022',
    '--moduleResolution', 'bundler', 'server/index.ts',
  ]);
}

// 2. Stage prod-only package.json
const prodPkg = {
  name: pkg.name,
  version: pkg.version,
  type: pkg.type,
  main: 'dist-server/server/index.js',
  scripts: {
    start: 'node dist-server/server/index.js',
    migrate: 'node scripts/migrate.mjs',
    bootstrap: 'node scripts/bootstrap.mjs',
  },
  dependencies: pkg.dependencies,
};
writeFileSync(join(stageDir, 'package.json'), JSON.stringify(prodPkg, null, 2));

// 3. Copy artifacts
cpSync('dist-server', join(stageDir, 'dist-server'), { recursive: true });
if (existsSync('plugins')) cpSync('plugins', join(stageDir, 'plugins'), { recursive: true });
mkdirSync(join(stageDir, 'scripts'), { recursive: true });
for (const f of ['install-server.sh', 'install-server.ps1', 'bootstrap.mjs', 'migrate.mjs']) {
  const src = join('scripts', f);
  if (existsSync(src)) copyFileSync(src, join(stageDir, 'scripts', f));
}
if (existsSync('systemd')) cpSync('systemd', join(stageDir, 'systemd'), { recursive: true });

// 4. Server-focused README
writeFileSync(join(stageDir, 'README-server.md'), `# VulnForge Server ${version}

Quick start:

**Linux / macOS**
\`\`\`
sudo ./scripts/install-server.sh
\`\`\`

**Windows (PowerShell as Administrator)**
\`\`\`
.\\scripts\\install-server.ps1
\`\`\`

Full docs: https://github.com/yourorg/vulnforge/tree/main/docs/operator
`);

// 5. Tar
console.log(`[build] tarring → ${finalName}`);
run('tar', ['-czf', finalName, '-C', stageDir, '.']);
console.log(`[build] done → ${finalName}`);

# Building artifacts

One codebase, three artifacts. Pick what you need.

## Desktop installer

```bash
npm install
npm run build:desktop
```

- Default target: current platform.
- Multi-platform: `npm run build:desktop -- --win --mac --linux` (requires matching toolchains).
- Publish: `npm run build:desktop -- --publish` (uses the configured provider in `package.json::build.publish`).

Output: `dist/VulnForge-Setup-<ver>.exe`, `VulnForge-<ver>.dmg`, `VulnForge-<ver>.AppImage`.

Under the hood: `scripts/build-desktop.mjs` runs `vite build` for the frontend, then `electron-builder` with the flags you passed.

## Server Docker image

```bash
npm run build:server:docker           # local image for current arch
npm run build:server:docker -- --push # multi-arch + push to registry
```

Tags: `vulnforge/server:<package-version>` and `:latest`.

Under the hood: `Dockerfile.server` is multi-stage — Node 20 builder compiles TypeScript, runtime stage is `node:20-bullseye-slim` + Python 3 + git. Non-root user `vulnforge` (uid 1001). Volume at `/data`.

## Server bare tarball

```bash
npm run build:server:tar
```

Output: `vulnforge-server-<ver>.tar.gz` containing `dist-server/`, `plugins/`, `package.json` (prod deps only), and `scripts/` (install + migrate + bootstrap).

Admin runs `tar xf ... && sudo ./scripts/install-server.sh` on the target host. See [`../operator/install-server.md`](../operator/install-server.md).

## Compiling the server on its own

```bash
npm run build:server
```

Produces `dist-server/` — handy for running the server directly without Electron:

```bash
VULNFORGE_MODE=server node dist-server/server/index.js
```

## Prerequisites by artifact

| Artifact | Node | Python | Docker | Platform binaries |
|---|---|---|---|---|
| Desktop installer | 20+ | — | — | electron-builder per target |
| Server Docker | 20+ | auto (in image) | 24+ | buildx for multi-arch |
| Server tarball | 20+ | — | — | `tar` + any OS |

## CI templates

Put these in `.github/workflows/` if you use GitHub Actions:

- `build-desktop.yml` — matrix `ubuntu-latest`, `macos-latest`, `windows-latest` → artifacts uploaded.
- `build-server.yml` — Linux runner → Docker image pushed to GHCR or Docker Hub + tarball attached to release.

(Leaving those as exercises — every team's CI story differs; hook into your preferred runner.)

## Troubleshooting

### `npm install` fails on electron postinstall

```
npm install --ignore-scripts bcryptjs jsonwebtoken  # or whatever you need
```

Electron's postinstall needs `node` on PATH in the spawned shell — sometimes nested shells lose it. `--ignore-scripts` skips it.

### Docker build runs out of memory

Multi-stage build needs ~2 GB. Bump Docker Desktop memory, or use the tarball path instead.

### TypeScript build errors that don't happen in `npm run dev`

`tsconfig.server.json` runs tsc strict-ish. `tsx` is looser. If dev works but `npm run build:server` fails, the type error is real — fix it rather than loosening the config.

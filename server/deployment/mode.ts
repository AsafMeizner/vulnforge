/**
 * Deployment mode detection - single source of truth for "am I a desktop
 * or a team server?". Read anywhere to branch behavior consistently.
 *
 * Precedence:
 *   1. VULNFORGE_MODE env var (explicit)           → 'server' | 'desktop'
 *   2. Electron parent process detected            → 'desktop'
 *   3. Loopback-only host binding                  → 'desktop'
 *      (covers plain `npm run dev` which binds to 127.0.0.1 and
 *      the `dev:server` script. Without this, the canonical helper
 *      would say 'server' for local dev and the bootstrap-admin
 *      guard would slam `503 run setup first` into every
 *      authenticated request.)
 *   4. default                                      → 'server'
 *
 * Client-side mode (solo vs team) is separate and stored in the local
 * `settings` table as `deployment_client_mode` - that concerns how the
 * desktop behaves relative to a server, not what this process IS.
 */

export type DeploymentMode = 'server' | 'desktop';

let cached: DeploymentMode | null = null;

function detect(): DeploymentMode {
  const explicit = process.env.VULNFORGE_MODE;
  if (explicit === 'server') return 'server';
  if (explicit === 'desktop') return 'desktop';

  // Electron sets several env variables; the reliable one is `ELECTRON_RUN_AS_NODE`
  // or the presence of `process.versions.electron`.
  if ((process.versions as any).electron) return 'desktop';
  if (process.env.ELECTRON_RUN_AS_NODE) return 'desktop';

  // Loopback-only host signal. The legacy auth.ts version of this
  // helper used this alone; we keep it as a fallback so plain
  // `npm run dev` (which defaults to 127.0.0.1) gets the desktop
  // experience without needing env-var plumbing.
  const host = process.env.VULNFORGE_HOST;
  if (host === '127.0.0.1' || host === 'localhost' || host === '::1') {
    return 'desktop';
  }
  // Unset VULNFORGE_HOST - the server binds to its own default
  // (127.0.0.1 per server/index.ts). Treat that same as loopback.
  if (!host) return 'desktop';

  return 'server';
}

export function getDeploymentMode(): DeploymentMode {
  if (cached) return cached;
  cached = detect();
  return cached;
}

export function isServerMode(): boolean {
  return getDeploymentMode() === 'server';
}

export function isDesktopMode(): boolean {
  return getDeploymentMode() === 'desktop';
}

/**
 * Reset cache - only for tests that manipulate env between scenarios.
 * Production code must not call this.
 */
export function __resetDeploymentModeForTests(): void {
  cached = null;
}

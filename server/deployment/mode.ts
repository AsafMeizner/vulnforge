/**
 * Deployment mode detection — single source of truth for "am I a desktop
 * or a team server?". Read anywhere to branch behavior consistently.
 *
 * Precedence:
 *   1. VULNFORGE_MODE env var (explicit)           → 'server' | 'desktop'
 *   2. Electron parent process detected            → 'desktop'
 *   3. default                                      → 'server'
 *
 * Client-side mode (solo vs team) is separate and stored in the local
 * `settings` table as `deployment_client_mode` — that concerns how the
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
 * Reset cache — only for tests that manipulate env between scenarios.
 * Production code must not call this.
 */
export function __resetDeploymentModeForTests(): void {
  cached = null;
}

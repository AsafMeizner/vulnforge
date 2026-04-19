/**
 * OpenClaw integration helpers — shared between cli/vulnforge.mjs
 * (the user-facing `vulnforge openclaw …` subcommand) and the unit
 * tests under tests/unit/openclaw-config.test.ts.
 *
 * The entry point of the CLI is a single zero-dep .mjs file by
 * design (easy to ship, easy to read top-to-bottom, no bundler to
 * install). Integration helpers that need their own unit tests go
 * in siblings like this one so the tests can import them directly
 * instead of exec-ing the whole CLI or keeping a hand-maintained
 * replica that drifts.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

// Local networks that should use the tighter 10s timeout. Anything
// else is "remote" and gets the 15s slack for cross-network latency.
const LOOPBACK_HOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/;

/**
 * Return a reasonable connectionTimeoutMs for a given base URL.
 * Loopback targets get 10s; everything else gets 15s so cross-net
 * TLS + keep-alive setup has room before OpenClaw gives up.
 */
export function computeTimeoutMs(baseUrl) {
  return LOOPBACK_HOST_RE.test(baseUrl) ? 10000 : 15000;
}

/**
 * Probe whether the `openclaw` binary is reachable on PATH by
 * spawning `openclaw --version`. Returns true on exit code 0,
 * false on any failure (ENOENT, timeout, non-zero).
 */
export function openclawAvailable() {
  try {
    const r = spawnSync('openclaw', ['--version'], {
      shell: false,
      encoding: 'utf8',
      timeout: 5000,
    });
    return r.status === 0;
  } catch {
    return false;
  }
}

/**
 * Build an MCP server entry in the exact shape OpenClaw's
 * `mcp.servers.<name>` config reads. Normalises the URL so the
 * caller can pass any of these and they all end up pointing at /mcp:
 *
 *   http://localhost:3001
 *   http://localhost:3001/
 *   http://localhost:3001/api
 *   http://localhost:3001/api/
 *   http://localhost:3001/mcp
 *
 * All collapse to `http://localhost:3001/mcp`. That's the most
 * important affordance the CLI wrapper provides — users copy-paste
 * whatever URL they had handy and it works.
 */
export function buildOpenclawMcpEntry({ url, token, timeoutMs }) {
  let mcpUrl = String(url || '').trim();
  // Trim trailing slashes first so downstream suffix checks work.
  mcpUrl = mcpUrl.replace(/\/+$/, '');
  // Strip /api if that's the suffix - users often have their CLI
  // configured with the REST api_base which ends in /api. OpenClaw
  // wants the /mcp endpoint, not /api.
  if (mcpUrl.endsWith('/api')) mcpUrl = mcpUrl.slice(0, -4);
  // Now append /mcp if it isn't already there.
  if (!mcpUrl.endsWith('/mcp')) mcpUrl = `${mcpUrl}/mcp`;

  const entry = {
    url: mcpUrl,
    transport: 'sse',
    connectionTimeoutMs: timeoutMs ?? computeTimeoutMs(mcpUrl),
  };
  if (token) {
    entry.headers = { Authorization: `Bearer ${token}` };
  }
  return entry;
}

// Candidate ports the VulnForge backend can land on. The server
// prefers 3001 but hops forward on EADDRINUSE (common when another
// dev tool is already on 3001, or when two VulnForge installs run
// side-by-side). Keep this list aligned with server/index.ts's
// retry range - currently "default + up to 9 more".
const DEFAULT_PORT_CANDIDATES = [3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010];

/**
 * Find the live VulnForge backend by trying the best signals in
 * priority order:
 *
 *   1. VULNFORGE_PORT env var (operator explicit override)
 *   2. .vulnforge-port file at process.cwd() (written by server/index.ts
 *      every time it successfully binds - covers the common case where
 *      the user runs the CLI from the repo root after `npm run dev`)
 *   3. An optional `forceBase` URL the caller already trusts (e.g. the
 *      CLI's configured api_base). Ping it; if it responds, use it.
 *   4. Probe DEFAULT_PORT_CANDIDATES one by one via /api/health and
 *      return the first that responds 200.
 *
 * Returns a normalised `http://localhost:<port>` origin on success, or
 * null if nothing responded. Never throws.
 *
 * The caller is expected to append `/mcp` (for OpenClaw) or `/api`
 * (for REST) themselves via buildOpenclawMcpEntry / the api helper.
 */
export async function discoverVulnforgeOrigin({
  forceBase,
  cwd = process.cwd(),
  probeTimeoutMs = 500,
} = {}) {
  // 1. VULNFORGE_PORT wins outright.
  const envPort = Number(process.env.VULNFORGE_PORT);
  if (Number.isFinite(envPort) && envPort > 0) {
    const url = `http://localhost:${envPort}`;
    if (await pingHealth(url, probeTimeoutMs)) return url;
    // env set but not reachable - still prefer the explicit value,
    // operator presumably knows it's about to come up.
    return url;
  }

  // 2. .vulnforge-port written by a running server.
  try {
    const portFile = join(cwd, '.vulnforge-port');
    if (existsSync(portFile)) {
      const text = readFileSync(portFile, 'utf8').trim();
      const port = Number(text);
      if (Number.isFinite(port) && port > 0 && port < 65536) {
        const url = `http://localhost:${port}`;
        if (await pingHealth(url, probeTimeoutMs)) return url;
        // File exists but server isn't up - fall through to probe.
      }
    }
  } catch {
    /* fall through */
  }

  // 3. Caller-supplied trusted base (e.g. CLI's configured api_base).
  if (forceBase) {
    try {
      const u = new URL(forceBase);
      const origin = `${u.protocol}//${u.host}`;
      if (await pingHealth(origin, probeTimeoutMs)) return origin;
    } catch {
      /* fall through */
    }
  }

  // 4. Sweep localhost port range.
  for (const port of DEFAULT_PORT_CANDIDATES) {
    const url = `http://localhost:${port}`;
    if (await pingHealth(url, probeTimeoutMs)) return url;
  }

  return null;
}

/** Single-shot HEAD-ish ping of <origin>/api/health. Never throws. */
async function pingHealth(origin, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${origin}/api/health`, { signal: ctrl.signal });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

/**
 * Ping an arbitrary VulnForge backend's /api/health endpoint once
 * to confirm it's reachable. Used by the `install` subcommand to
 * surface the most common failure mode ("backend down / wrong URL")
 * immediately instead of letting the user open an OpenClaw
 * conversation and see a mysterious timeout.
 *
 * CRITICAL: this MUST use the explicit baseUrl passed in, not the
 * CLI's shared api() helper which would hit cfg.api_base. When a
 * user runs `vulnforge openclaw install --url https://remote...`,
 * the CLI's own config still points at localhost — pinging the
 * wrong host for the check was the exact bug sourcery-ai flagged
 * on the first review pass.
 *
 * Returns { ok: true, uptime } on success, { ok: false, error }
 * on failure. Never throws.
 */
export async function pingVulnforgeBackend(baseUrl, { timeoutMs = 5000 } = {}) {
  // Normalise: accept either /api-style or root-style base URLs.
  // We want to hit <origin>/api/health regardless of what was passed.
  let origin;
  try {
    const u = new URL(baseUrl);
    origin = `${u.protocol}//${u.host}`;
  } catch {
    return { ok: false, error: `invalid URL: ${baseUrl}` };
  }
  const url = `${origin}/api/health`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) {
      return { ok: false, error: `HTTP ${res.status} ${res.statusText}` };
    }
    const body = await res.json().catch(() => ({}));
    return { ok: true, uptime: body.uptime };
  } catch (err) {
    return { ok: false, error: err?.message || String(err) };
  } finally {
    clearTimeout(timer);
  }
}

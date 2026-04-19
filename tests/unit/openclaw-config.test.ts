/**
 * OpenClaw integration — config-shape guardrails.
 *
 * Two kinds of asserts:
 *
 *  1. The ready-to-paste docs/integrations/openclaw/openclaw.mcp.json
 *     parses as JSON and carries both the solo + team entries with the
 *     expected transport + timeout + headers shapes. The point is to
 *     fail CI loudly if someone edits that file and accidentally breaks
 *     the schema OpenClaw's CLI consumes.
 *
 *  2. The CLI's `buildOpenclawMcpEntry` + `discoverVulnforgeOrigin`
 *     helpers (imported from the real module instead of a replica —
 *     a replica would just re-encode the bug you want to catch). Covers
 *     URL normalisation, auth-header shaping, loopback timeout tiering,
 *     and the four-step port-discovery priority chain so CI fails if a
 *     future change breaks dev-mode setups where the server hops off
 *     port 3001 on EADDRINUSE.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// Real implementations — not a replica. The whole point of extracting
// cli/openclaw.mjs out of cli/vulnforge.mjs was so these tests can
// import the code that actually runs in production.
// @ts-expect-error - .mjs has no declared types, but moduleResolution: bundler resolves it.
import {
  buildOpenclawMcpEntry,
  computeTimeoutMs,
  discoverVulnforgeOrigin,
  pingVulnforgeBackend,
  isLoopbackUrl,
} from '../../cli/openclaw.mjs';

const REPO_ROOT = join(__dirname, '..', '..');
const SNIPPET = join(
  REPO_ROOT,
  'docs',
  'integrations',
  'openclaw',
  'openclaw.mcp.json',
);

describe('docs/integrations/openclaw/openclaw.mcp.json', () => {
  const raw = readFileSync(SNIPPET, 'utf8');

  it('is valid JSON', () => {
    expect(() => JSON.parse(raw)).not.toThrow();
  });

  const cfg = JSON.parse(raw);

  it('has the OpenClaw-expected mcp.servers shape', () => {
    expect(cfg).toHaveProperty('mcp.servers');
    expect(typeof cfg.mcp.servers).toBe('object');
  });

  it('exposes a solo entry with url / transport / timeout', () => {
    const solo = cfg.mcp.servers.vulnforge;
    expect(solo).toBeDefined();
    expect(solo.url).toMatch(/^http:\/\/localhost:\d+\/mcp$/);
    expect(solo.transport).toBe('sse');
    expect(typeof solo.connectionTimeoutMs).toBe('number');
    expect(solo.connectionTimeoutMs).toBeGreaterThan(0);
  });

  it('exposes a team entry with Authorization header', () => {
    const team = cfg.mcp.servers['vulnforge-team'];
    expect(team).toBeDefined();
    expect(team.url).toMatch(/^https:\/\/.+\/mcp$/);
    expect(team.transport).toBe('sse');
    expect(team.headers).toBeDefined();
    expect(team.headers.Authorization).toMatch(/^Bearer\s+vf_/);
  });

  it('team timeout is more generous than solo (cross-net slack)', () => {
    const solo = cfg.mcp.servers.vulnforge;
    const team = cfg.mcp.servers['vulnforge-team'];
    expect(team.connectionTimeoutMs).toBeGreaterThanOrEqual(solo.connectionTimeoutMs);
  });
});

describe('buildOpenclawMcpEntry (real implementation)', () => {
  it('appends /mcp when a bare host is passed', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001' });
    expect(entry.url).toBe('http://localhost:3001/mcp');
  });

  it('strips trailing /api before appending /mcp', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001/api' });
    expect(entry.url).toBe('http://localhost:3001/mcp');
  });

  it('strips trailing /api/ (trailing slash + /api combo)', () => {
    // The CLI's default api_base is literally "http://localhost:3001/api"
    // but users often type "http://localhost:3001/api/" — this is the
    // paste-what-you-had-handy affordance the CLI advertises.
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001/api/' });
    expect(entry.url).toBe('http://localhost:3001/mcp');
  });

  it('leaves /mcp alone if already present', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001/mcp' });
    expect(entry.url).toBe('http://localhost:3001/mcp');
  });

  it('strips trailing slash', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001/' });
    expect(entry.url).toBe('http://localhost:3001/mcp');
  });

  it('collapses multiple trailing slashes', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001///' });
    expect(entry.url).toBe('http://localhost:3001/mcp');
  });

  it('omits headers when no token is provided', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001' });
    expect(entry.headers).toBeUndefined();
  });

  it('attaches a Bearer header when a token is provided', () => {
    const entry = buildOpenclawMcpEntry({
      url: 'https://vulnforge.acme.corp',
      token: 'vf_abc123',
    });
    expect(entry.headers).toEqual({ Authorization: 'Bearer vf_abc123' });
  });

  it('honours an explicit timeout', () => {
    const entry = buildOpenclawMcpEntry({
      url: 'http://localhost:3001',
      timeoutMs: 42_000,
    });
    expect(entry.connectionTimeoutMs).toBe(42_000);
  });

  it('picks 10s timeout for loopback URLs by default', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001' });
    expect(entry.connectionTimeoutMs).toBe(10_000);
  });

  it('picks 15s timeout for remote URLs by default', () => {
    const entry = buildOpenclawMcpEntry({ url: 'https://vulnforge.acme.corp' });
    expect(entry.connectionTimeoutMs).toBe(15_000);
  });

  it('picks 10s timeout for 127.0.0.1 loopback', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://127.0.0.1:3001' });
    expect(entry.connectionTimeoutMs).toBe(10_000);
  });
});

describe('computeTimeoutMs', () => {
  it('returns 10000 for localhost', () => {
    expect(computeTimeoutMs('http://localhost:3001/mcp')).toBe(10_000);
  });
  it('returns 10000 for 127.0.0.1', () => {
    expect(computeTimeoutMs('http://127.0.0.1:3001/mcp')).toBe(10_000);
  });
  it('returns 10000 for [::1] IPv6 loopback', () => {
    expect(computeTimeoutMs('http://[::1]:3001/mcp')).toBe(10_000);
  });
  it('returns 15000 for a remote host', () => {
    expect(computeTimeoutMs('https://vulnforge.acme.corp/mcp')).toBe(15_000);
  });
});

// ── isLoopbackUrl ────────────────────────────────────────────────────────
//
// The CLI uses this to decide whether a token is REQUIRED for install:
// loopback URLs can run without auth (desktop mode), non-loopback URLs
// MUST have a token or the MCP entry will 401 on every call.
//
// These tests guard the boundary — a regression that accidentally
// classifies localhost.evil.com or vulnforge.acme.corp as loopback
// would break the remote-install fail-fast safety net.

describe('isLoopbackUrl', () => {
  it('accepts localhost with port', () => {
    expect(isLoopbackUrl('http://localhost:3001/mcp')).toBe(true);
  });
  it('accepts localhost without port', () => {
    expect(isLoopbackUrl('http://localhost/mcp')).toBe(true);
  });
  it('accepts 127.0.0.1', () => {
    expect(isLoopbackUrl('http://127.0.0.1:3001')).toBe(true);
  });
  it('accepts [::1] IPv6 loopback', () => {
    expect(isLoopbackUrl('http://[::1]:3001')).toBe(true);
  });
  it('rejects a plain remote hostname', () => {
    expect(isLoopbackUrl('https://vulnforge.acme.corp/mcp')).toBe(false);
  });
  it('rejects subdomain spoof (localhost.evil.com)', () => {
    expect(isLoopbackUrl('http://localhost.evil.com/mcp')).toBe(false);
  });
  it('rejects subdomain spoof (127.0.0.1.evil.com)', () => {
    expect(isLoopbackUrl('http://127.0.0.1.evil.com/mcp')).toBe(false);
  });
  it('rejects prefix spoof (mylocalhost)', () => {
    expect(isLoopbackUrl('http://mylocalhost:3001')).toBe(false);
  });
  it('rejects an RFC1918 private address', () => {
    // Not strictly "loopback" even though it's unroutable — the
    // fail-fast predicate is about auth-required, and a 10.x host
    // could be an actual team server on a private network.
    expect(isLoopbackUrl('http://10.0.0.5:3001')).toBe(false);
  });
  it('tolerates empty / garbage input', () => {
    expect(isLoopbackUrl('')).toBe(false);
    expect(isLoopbackUrl(undefined)).toBe(false);
    expect(isLoopbackUrl(null as unknown as string)).toBe(false);
    expect(isLoopbackUrl('not a url')).toBe(false);
  });
});

// ── discoverVulnforgeOrigin ──────────────────────────────────────────────
//
// Four-step priority chain:
//   1. VULNFORGE_PORT env var (explicit operator override — we trust
//      it even if the server isn't up yet).
//   2. .vulnforge-port file at cwd (written by server/index.ts on bind).
//   3. forceBase URL (caller-supplied, typically cfg.api_base).
//   4. Probe DEFAULT_PORT_CANDIDATES = [3001..3010].
//
// Each test isolates by using a tmpdir cwd (no .vulnforge-port) and
// stubbing fetch to return the shape we want per probe.

describe('discoverVulnforgeOrigin', () => {
  let tmpCwd: string;
  const savedEnv = process.env.VULNFORGE_PORT;

  beforeEach(() => {
    tmpCwd = mkdtempSync(join(tmpdir(), 'vulnforge-discover-'));
    delete process.env.VULNFORGE_PORT;
    vi.restoreAllMocks();
  });

  afterEach(() => {
    rmSync(tmpCwd, { recursive: true, force: true });
    if (savedEnv === undefined) delete process.env.VULNFORGE_PORT;
    else process.env.VULNFORGE_PORT = savedEnv;
    vi.restoreAllMocks();
  });

  it('honours VULNFORGE_PORT env var when reachable', async () => {
    process.env.VULNFORGE_PORT = '4321';
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true } as Response)));
    const origin = await discoverVulnforgeOrigin({ cwd: tmpCwd });
    expect(origin).toBe('http://localhost:4321');
  });

  it('returns the env-specified URL even if unreachable (operator trust)', async () => {
    process.env.VULNFORGE_PORT = '4321';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('ECONNREFUSED');
      }),
    );
    const origin = await discoverVulnforgeOrigin({ cwd: tmpCwd });
    // Priority 1 wins even on failure — the operator just hasn't
    // started the server yet but told us where it'll be.
    expect(origin).toBe('http://localhost:4321');
  });

  it('reads .vulnforge-port file when env is unset', async () => {
    writeFileSync(join(tmpCwd, '.vulnforge-port'), '5555', 'utf8');
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true } as Response)));
    const origin = await discoverVulnforgeOrigin({ cwd: tmpCwd });
    expect(origin).toBe('http://localhost:5555');
  });

  it('falls through if .vulnforge-port is stale (server no longer bound)', async () => {
    writeFileSync(join(tmpCwd, '.vulnforge-port'), '5555', 'utf8');
    // fetch returns ok: true only for port 3001 (the canonical default)
    const fetchMock = vi.fn(async (url: string) => {
      if (url.startsWith('http://localhost:3001/')) {
        return { ok: true } as Response;
      }
      throw new Error('ECONNREFUSED');
    });
    vi.stubGlobal('fetch', fetchMock);
    const origin = await discoverVulnforgeOrigin({ cwd: tmpCwd });
    // Should skip the stale port-file entry and fall through to the
    // port sweep, landing on 3001.
    expect(origin).toBe('http://localhost:3001');
  });

  it('uses forceBase when env + file are absent', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        // Must match the host-and-port combination exactly —
        // pingHealth builds `${origin}/api/health` where origin
        // includes the port.
        if (url.startsWith('http://my-vulnforge.local:9999/')) {
          return { ok: true } as Response;
        }
        throw new Error('ECONNREFUSED');
      }),
    );
    const origin = await discoverVulnforgeOrigin({
      cwd: tmpCwd,
      forceBase: 'http://my-vulnforge.local:9999/api',
    });
    expect(origin).toBe('http://my-vulnforge.local:9999');
  });

  it('probes the default port range when nothing else helps', async () => {
    // Mock fetch to only succeed on port 3003 (server hopped twice).
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.startsWith('http://localhost:3003/')) {
          return { ok: true } as Response;
        }
        throw new Error('ECONNREFUSED');
      }),
    );
    const origin = await discoverVulnforgeOrigin({ cwd: tmpCwd });
    expect(origin).toBe('http://localhost:3003');
  });

  it('returns null when nothing responds', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('ECONNREFUSED');
      }),
    );
    const origin = await discoverVulnforgeOrigin({ cwd: tmpCwd });
    expect(origin).toBeNull();
  });

  it('ignores malformed .vulnforge-port contents', async () => {
    writeFileSync(join(tmpCwd, '.vulnforge-port'), 'not-a-number', 'utf8');
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.startsWith('http://localhost:3001/')) {
          return { ok: true } as Response;
        }
        throw new Error('ECONNREFUSED');
      }),
    );
    const origin = await discoverVulnforgeOrigin({ cwd: tmpCwd });
    // Garbage in the file shouldn't crash — priority 2 gets skipped.
    expect(origin).toBe('http://localhost:3001');
  });
});

describe('pingVulnforgeBackend', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns ok:true with uptime on a 200 response', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({ uptime: 42 }),
      })) as unknown as typeof fetch,
    );
    const res = await pingVulnforgeBackend('http://localhost:3001/api');
    expect(res).toEqual({ ok: true, uptime: 42 });
  });

  it('rejects invalid URLs before even dialling', async () => {
    const res = await pingVulnforgeBackend('not a url');
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/invalid URL/);
  });

  it('surfaces non-2xx status as an error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
      })) as unknown as typeof fetch,
    );
    const res = await pingVulnforgeBackend('http://localhost:3001/api');
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/503/);
  });

  it('surfaces network failures as an error without throwing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('ECONNREFUSED');
      }) as unknown as typeof fetch,
    );
    const res = await pingVulnforgeBackend('http://localhost:3001/api');
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/ECONNREFUSED/);
  });

  it('hits /api/health regardless of input path (explicit baseUrl, not cfg)', async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        calls.push(url);
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          json: async () => ({ uptime: 1 }),
        };
      }) as unknown as typeof fetch,
    );
    // User passes a /mcp URL — we should still hit /api/health on the
    // same origin rather than the MCP endpoint.
    await pingVulnforgeBackend('http://localhost:3001/mcp');
    expect(calls).toEqual(['http://localhost:3001/api/health']);
  });
});

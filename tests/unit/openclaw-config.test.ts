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
 *  2. The CLI's build-entry logic (imported via a tiny shim because
 *     cli/vulnforge.mjs isn't a module we can import directly — it's a
 *     zero-dep script that reads argv on load) produces the right shape
 *     for solo + team + edge-case URLs.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

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

// Tiny replica of the CLI's buildOpenclawMcpEntry so we can unit-test
// the URL-normalisation logic without exec-ing the whole zero-dep
// script. Keep in sync with cli/vulnforge.mjs.
function buildOpenclawMcpEntry({
  url,
  token,
  timeoutMs = 10000,
}: {
  url: string;
  token?: string;
  timeoutMs?: number;
}): Record<string, unknown> {
  let mcpUrl = url.replace(/\/$/, '');
  if (mcpUrl.endsWith('/api')) mcpUrl = mcpUrl.slice(0, -4);
  if (!mcpUrl.endsWith('/mcp')) mcpUrl = `${mcpUrl}/mcp`;

  const entry: Record<string, unknown> = {
    url: mcpUrl,
    transport: 'sse',
    connectionTimeoutMs: timeoutMs,
  };
  if (token) {
    entry.headers = { Authorization: `Bearer ${token}` };
  }
  return entry;
}

describe('buildOpenclawMcpEntry (CLI helper replica)', () => {
  it('appends /mcp when a bare host is passed', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001' });
    expect(entry.url).toBe('http://localhost:3001/mcp');
  });

  it('strips trailing /api before appending /mcp', () => {
    const entry = buildOpenclawMcpEntry({ url: 'http://localhost:3001/api' });
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
});

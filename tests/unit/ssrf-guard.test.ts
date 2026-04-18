/**
 * SSRF guard unit tests (CR-12).
 *
 * These tests matter disproportionately: a regression here fails open
 * (fetch succeeds against a blocked IP) with no other observable
 * signal. We exercise every blocklist branch explicitly so a future
 * refactor that misses one range produces a visible failure.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import {
  assertSafeExternalUrl,
  isSafeExternalUrl,
  isBlockedIpv4,
  isBlockedIpv6,
  SsrfError,
} from '../../server/lib/net';
import { __resetDeploymentModeForTests } from '../../server/deployment/mode';

// ── IPv4 blocklist ──────────────────────────────────────────────────────────

describe('isBlockedIpv4', () => {
  it('rejects RFC1918 ranges', () => {
    expect(isBlockedIpv4('10.0.0.1')).toBe(true);
    expect(isBlockedIpv4('10.255.255.255')).toBe(true);
    expect(isBlockedIpv4('172.16.0.1')).toBe(true);
    expect(isBlockedIpv4('172.31.255.254')).toBe(true);
    expect(isBlockedIpv4('192.168.1.1')).toBe(true);
  });

  it('allows public space between the RFC1918 blocks', () => {
    // 172.15.x and 172.32.x are outside the /12
    expect(isBlockedIpv4('172.15.0.1')).toBe(false);
    expect(isBlockedIpv4('172.32.0.1')).toBe(false);
  });

  it('rejects loopback and cloud metadata', () => {
    expect(isBlockedIpv4('127.0.0.1')).toBe(true);
    expect(isBlockedIpv4('127.0.0.53')).toBe(true);
    // AWS / GCP / Azure metadata
    expect(isBlockedIpv4('169.254.169.254')).toBe(true);
    // Link-local neighbours
    expect(isBlockedIpv4('169.254.0.1')).toBe(true);
  });

  it('rejects CGNAT and test-net ranges', () => {
    expect(isBlockedIpv4('100.64.0.1')).toBe(true);
    expect(isBlockedIpv4('100.127.255.254')).toBe(true);
    expect(isBlockedIpv4('198.18.0.1')).toBe(true);
    expect(isBlockedIpv4('192.0.2.1')).toBe(true);
    expect(isBlockedIpv4('198.51.100.1')).toBe(true);
    expect(isBlockedIpv4('203.0.113.1')).toBe(true);
  });

  it('rejects 0.0.0.0/8, multicast, and reserved', () => {
    expect(isBlockedIpv4('0.0.0.0')).toBe(true);
    expect(isBlockedIpv4('0.1.2.3')).toBe(true);
    expect(isBlockedIpv4('224.0.0.1')).toBe(true);
    expect(isBlockedIpv4('240.0.0.0')).toBe(true);
    expect(isBlockedIpv4('255.255.255.255')).toBe(true);
  });

  it('allows regular global unicast', () => {
    expect(isBlockedIpv4('8.8.8.8')).toBe(false);
    expect(isBlockedIpv4('1.1.1.1')).toBe(false);
    expect(isBlockedIpv4('140.82.114.3')).toBe(false); // github
  });

  it('fails closed on malformed IPs', () => {
    expect(isBlockedIpv4('not-an-ip')).toBe(true);
    expect(isBlockedIpv4('999.0.0.1')).toBe(true);
    expect(isBlockedIpv4('1.2.3')).toBe(true);
  });
});

// ── IPv6 blocklist ──────────────────────────────────────────────────────────

describe('isBlockedIpv6', () => {
  it('rejects loopback and unspecified', () => {
    expect(isBlockedIpv6('::1')).toBe(true);
    expect(isBlockedIpv6('::')).toBe(true);
  });

  it('rejects ULA (fc00::/7)', () => {
    expect(isBlockedIpv6('fc00::1')).toBe(true);
    expect(isBlockedIpv6('fd12:3456:789a::1')).toBe(true);
  });

  it('rejects link-local (fe80::/10)', () => {
    expect(isBlockedIpv6('fe80::1')).toBe(true);
    expect(isBlockedIpv6('fe80::abcd:1234')).toBe(true);
  });

  it('rejects multicast (ff00::/8)', () => {
    expect(isBlockedIpv6('ff02::1')).toBe(true);
  });

  it('rejects IPv4-mapped RFC1918 via v6 syntax', () => {
    // Classic bypass: net.isIP returns 6 but the underlying IP is v4
    expect(isBlockedIpv6('::ffff:10.0.0.1')).toBe(true);
    expect(isBlockedIpv6('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedIpv6('::ffff:169.254.169.254')).toBe(true);
  });

  it('allows public IPv6', () => {
    expect(isBlockedIpv6('2606:4700:4700::1111')).toBe(false); // cloudflare
    expect(isBlockedIpv6('2001:4860:4860::8888')).toBe(false); // google
  });
});

// ── URL validation ──────────────────────────────────────────────────────────

describe('assertSafeExternalUrl (server mode)', () => {
  const original = process.env.VULNFORGE_MODE;

  beforeEach(() => {
    process.env.VULNFORGE_MODE = 'server';
    __resetDeploymentModeForTests();
  });

  afterEach(() => {
    if (original === undefined) delete process.env.VULNFORGE_MODE;
    else process.env.VULNFORGE_MODE = original;
    __resetDeploymentModeForTests();
  });

  it('rejects non-http(s) protocols', async () => {
    await expect(assertSafeExternalUrl('file:///etc/passwd')).rejects.toThrow();
    await expect(assertSafeExternalUrl('gopher://example.com/')).rejects.toThrow();
    await expect(assertSafeExternalUrl('javascript:alert(1)')).rejects.toThrow();
    // ftp is intentionally blocked - we don't fetch ftp in this server
    await expect(assertSafeExternalUrl('ftp://example.com/')).rejects.toThrow();
  });

  it('rejects loopback in server mode', async () => {
    await expect(assertSafeExternalUrl('http://localhost:3001')).rejects.toThrow();
    await expect(assertSafeExternalUrl('http://127.0.0.1/admin')).rejects.toThrow();
    await expect(assertSafeExternalUrl('http://[::1]/')).rejects.toThrow();
  });

  it('rejects literal RFC1918 IPs', async () => {
    await expect(assertSafeExternalUrl('http://10.0.0.1/')).rejects.toThrow();
    await expect(assertSafeExternalUrl('http://192.168.1.1/')).rejects.toThrow();
    await expect(assertSafeExternalUrl('http://172.16.5.5/')).rejects.toThrow();
  });

  it('rejects cloud metadata endpoints', async () => {
    await expect(assertSafeExternalUrl('http://169.254.169.254/')).rejects.toThrow();
    await expect(assertSafeExternalUrl('http://metadata.google.internal/')).rejects.toThrow();
  });

  it('rejects malformed URLs', async () => {
    await expect(assertSafeExternalUrl('not-a-url')).rejects.toThrow();
    await expect(assertSafeExternalUrl('')).rejects.toThrow();
    await expect(assertSafeExternalUrl(null)).rejects.toThrow();
    await expect(assertSafeExternalUrl(undefined)).rejects.toThrow();
  });

  it('throws SsrfError with .status = 400', async () => {
    try {
      await assertSafeExternalUrl('http://127.0.0.1/');
      expect.fail('should have thrown');
    } catch (err: any) {
      expect(err).toBeInstanceOf(SsrfError);
      expect(err.status).toBe(400);
      expect(err.code).toBe('SSRF_REFUSED');
    }
  });

  it('honours the allowedHosts bypass', async () => {
    // allowedHosts skips DNS - useful for known-good IdPs
    await expect(
      assertSafeExternalUrl('https://login.okta.com/', {
        allowedHosts: ['login.okta.com'],
      }),
    ).resolves.toBeUndefined();
  });

  it('rejects plaintext http for non-loopback by default', async () => {
    // Even a public IP over plaintext is refused (passive-MITM risk
    // against leaked tokens)
    await expect(assertSafeExternalUrl('http://example.com/')).rejects.toThrow();
  });

  it('allows plaintext http when caller opts in', async () => {
    // Validates shape only - no DNS (allowedHosts bypass)
    await expect(
      assertSafeExternalUrl('http://api.example.com/', {
        allowHttp: true,
        allowedHosts: ['api.example.com'],
      }),
    ).resolves.toBeUndefined();
  });
});

describe('assertSafeExternalUrl (desktop mode)', () => {
  const original = process.env.VULNFORGE_MODE;

  beforeEach(() => {
    process.env.VULNFORGE_MODE = 'desktop';
    __resetDeploymentModeForTests();
  });

  afterEach(() => {
    if (original === undefined) delete process.env.VULNFORGE_MODE;
    else process.env.VULNFORGE_MODE = original;
    __resetDeploymentModeForTests();
  });

  it('allows localhost in desktop mode (Ollama)', async () => {
    await expect(
      assertSafeExternalUrl('http://localhost:11434/api/chat'),
    ).resolves.toBeUndefined();
    await expect(
      assertSafeExternalUrl('http://127.0.0.1:11434/api/chat'),
    ).resolves.toBeUndefined();
  });

  it('still rejects cloud metadata even in desktop mode', async () => {
    // Desktop running inside a cloud VM is still vulnerable - metadata
    // bypass is never allowed regardless of mode.
    await expect(
      assertSafeExternalUrl('http://169.254.169.254/latest/meta-data/'),
    ).rejects.toThrow();
  });
});

describe('isSafeExternalUrl', () => {
  const original = process.env.VULNFORGE_MODE;

  beforeEach(() => {
    process.env.VULNFORGE_MODE = 'server';
    __resetDeploymentModeForTests();
  });

  afterEach(() => {
    if (original === undefined) delete process.env.VULNFORGE_MODE;
    else process.env.VULNFORGE_MODE = original;
    __resetDeploymentModeForTests();
  });

  it('returns boolean false on reject', async () => {
    expect(await isSafeExternalUrl('http://127.0.0.1/')).toBe(false);
    expect(await isSafeExternalUrl('file:///etc/passwd')).toBe(false);
  });
});

/**
 * server/lib/net.ts - SSRF guardrail for outbound fetches.
 *
 * Any user-controlled URL (AI provider base_url, OIDC issuer_url,
 * integration webhooks, git clone targets the AI suggests, etc.) can
 * coerce the server into contacting arbitrary hosts on behalf of the
 * user. In server-mode deployments this is a classic SSRF vector:
 *
 *  - http://127.0.0.1:3001/api/admin/...  -> hits our own bound-but-
 *    untrusted local admin surface with the server's loopback identity
 *  - http://10.0.0.1/               -> LAN recon from a cloud VM
 *  - http://169.254.169.254/        -> AWS / GCP / Azure metadata
 *    endpoints, returns IAM creds
 *  - http://metadata.google.internal/ -> same, by name
 *  - http://[::1]/                  -> IPv6 loopback
 *
 * The helper below rejects any URL that:
 *  - is not http(s)
 *  - resolves to a private / reserved / metadata IP range (v4 or v6)
 *  - is hostname-shaped but maps to any of the above
 *  - uses http (plaintext) for anything non-loopback
 *
 * Localhost is permitted ONLY in desktop mode because desktop mode has
 * a legitimate reason (Ollama on :11434, local tool runners, etc.). A
 * server deployment has no outbound reason to fetch its own loopback
 * and allowing it would re-open SSRF-to-admin.
 *
 * Usage:
 *   await assertSafeExternalUrl(body.base_url);            // throws on bad
 *   if (!(await isSafeExternalUrl(url))) return 400;        // boolean form
 *   const ip = await resolveAndValidate(hostname);          // for pinning
 */

import dns from 'node:dns/promises';
import net from 'node:net';

import { isDesktopMode } from '../deployment/mode.js';

export interface UrlGuardOptions {
  /**
   * Allow 127.x / ::1 / localhost. Defaults to true in desktop mode,
   * false in server mode. Pass an explicit boolean to override.
   */
  allowLocalhost?: boolean;
  /** Allow plaintext http (non-loopback). Default: false. */
  allowHttp?: boolean;
  /** Exact-match allowlist of hostnames that bypass IP checks. */
  allowedHosts?: string[];
  /** Which protocols are allowed. Default: ['http:', 'https:']. */
  allowedProtocols?: string[];
  /**
   * Caller-friendly label for the field that failed validation. Goes
   * into the error message so the user knows which input was rejected.
   */
  field?: string;
}

class SsrfError extends Error {
  status = 400;
  code = 'SSRF_REFUSED';
  constructor(msg: string) {
    super(msg);
    this.name = 'SsrfError';
  }
}

// ── IP classification ──────────────────────────────────────────────────────

/** Is this an RFC1918 / reserved / metadata / loopback IPv4? */
export function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split('.').map(n => parseInt(n, 10));
  if (parts.length !== 4 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) {
    // Malformed - treat as blocked (fail-closed).
    return true;
  }
  const [a, b, _c, _d] = parts as [number, number, number, number];

  // 0.0.0.0/8 - unspecified / current network
  if (a === 0) return true;
  // 10.0.0.0/8 - RFC1918
  if (a === 10) return true;
  // 100.64.0.0/10 - CGNAT (RFC6598)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 - loopback
  if (a === 127) return true;
  // 169.254.0.0/16 - link-local (includes 169.254.169.254 cloud metadata)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 - RFC1918
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24 - IETF Protocol Assignments
  if (a === 192 && b === 0 && _c === 0) return true;
  // 192.0.2.0/24 - TEST-NET-1
  if (a === 192 && b === 0 && _c === 2) return true;
  // 192.168.0.0/16 - RFC1918
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 - benchmarking
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 198.51.100.0/24 - TEST-NET-2
  if (a === 198 && b === 51 && _c === 100) return true;
  // 203.0.113.0/24 - TEST-NET-3
  if (a === 203 && b === 0 && _c === 113) return true;
  // 224.0.0.0/4 - multicast
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 - reserved / broadcast
  if (a >= 240) return true;

  return false;
}

/** Is this a non-global-unicast IPv6? */
export function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();

  // ::  (unspecified) and ::1 (loopback)
  if (lower === '::' || lower === '::1') return true;

  // IPv4-mapped (::ffff:10.0.0.1) - check the v4 part
  const v4map = lower.match(/^::ffff:([0-9.]+)$/);
  if (v4map) return isBlockedIpv4(v4map[1]);

  // IPv4-compatible deprecated (::a.b.c.d)
  const v4compat = lower.match(/^::([0-9.]+)$/);
  if (v4compat && v4compat[1].includes('.')) return isBlockedIpv4(v4compat[1]);

  // fc00::/7  Unique Local Addresses
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
  // fe80::/10  link-local
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
  // ff00::/8  multicast
  if (/^ff[0-9a-f]{2}:/.test(lower)) return true;
  // 2001:db8::/32  documentation
  if (lower.startsWith('2001:db8:')) return true;
  // 64:ff9b::/96  NAT64 wellknown (usually fine but we refuse to be safe)
  if (lower.startsWith('64:ff9b:')) return true;

  return false;
}

export function isBlockedIp(ip: string): boolean {
  const v = net.isIP(ip);
  if (v === 4) return isBlockedIpv4(ip);
  if (v === 6) return isBlockedIpv6(ip);
  // Not a valid literal - let the caller keep treating as a hostname.
  return false;
}

// ── Hostname classification ────────────────────────────────────────────────

const METADATA_HOSTNAMES = new Set<string>([
  'metadata.google.internal',
  'metadata',
  'metadata.azure.com',
  'metadata.ec2.internal',
  'instance-data',
  'instance-data.ec2.internal',
]);

function isLoopbackHostname(h: string): boolean {
  const lower = h.toLowerCase();
  return lower === 'localhost' || lower.endsWith('.localhost');
}

// ── URL validation ─────────────────────────────────────────────────────────

function parse(raw: unknown, opts: UrlGuardOptions): URL {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new SsrfError(`${opts.field || 'url'}: empty or non-string`);
  }
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new SsrfError(`${opts.field || 'url'}: malformed URL`);
  }
  const allowedProtocols = opts.allowedProtocols || ['http:', 'https:'];
  if (!allowedProtocols.includes(u.protocol)) {
    throw new SsrfError(
      `${opts.field || 'url'}: protocol ${u.protocol} not allowed (need ${allowedProtocols.join(', ')})`,
    );
  }
  return u;
}

/**
 * Throws if the URL resolves to a non-global IP, uses a forbidden
 * protocol, or points at a known metadata endpoint. Performs DNS at
 * validation time so a hostname trick (evil.com → 127.0.0.1) is caught.
 */
export async function assertSafeExternalUrl(raw: unknown, opts: UrlGuardOptions = {}): Promise<void> {
  const u = parse(raw, opts);
  const host = u.hostname;
  const field = opts.field || 'url';

  // Allowlist bypass - exact match, used sparingly (e.g. known IdPs).
  if (opts.allowedHosts && opts.allowedHosts.some(h => h.toLowerCase() === host.toLowerCase())) {
    return;
  }

  // Cloud metadata by name
  if (METADATA_HOSTNAMES.has(host.toLowerCase())) {
    throw new SsrfError(`${field}: refuses cloud metadata hostname`);
  }

  const allowLocal = opts.allowLocalhost ?? isDesktopMode();

  if (isLoopbackHostname(host)) {
    if (!allowLocal) throw new SsrfError(`${field}: localhost not allowed in server mode`);
    // Fine - localhost in desktop mode.
    return;
  }

  const ipKind = net.isIP(host);
  if (ipKind) {
    // Literal IP - validate directly.
    if (isBlockedIp(host)) {
      if (allowLocal && (host === '127.0.0.1' || host === '::1')) return;
      throw new SsrfError(`${field}: IP ${host} is private / reserved / metadata`);
    }
    if (u.protocol === 'http:' && !opts.allowHttp) {
      throw new SsrfError(`${field}: plaintext http to ${host} not allowed`);
    }
    return;
  }

  // Hostname - resolve and re-check.
  let addrs: string[];
  try {
    const recs = await dns.lookup(host, { all: true, verbatim: true });
    addrs = recs.map(r => r.address);
  } catch (err: any) {
    throw new SsrfError(`${field}: DNS lookup failed for ${host}: ${err?.code || err?.message || 'unknown'}`);
  }

  if (addrs.length === 0) {
    throw new SsrfError(`${field}: host ${host} did not resolve`);
  }

  for (const addr of addrs) {
    if (isBlockedIp(addr)) {
      if (allowLocal && (addr === '127.0.0.1' || addr === '::1')) continue;
      throw new SsrfError(`${field}: host ${host} resolves to blocked IP ${addr}`);
    }
  }

  if (u.protocol === 'http:' && !opts.allowHttp) {
    throw new SsrfError(`${field}: plaintext http not allowed for ${host}`);
  }
}

export async function isSafeExternalUrl(raw: unknown, opts: UrlGuardOptions = {}): Promise<boolean> {
  try {
    await assertSafeExternalUrl(raw, opts);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve a hostname and return the first non-blocked address. Useful
 * for fetch-time IP pinning: callers can hand the resolved address to
 * an http.Agent's `lookup` option so the socket connects to the IP we
 * just validated rather than re-resolving the hostname (which closes
 * the DNS-rebinding window).
 *
 * Throws if no safe address is returned.
 */
export async function resolveAndValidate(
  hostname: string,
  opts: UrlGuardOptions = {},
): Promise<{ address: string; family: 4 | 6 }> {
  const allowLocal = opts.allowLocalhost ?? isDesktopMode();

  if (isLoopbackHostname(hostname)) {
    if (!allowLocal) throw new SsrfError(`${opts.field || 'host'}: localhost blocked`);
    return { address: '127.0.0.1', family: 4 };
  }

  const literal = net.isIP(hostname);
  if (literal) {
    if (isBlockedIp(hostname)) {
      if (allowLocal && (hostname === '127.0.0.1' || hostname === '::1')) {
        return { address: hostname, family: literal as 4 | 6 };
      }
      throw new SsrfError(`${opts.field || 'host'}: IP ${hostname} blocked`);
    }
    return { address: hostname, family: literal as 4 | 6 };
  }

  const recs = await dns.lookup(hostname, { all: true, verbatim: true });
  for (const r of recs) {
    if (!isBlockedIp(r.address)) {
      return { address: r.address, family: r.family as 4 | 6 };
    }
    if (allowLocal && (r.address === '127.0.0.1' || r.address === '::1')) {
      return { address: r.address, family: r.family as 4 | 6 };
    }
  }
  throw new SsrfError(`${opts.field || 'host'}: ${hostname} resolves only to blocked IPs`);
}

export { SsrfError };

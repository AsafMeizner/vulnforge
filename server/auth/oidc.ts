/**
 * OIDC scaffolding — OAuth 2.0 / OpenID Connect flow for team-server SSO.
 *
 * This file is the adapter. Actual provider rows live in `oidc_providers`
 * table. Admin configures providers there via the Settings UI.
 *
 * Flow overview:
 *   Desktop opens /api/auth/oidc/:name/start in system browser
 *     → server 302s to provider's authorization endpoint (PKCE challenge)
 *   Provider redirects back to /api/auth/oidc/:name/callback
 *     → server swaps code for tokens, stashes a one-time code,
 *       renders a "paste this into desktop" page
 *   Desktop POSTs /api/auth/oidc/exchange {one_time_code}
 *     → server returns JWT access+refresh pair
 *
 * Behind a flag (settings.oidc_enabled or VULNFORGE_OIDC=1) so installs
 * that don't need SSO never load the OIDC code path.
 *
 * HTTP calls use the built-in fetch so no extra dependency is required
 * for this scaffolding pass. Full openid-client integration (JWT signature
 * verification on id_token) is a follow-up task.
 */
import { randomBytes, createHash } from 'crypto';
import { getDb, persistDb } from '../db.js';

// ── Types ───────────────────────────────────────────────────────────────────

export interface OidcProviderRow {
  id: number;
  name: string;
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  role_mapping_json: string;
  enabled: number;
  created_at: number;
}

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
}

interface PendingAuth {
  provider_name: string;
  state: string;
  code_verifier: string;
  nonce: string;
  created_at: number;
}

interface OneTimeCode {
  provider_name: string;
  upstream_sub: string;
  upstream_email: string | null;
  created_at: number;
}

// ── In-memory stores ────────────────────────────────────────────────────────
// For a single-process server this is fine. Clustered setups need SQLite or Redis.

const PENDING_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 2 * 60 * 1000;
const pending = new Map<string, PendingAuth>();
const codes = new Map<string, OneTimeCode>();

// ── Feature flag ────────────────────────────────────────────────────────────

export function isOidcEnabled(): boolean {
  if (process.env.VULNFORGE_OIDC === '0' || process.env.VULNFORGE_OIDC === 'false') return false;
  if (process.env.VULNFORGE_OIDC === '1' || process.env.VULNFORGE_OIDC === 'true') return true;
  try {
    const db = getDb();
    const stmt = db.prepare(`SELECT value FROM settings WHERE key = 'oidc_enabled'`);
    if (stmt.step()) {
      const v = stmt.get()[0];
      stmt.free();
      return v === '1' || v === 'true';
    }
    stmt.free();
  } catch { /* settings table missing on some old DBs */ }
  return false;
}

// ── Provider lookup ─────────────────────────────────────────────────────────

export function getOidcProvider(name: string): OidcProviderRow | null {
  try {
    const db = getDb();
    const stmt = db.prepare(
      `SELECT id, name, issuer_url, client_id, client_secret, scopes,
              role_mapping_json, enabled, created_at
       FROM oidc_providers WHERE name = ? AND enabled = 1 LIMIT 1`,
    );
    stmt.bind([name]);
    if (!stmt.step()) { stmt.free(); return null; }
    const cols = stmt.getColumnNames();
    const vals = stmt.get();
    stmt.free();
    const row: Record<string, any> = {};
    cols.forEach((c: string, i: number) => { row[c] = vals[i]; });
    return row as OidcProviderRow;
  } catch { return null; }
}

// ── PKCE + state ────────────────────────────────────────────────────────────

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function makePkce(): { verifier: string; challenge: string } {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

// ── Discovery ───────────────────────────────────────────────────────────────

const discoveryCache = new Map<string, { at: number; data: OidcDiscovery }>();
const DISCOVERY_TTL_MS = 24 * 60 * 60 * 1000;

export async function discoverProvider(provider: OidcProviderRow): Promise<OidcDiscovery> {
  const cached = discoveryCache.get(provider.issuer_url);
  if (cached && Date.now() - cached.at < DISCOVERY_TTL_MS) return cached.data;
  const wellKnown = provider.issuer_url.replace(/\/$/, '') + '/.well-known/openid-configuration';
  const resp = await fetch(wellKnown);
  if (!resp.ok) throw new Error(`discovery failed ${resp.status} ${wellKnown}`);
  const data = await resp.json() as OidcDiscovery;
  if (!data.authorization_endpoint || !data.token_endpoint) {
    throw new Error(`discovery incomplete — missing endpoints`);
  }
  discoveryCache.set(provider.issuer_url, { at: Date.now(), data });
  return data;
}

// ── Flow: build authorize URL ───────────────────────────────────────────────

export async function buildAuthorizeUrl(
  provider: OidcProviderRow,
  redirect_uri: string,
): Promise<string> {
  const discovery = await discoverProvider(provider);
  const state = base64url(randomBytes(24));
  const nonce = base64url(randomBytes(16));
  const pkce = makePkce();

  pending.set(state, {
    provider_name: provider.name,
    state,
    code_verifier: pkce.verifier,
    nonce,
    created_at: Date.now(),
  });
  gcPending();

  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', provider.client_id);
  url.searchParams.set('redirect_uri', redirect_uri);
  url.searchParams.set('scope', provider.scopes || 'openid email profile');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('code_challenge', pkce.challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

// ── Flow: handle callback ───────────────────────────────────────────────────

export interface CallbackOk { ok: true; one_time_code: string; email: string | null; }
export interface CallbackErr { ok: false; error: string; code: string; }

export async function handleCallback(
  providerName: string,
  redirect_uri: string,
  code: string,
  state: string,
): Promise<CallbackOk | CallbackErr> {
  const provider = getOidcProvider(providerName);
  if (!provider) return { ok: false, error: `unknown provider ${providerName}`, code: 'UNKNOWN_PROVIDER' };
  const rec = pending.get(state);
  if (!rec) return { ok: false, error: 'expired or invalid state', code: 'BAD_STATE' };
  pending.delete(state);

  const discovery = await discoverProvider(provider);

  const tokenResp = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri,
      client_id: provider.client_id,
      client_secret: provider.client_secret,
      code_verifier: rec.code_verifier,
    }).toString(),
  });
  if (!tokenResp.ok) {
    const body = await tokenResp.text();
    return { ok: false, error: `token swap failed: ${body.slice(0, 200)}`, code: 'TOKEN_SWAP_FAILED' };
  }
  const tokens = await tokenResp.json() as { id_token?: string; access_token?: string };

  let sub = 'unknown';
  let email: string | null = null;
  if (tokens.id_token) {
    const parts = tokens.id_token.split('.');
    if (parts.length === 3) {
      try {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as { sub?: string; email?: string };
        if (payload.sub) sub = payload.sub;
        if (payload.email) email = payload.email;
      } catch { /* malformed — fall through */ }
    }
  }
  if (!email && tokens.access_token && discovery.userinfo_endpoint) {
    try {
      const ui = await fetch(discovery.userinfo_endpoint, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      if (ui.ok) {
        const j = await ui.json() as { email?: string; sub?: string };
        if (j.email) email = j.email;
        if (!sub || sub === 'unknown') sub = j.sub ?? sub;
      }
    } catch { /* non-fatal */ }
  }

  const oneTimeCode = base64url(randomBytes(24));
  codes.set(oneTimeCode, {
    provider_name: providerName,
    upstream_sub: sub,
    upstream_email: email,
    created_at: Date.now(),
  });
  gcCodes();
  return { ok: true, one_time_code: oneTimeCode, email };
}

// ── Flow: consume one-time code → provider identity record ─────────────────

export function consumeOneTimeCode(oneTimeCode: string): OneTimeCode | null {
  const rec = codes.get(oneTimeCode);
  if (!rec) return null;
  if (Date.now() - rec.created_at > CODE_TTL_MS) {
    codes.delete(oneTimeCode);
    return null;
  }
  codes.delete(oneTimeCode);
  return rec;
}

// ── Role mapping ────────────────────────────────────────────────────────────

export function mapRoleFromProvider(
  provider: OidcProviderRow,
  email: string | null,
  groups: string[] = [],
): string {
  let mapping: any = {};
  try { mapping = JSON.parse(provider.role_mapping_json || '{}'); } catch { /* default empty */ }
  if (Array.isArray(groups) && mapping.groups) {
    for (const g of groups) {
      if (mapping.groups[g]) return String(mapping.groups[g]);
    }
  }
  if (email && mapping.email_domain) {
    const domain = email.split('@')[1]?.toLowerCase();
    if (domain && mapping.email_domain[domain]) return String(mapping.email_domain[domain]);
  }
  return String(mapping.default || 'viewer');
}

// ── Provider CRUD (admin UI) ────────────────────────────────────────────────

export function upsertOidcProvider(row: Omit<OidcProviderRow, 'id' | 'created_at'>): number {
  const db = getDb();
  db.run(
    `INSERT OR REPLACE INTO oidc_providers
       (name, issuer_url, client_id, client_secret, scopes, role_mapping_json, enabled, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [row.name, row.issuer_url, row.client_id, row.client_secret,
     row.scopes, row.role_mapping_json, row.enabled, Date.now()],
  );
  persistDb();
  const idRow = db.exec('SELECT last_insert_rowid() AS id');
  return (idRow[0]?.values?.[0]?.[0] as number) ?? 0;
}

export function listOidcProviders(): OidcProviderRow[] {
  try {
    const db = getDb();
    const stmt = db.prepare(`SELECT * FROM oidc_providers ORDER BY name`);
    const rows: OidcProviderRow[] = [];
    while (stmt.step()) {
      const cols = stmt.getColumnNames();
      const vals = stmt.get();
      const obj: Record<string, any> = {};
      cols.forEach((c: string, i: number) => { obj[c] = vals[i]; });
      rows.push(obj as OidcProviderRow);
    }
    stmt.free();
    return rows;
  } catch { return []; }
}

// ── GC ──────────────────────────────────────────────────────────────────────

function gcPending(): void {
  const cutoff = Date.now() - PENDING_TTL_MS;
  for (const [k, v] of pending) if (v.created_at < cutoff) pending.delete(k);
}
function gcCodes(): void {
  const cutoff = Date.now() - CODE_TTL_MS;
  for (const [k, v] of codes) if (v.created_at < cutoff) codes.delete(k);
}

// For tests
export function __resetOidcStateForTests(): void {
  pending.clear();
  codes.clear();
  discoveryCache.clear();
}

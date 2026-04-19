/**
 * OIDC scaffolding - OAuth 2.0 / OpenID Connect flow for team-server SSO.
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
 * for this scaffolding pass. id_token signature verification is done
 * locally via Node's native JWK -> KeyObject path + jsonwebtoken; see
 * verifyIdToken() below.
 */
import { randomBytes, createHash, createPublicKey } from 'crypto';
import jwt from 'jsonwebtoken';
import { getDb, persistDb } from '../db.js';
import { encryptSecret, decryptSecret, isEncrypted } from '../lib/crypto.js';
import { assertSafeExternalUrl } from '../lib/net.js';

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
    // Security CR-09: client_secret is stored encrypted. Decrypt
    // transparently so the OIDC flow sees plaintext.
    if (typeof row.client_secret === 'string' && row.client_secret) {
      try { row.client_secret = decryptSecret(row.client_secret); }
      catch { row.client_secret = '__undecryptable__'; }
    }
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

  // CR-12: validate the stored issuer before fetching. Server-mode
  // deployments reject loopback / RFC1918 / cloud-metadata destinations;
  // desktop mode allows loopback (self-hosted Keycloak at localhost).
  await assertSafeExternalUrl(provider.issuer_url, { field: 'issuer_url' });

  const wellKnown = provider.issuer_url.replace(/\/$/, '') + '/.well-known/openid-configuration';
  const resp = await fetch(wellKnown);
  if (!resp.ok) throw new Error(`discovery failed ${resp.status} ${wellKnown}`);
  const data = await resp.json() as OidcDiscovery;
  if (!data.authorization_endpoint || !data.token_endpoint) {
    throw new Error(`discovery incomplete - missing endpoints`);
  }

  // CR-12: the IdP hands back URLs the server will subsequently fetch.
  // A malicious or compromised IdP could point token_endpoint at our own
  // loopback admin API. Re-validate each endpoint the same way we did
  // the issuer_url.
  await assertSafeExternalUrl(data.token_endpoint, { field: 'token_endpoint' });
  if (data.userinfo_endpoint) {
    await assertSafeExternalUrl(data.userinfo_endpoint, { field: 'userinfo_endpoint' });
  }
  if (data.jwks_uri) {
    await assertSafeExternalUrl(data.jwks_uri, { field: 'jwks_uri' });
  }
  // authorization_endpoint is not fetched by the server (browser follows
  // the 302) so server-side SSRF isn't a concern for that one.

  discoveryCache.set(provider.issuer_url, { at: Date.now(), data });
  return data;
}

// ── JWKS + id_token signature verification ─────────────────────────────────
//
// Previously this file decoded the id_token payload with zero signature
// verification. Any network-positioned attacker (compromised IdP, BGP
// hijack, DNS poisoning, a malicious self-hosted Keycloak) could hand
// back a hand-rolled base64-JSON body in `id_token` and we'd trust its
// `sub` + `email` - instant identity spoofing including `admin`.
//
// The fix: fetch JWKS once per issuer (cached 1h), pick the key by
// `kid`, convert the JWK -> PEM via Node's native jwk->KeyObject path,
// and hand the whole thing to `jsonwebtoken.verify` with iss / aud /
// exp enforced. Zero new deps - we already ship jsonwebtoken + Node
// 18's crypto.createPublicKey({ format: 'jwk', ... }).

const JWKS_TTL_MS = 60 * 60 * 1000;

interface Jwk {
  kid?: string;
  kty: string;
  alg?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
  crv?: string;
  use?: string;
}

const jwksCache = new Map<string, { at: number; keys: Jwk[] }>();

async function fetchJwks(jwksUri: string): Promise<Jwk[]> {
  const cached = jwksCache.get(jwksUri);
  if (cached && Date.now() - cached.at < JWKS_TTL_MS) return cached.keys;

  await assertSafeExternalUrl(jwksUri, { field: 'jwks_uri' });
  const resp = await fetch(jwksUri);
  if (!resp.ok) throw new Error(`jwks fetch failed ${resp.status} ${jwksUri}`);
  const body = await resp.json() as { keys?: Jwk[] };
  const keys = Array.isArray(body.keys) ? body.keys : [];
  jwksCache.set(jwksUri, { at: Date.now(), keys });
  return keys;
}

/** Force a JWKS refresh - used when the id_token references a `kid` we don't know. */
async function refreshJwks(jwksUri: string): Promise<Jwk[]> {
  jwksCache.delete(jwksUri);
  return fetchJwks(jwksUri);
}

/**
 * Verify an id_token against the provider's JWKS + standard claims.
 * Throws on any failure; returns the decoded payload on success.
 *
 * Allowed algorithms are pinned to asymmetric JWT algs. HS* is
 * refused - the `alg: 'none'` bypass is implicitly refused by the
 * allowlist + `jwt.verify` rejects it internally anyway.
 */
async function verifyIdToken(
  idToken: string,
  provider: OidcProviderRow,
  discovery: OidcDiscovery,
  expectedNonce: string,
): Promise<Record<string, any>> {
  if (!discovery.jwks_uri) {
    throw new Error('OIDC provider has no jwks_uri - refusing unverified id_token');
  }

  // Decode header without verification to extract kid + alg.
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('malformed id_token (wrong segment count)');
  let header: { alg?: string; kid?: string };
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch {
    throw new Error('malformed id_token header');
  }
  const alg = header.alg;
  const ALLOWED_ALGS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'] as const;
  if (!alg || !(ALLOWED_ALGS as readonly string[]).includes(alg)) {
    throw new Error(`id_token alg not allowed: ${alg || '(none)'}`);
  }

  let keys = await fetchJwks(discovery.jwks_uri);
  let jwk = header.kid ? keys.find(k => k.kid === header.kid) : keys[0];
  if (!jwk) {
    // Key rotation: refresh once and retry.
    keys = await refreshJwks(discovery.jwks_uri);
    jwk = header.kid ? keys.find(k => k.kid === header.kid) : keys[0];
  }
  if (!jwk) {
    throw new Error(`no JWKS key matches id_token kid=${header.kid || '(none)'}`);
  }

  // Convert the JWK to a PEM public key via Node's native path.
  let pem: string;
  try {
    const keyObj = createPublicKey({ format: 'jwk', key: jwk as any });
    pem = keyObj.export({ format: 'pem', type: 'spki' }) as string;
  } catch (err: any) {
    throw new Error(`failed to import JWK: ${err?.message || err}`);
  }

  const payload = jwt.verify(idToken, pem, {
    algorithms: [alg as any],
    // Trim trailing slash differences the same way the issuer check in
    // the spec does. Most IdPs are strict about this so we match what
    // they emit.
    issuer: provider.issuer_url.replace(/\/$/, ''),
    audience: provider.client_id,
  }) as Record<string, any>;

  // Extra claim that `jwt.verify` doesn't check for us.
  if (!expectedNonce) throw new Error('internal error - no expected nonce');
  if (payload.nonce !== expectedNonce) {
    throw new Error('id_token nonce mismatch');
  }
  return payload;
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
  if (!tokens.id_token) {
    return { ok: false, error: 'token response missing id_token', code: 'NO_ID_TOKEN' };
  }

  // Verify id_token signature + iss / aud / exp / nonce claims. Bail
  // on any failure - we used to trust the unverified payload which
  // meant any network-positioned attacker could impersonate any user.
  let payload: Record<string, any>;
  try {
    payload = await verifyIdToken(tokens.id_token, provider, discovery, rec.nonce);
  } catch (err: any) {
    return {
      ok: false,
      error: `id_token verification failed: ${err?.message || err}`,
      code: 'ID_TOKEN_INVALID',
    };
  }
  if (typeof payload.sub === 'string' && payload.sub) sub = payload.sub;
  if (typeof payload.email === 'string' && payload.email) email = payload.email;
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

export async function upsertOidcProvider(
  row: Omit<OidcProviderRow, 'id' | 'created_at'>,
): Promise<number> {
  // CR-12: validate issuer_url against SSRF before persisting. Throws a
  // SsrfError with .status = 400 on failure; callers can surface to HTTP.
  if (row.issuer_url) {
    await assertSafeExternalUrl(row.issuer_url, { field: 'issuer_url' });
  }

  const db = getDb();
  // CR-09 fix: encrypt client_secret before it hits SQLite.
  // encryptSecret is idempotent via isEncrypted(); safe to call on
  // field updates where the secret isn't changing.
  const secretCipher = row.client_secret ? encryptSecret(row.client_secret) : null;
  db.run(
    `INSERT OR REPLACE INTO oidc_providers
       (name, issuer_url, client_id, client_secret, scopes, role_mapping_json, enabled, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [row.name, row.issuer_url, row.client_id, secretCipher,
     row.scopes, row.role_mapping_json, row.enabled, Date.now()],
  );
  persistDb();
  const idStmt = db.prepare('SELECT last_insert_rowid() AS id');
  let newId = 0;
  if (idStmt.step()) {
    const val = idStmt.get()[0];
    if (typeof val === 'number') newId = val;
  }
  idStmt.free();
  return newId;
}

/**
 * Boot-time migration. Scans oidc_providers for rows whose
 * client_secret is still plaintext (no `vf1:` prefix) and encrypts
 * them in place. Safe to run repeatedly - the prefix check stops
 * double-encrypting. Called once from initDb() after schema setup.
 */
export function migrateOidcSecrets(): void {
  try {
    const db = getDb();
    const stmt = db.prepare('SELECT id, client_secret FROM oidc_providers WHERE client_secret IS NOT NULL');
    const rows: Array<{ id: number; secret: string }> = [];
    while (stmt.step()) {
      const [id, secret] = stmt.get() as [number, string];
      rows.push({ id, secret });
    }
    stmt.free();
    let migrated = 0;
    for (const r of rows) {
      if (typeof r.secret === 'string' && r.secret && !isEncrypted(r.secret)) {
        db.run('UPDATE oidc_providers SET client_secret = ? WHERE id = ?', [encryptSecret(r.secret), r.id]);
        migrated++;
      }
    }
    if (migrated > 0) { persistDb(); console.log(`[crypto] migrated ${migrated} OIDC client_secret rows`); }
  } catch (err: any) {
    console.warn(`[crypto] migrateOidcSecrets failed: ${err?.message || err}`);
  }
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

// Run GC on a 60s timer in addition to per-request. Previously GC
// only fired inside buildAuthorizeUrl + handleCallback, so 10k pending
// entries during a flood would stay resident for the full PENDING_TTL
// if no further OIDC traffic arrived. Also cap map sizes so a single
// attacker can't hold arbitrary RSS.
const OIDC_GC_INTERVAL_MS = 60_000;
const PENDING_CAP = 5000;
const CODES_CAP = 2000;
const _oidcGcTimer = setInterval(() => {
  gcPending();
  gcCodes();
  // Defensive cap: if either map is still over limit after TTL-based
  // GC, drop oldest until under cap.
  dropOldestOver(pending, PENDING_CAP);
  dropOldestOver(codes, CODES_CAP);
}, OIDC_GC_INTERVAL_MS);
_oidcGcTimer.unref?.(); // don't keep the event loop alive for this alone

function dropOldestOver<V extends { created_at: number }>(
  m: Map<string, V>,
  cap: number,
): void {
  if (m.size <= cap) return;
  const sorted = Array.from(m.entries()).sort((a, b) => a[1].created_at - b[1].created_at);
  const toDrop = m.size - cap;
  for (let i = 0; i < toDrop; i++) m.delete(sorted[i][0]);
}

// For tests
export function __resetOidcStateForTests(): void {
  pending.clear();
  codes.clear();
  discoveryCache.clear();
}

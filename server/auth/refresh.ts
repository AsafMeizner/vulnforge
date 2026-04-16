/**
 * Refresh tokens — 30-day opaque strings that can be traded for a fresh
 * access token. One row per logged-in device.
 *
 * Security model:
 *   - Tokens are 256-bit random values, never JWT (opaque).
 *   - Stored SERVER-SIDE as bcrypt-hashed values. The raw token only
 *     ever exists in the response body on issue / rotate, and in the
 *     client's OS secure store thereafter.
 *   - Every use ROTATES the token (single-use). Replay of an old token
 *     revokes the entire device session and emits an audit_log event.
 *   - Expiry is enforced server-side. Revocation is immediate
 *     (revoked=1 flag), propagates on next refresh attempt.
 */
import { randomBytes } from 'crypto';
import bcrypt from 'bcryptjs';
import { ulid } from '../utils/ulid.js';

export const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const REFRESH_BCRYPT_COST = 6; // low cost — tokens already have 256 bits of entropy

export interface RefreshTokenRow {
  id?: number;
  user_id: number;
  token_hash: string;
  device_id: string;
  device_name: string;
  expires_at: number;
  revoked: 0 | 1;
  created_at: number;
  last_used_at: number | null;
}

/** Generate a fresh refresh token + device_id on first login for a device. */
export function mintRefreshToken(): { raw: string; expires_at: number } {
  const raw = randomBytes(32).toString('base64url');
  const expires_at = Date.now() + REFRESH_TTL_MS;
  return { raw, expires_at };
}

export function mintDeviceId(): string {
  return ulid();
}

export async function hashRefreshToken(raw: string): Promise<string> {
  return bcrypt.hash(raw, REFRESH_BCRYPT_COST);
}

export async function verifyRefreshToken(raw: string, hash: string): Promise<boolean> {
  if (!raw || !hash) return false;
  try {
    return await bcrypt.compare(raw, hash);
  } catch { return false; }
}

/**
 * Classify a refresh attempt outcome. Callers persist the result.
 *   'ok'            — rotate: issue new pair, invalidate old.
 *   'expired'       — row exists but past expires_at.
 *   'revoked'       — row revoked=1; do NOT re-issue; audit log.
 *   'not-found'     — raw token has no match. Possible replay of pre-rotation
 *                     token → caller should flag the device_id for audit.
 */
export type RefreshOutcome = 'ok' | 'expired' | 'revoked' | 'not-found';

export function evaluateRefreshRow(
  row: RefreshTokenRow | null,
  now: number = Date.now(),
): Exclude<RefreshOutcome, 'ok'> | null {
  if (!row) return 'not-found';
  if (row.revoked) return 'revoked';
  if (row.expires_at < now) return 'expired';
  return null; // null = no problem, proceed with verify
}

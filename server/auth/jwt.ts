/**
 * JWT access-token signing and verification.
 *
 * Access tokens are short-lived (15 minutes) and carry only what's
 * needed for routing + permission checks: user id, role, device id.
 * They are ephemeral on the client (memory only) — never persisted
 * to disk. Refresh tokens (separate module) live longer and are
 * used to mint fresh access tokens.
 *
 * Secret source precedence:
 *   1. process.env.VULNFORGE_JWT_SECRET (prod — set by server install)
 *   2. settings.jwt_signing_secret (dev — auto-generated on first boot)
 *   3. in-memory random (test — every test run regenerates)
 *
 * Rotating the secret invalidates every outstanding access token
 * instantly and is documented in docs/security/secret-handling.md.
 */
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

let cachedSecret: string | null = null;

export function setJwtSecret(secret: string): void {
  if (!secret || secret.length < 32) {
    throw new Error('setJwtSecret: secret must be at least 32 chars of entropy');
  }
  cachedSecret = secret;
}

export function getJwtSecret(): string {
  if (cachedSecret) return cachedSecret;
  const envSecret = process.env.VULNFORGE_JWT_SECRET;
  if (envSecret && envSecret.length >= 32) {
    cachedSecret = envSecret;
    return cachedSecret;
  }
  // Dev/test fallback — random per process. Won't persist across restarts,
  // which is deliberately inconvenient so prod installs set the env var.
  cachedSecret = randomBytes(48).toString('base64');
  return cachedSecret;
}

export interface AccessTokenClaims {
  sub: number;           // user_id
  role: string;
  device_id: string;
  iat?: number;
  exp?: number;
}

export function signAccessToken(
  claims: Omit<AccessTokenClaims, 'iat' | 'exp'>,
): string {
  return jwt.sign(
    { sub: claims.sub, role: claims.role, device_id: claims.device_id },
    getJwtSecret(),
    { algorithm: 'HS256', expiresIn: ACCESS_TOKEN_TTL_SECONDS },
  );
}

export interface VerifyResult {
  ok: boolean;
  claims?: AccessTokenClaims;
  error?: 'malformed' | 'expired' | 'invalid-signature' | 'unknown';
}

export function verifyAccessToken(token: string): VerifyResult {
  try {
    const decoded = jwt.verify(token, getJwtSecret(), { algorithms: ['HS256'] }) as unknown as AccessTokenClaims;
    if (typeof decoded !== 'object' || typeof decoded.sub !== 'number') {
      return { ok: false, error: 'malformed' };
    }
    return { ok: true, claims: decoded };
  } catch (e: any) {
    if (e.name === 'TokenExpiredError') return { ok: false, error: 'expired' };
    if (e.name === 'JsonWebTokenError') return { ok: false, error: 'invalid-signature' };
    return { ok: false, error: 'unknown' };
  }
}

export const JWT_CONFIG = {
  ACCESS_TOKEN_TTL_SECONDS,
} as const;

/**
 * Authentication module — password hashing, token generation, middleware.
 *
 * Uses Node's built-in crypto.scrypt for password hashing (no external deps).
 * Tokens are random hex strings stored in the api_tokens table.
 *
 * Auth is OPTIONAL — if no users exist in the DB, all requests pass through
 * (single-user mode). Once the first user is created, auth is enforced.
 */
import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import {
  getUserById,
  getUserByUsername,
  getApiTokenByValue,
  countUsers,
  createUser,
  updateUser,
  type UserRow,
} from '../db.js';
import { verifyAccessToken } from './jwt.js';

// ── Password hashing ───────────────────────────────────────────────────────

const SALT_LEN = 32;
const KEY_LEN = 64;

export function hashPassword(password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(SALT_LEN).toString('hex');
    crypto.scrypt(password, salt, KEY_LEN, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(`${salt}:${derivedKey.toString('hex')}`);
    });
  });
}

export function verifyPassword(password: string, stored: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const [salt, hash] = stored.split(':');
    if (!salt || !hash) { resolve(false); return; }
    crypto.scrypt(password, salt, KEY_LEN, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey.toString('hex') === hash);
    });
  });
}

// ── Token generation ───────────────────────────────────────────────────────

export function generateToken(): string {
  return `vf_${crypto.randomBytes(32).toString('hex')}`;
}

// ── Auth middleware ────────────────────────────────────────────────────────

/**
 * Legacy name kept for backward compatibility with phase 14/15 routes.
 * Delegates to the Express Request augmentation in server/auth/middleware.ts
 * (`AuthedUser` shape) — `username` and `device_id` are optional there
 * because the JWT-session flow and the API-token flow populate different
 * fields. Routes that read `req.user.username` must `?? ''` or guard.
 */
export type AuthenticatedRequest = Request;

/**
 * Auth middleware — checks for Bearer token or session.
 * If no users exist (fresh install), all requests pass through.
 *
 * Bearer token resolution order (added subsystem B13.4):
 *   1. JWT access token (signed by server/auth/jwt.ts)
 *   2. Long-lived API token (legacy api_tokens row)
 *   3. Fall through to anonymous viewer
 *
 * This order matters because JWT tokens and API tokens share the same
 * `Authorization: Bearer <...>` header slot. JWTs are always 3 dot-separated
 * base64url segments and far longer than `vf_<hex>` tokens, so there's no
 * ambiguity in practice.
 */
export function authMiddleware(req: AuthenticatedRequest, _res: Response, next: NextFunction): void {
  // Skip auth if no users configured (single-user mode)
  try {
    const userCount = countUsers();
    if (userCount === 0) {
      req.user = { id: 0, username: 'local', role: 'admin' };
      return next();
    }
  } catch {
    return next(); // DB not ready yet
  }

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7);

    // 1. Try JWT first (new session flow).
    try {
      const result = verifyAccessToken(token);
      if (result.ok && result.claims) {
        const user = getUserById(result.claims.sub);
        if (user) {
          req.user = { id: user.id!, username: user.username, role: user.role };
          return next();
        }
      }
    } catch { /* fall through to API-token path */ }

    // 2. Try legacy API token row.
    const tokenRow = getApiTokenByValue(token);
    if (tokenRow) {
      if (!tokenRow.expires_at || new Date(tokenRow.expires_at) >= new Date()) {
        req.user = { id: tokenRow.user_id, username: tokenRow.username, role: tokenRow.role };
        return next();
      }
    }
  }

  // No valid auth — allow read-only anonymous; write routes gate via RBAC.
  req.user = { id: 0, username: 'anonymous', role: 'viewer' };
  next();
}

/**
 * Role guard — use after authMiddleware to require a minimum role.
 */
export function requireRole(...roles: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }
    next();
  };
}

// ── Login / initial setup ──────────────────────────────────────────────────

export async function login(username: string, password: string): Promise<UserRow | null> {
  const user = getUserByUsername(username);
  if (!user || !user.active) return null;

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) return null;

  // Update last_login
  updateUser(user.id!, { last_login: new Date().toISOString() } as any);
  return user;
}

/**
 * Create the initial admin user if no users exist.
 * Called from the setup endpoint or installer.
 */
export async function setupInitialUser(username: string, password: string): Promise<UserRow | null> {
  if (countUsers() > 0) return null; // Already set up

  const hash = await hashPassword(password);
  const id = createUser({
    username,
    password_hash: hash,
    role: 'admin',
    display_name: username,
  });

  return getUserByUsername(username);
}

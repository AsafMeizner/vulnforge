/**
 * Authentication module - password hashing, token generation, middleware.
 *
 * Uses Node's built-in crypto.scrypt for password hashing (no external deps).
 * Tokens are random hex strings stored in the api_tokens table.
 *
 * Auth is OPTIONAL - if no users exist in the DB, all requests pass through
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
      if (err) return reject(err);
      // timingSafeEqual prevents timing-attack-driven hash recovery
      // at the local-process level. The string `===` comparison that
      // was here leaked byte position via short-circuit evaluation;
      // scrypt's own running time dominates at the network layer but
      // not for a colocated-tenant attacker.
      let expected: Buffer;
      try {
        expected = Buffer.from(hash, 'hex');
      } catch {
        return resolve(false);
      }
      if (expected.length !== derivedKey.length) return resolve(false);
      resolve(crypto.timingSafeEqual(derivedKey, expected));
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
 * (`AuthedUser` shape) - `username` and `device_id` are optional there
 * because the JWT-session flow and the API-token flow populate different
 * fields. Routes that read `req.user.username` must `?? ''` or guard.
 */
export type AuthenticatedRequest = Request;

/**
 * Auth middleware - checks for Bearer token or session.
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
// Paths that are intentionally unauthenticated. Everything else
// (including /api/*, /mcp, /ws) requires a valid token or the mode
// gate below. Keep this list tight — anything added here is exposed
// to the network without auth.
const PUBLIC_PATH_PREFIXES = [
  '/api/health',
  '/api/config',
  '/api/auth/login',
  '/api/auth/setup',
  '/api/auth-session/login',
  '/api/auth-session/refresh',
  '/api/auth-session/bootstrap',   // one-time setup token
  '/api/auth-oidc',                // OIDC discovery + callback
] as const;

/**
 * "Desktop mode" - single-user local-loopback install. Detected from
 * the host binding: when we're pinned to 127.0.0.1 / ::1 the user is
 * physically at the machine, nobody else can reach us, and the
 * historical "no users = skip auth" convenience is acceptable.
 *
 * "Server mode" is everything else (0.0.0.0, custom interface) and
 * MUST have a seeded admin. The previous code's "empty users table =
 * admin" shortcut (CR-02) meant a freshly-bootstrapped server
 * deployment accepted every anonymous request as admin, which is a
 * catastrophic default. Now that shortcut only applies when the
 * binding proves we're local.
 *
 * Delegates to the canonical helper in server/deployment/mode.ts -
 * previously this file had its own host-based version that disagreed
 * with the canonical one under Electron's forked-Node child (Electron
 * forks with VULNFORGE_HOST=127.0.0.1 but without
 * process.versions.electron), so auth.ts said "desktop" while
 * lib/net.ts said "server" and Ollama silently stopped working.
 */
import { isDesktopMode as modeIsDesktop } from '../deployment/mode.js';
function isDesktopMode(): boolean {
  return modeIsDesktop();
}

function isPublicPath(p: string): boolean {
  for (const prefix of PUBLIC_PATH_PREFIXES) {
    if (p === prefix || p.startsWith(prefix + '/') || p.startsWith(prefix + '?')) {
      return true;
    }
  }
  return false;
}

export function authMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  // Public routes skip auth entirely. Do this BEFORE touching the DB
  // so startup can serve /health before the users table is created.
  if (isPublicPath(req.path)) return next();

  // Desktop-mode empty-users shortcut. Only allowed when bound to
  // loopback (isDesktopMode). Server mode refuses until setup runs
  // (CR-02). Wrapped in try because authMiddleware may fire before
  // initDb() on the very first request.
  try {
    const userCount = countUsers();
    if (userCount === 0) {
      if (isDesktopMode()) {
        req.user = { id: 0, username: 'local', role: 'admin' };
        return next();
      }
      // Server mode + no users = not bootstrapped. Refuse with a
      // clear message so the operator knows to run setup.
      res.status(503).json({
        error: 'Server not bootstrapped. Run setup on this host first, or set VULNFORGE_HOST=127.0.0.1 for single-user mode.',
      });
      return;
    }
  } catch {
    // DB not ready yet - let the handler decide. The handler itself
    // will fail with a clear error instead of granting admin.
    return next();
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

  // CR-01 fix: invalid/missing auth no longer falls through to an
  // "anonymous viewer". Return 401 so every request is either
  // authenticated or visibly rejected. Routes that truly need
  // unauthenticated access go on the PUBLIC_PATH_PREFIXES allowlist.
  res.status(401).json({ error: 'Authentication required' });
}

/**
 * Role guard - use after authMiddleware to require a minimum role.
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

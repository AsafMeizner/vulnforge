/**
 * Auth middleware — JWT verification, user attachment, solo-mode short-circuit.
 *
 * Exported variants:
 *   requireAuth      — 401 if no/invalid token
 *   optionalAuth     — attaches req.user if present, never blocks
 *   soloModeBypass   — attaches a synthetic admin user (id=1) and moves on
 *
 * The auth stack picks a variant at mount time based on deployment mode:
 *   VULNFORGE_MODE=server → requireAuth on all /api routes
 *   desktop solo          → soloModeBypass (always-admin)
 *   desktop team          → requireAuth
 */
import type { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from './jwt.js';

/**
 * Union-shape user object attached to req.user by any auth path.
 * `device_id` is present on JWT-session flow (subsystem B13.4) but absent
 * from the legacy phase 14/15 API-token flow; `username` is the opposite.
 * Keeping both optional means one augmentation works for both middlewares.
 */
export interface AuthedUser {
  id: number;
  role: string;
  device_id?: string;
  username?: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthedUser;
    }
  }
}

function extractBearer(req: Request): string | null {
  const h = req.headers.authorization;
  if (typeof h !== 'string') return null;
  if (!h.toLowerCase().startsWith('bearer ')) return null;
  return h.slice(7).trim() || null;
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = extractBearer(req);
  if (!token) {
    res.status(401).json({ error: 'missing bearer token' });
    return;
  }
  const result = verifyAccessToken(token);
  if (!result.ok || !result.claims) {
    res.status(401).json({ error: `invalid token: ${result.error ?? 'unknown'}` });
    return;
  }
  req.user = {
    id: result.claims.sub,
    role: result.claims.role,
    device_id: result.claims.device_id,
  };
  next();
}

export function optionalAuth(req: Request, _res: Response, next: NextFunction): void {
  const token = extractBearer(req);
  if (!token) return next();
  const result = verifyAccessToken(token);
  if (result.ok && result.claims) {
    req.user = {
      id: result.claims.sub,
      role: result.claims.role,
      device_id: result.claims.device_id,
    };
  }
  next();
}

/**
 * Solo-mode pass-through. Desktop in solo mode has no network auth but still
 * runs route permission checks — this hands those checks a synthetic admin
 * user so they uniformly succeed.
 */
export function soloModeBypass(req: Request, _res: Response, next: NextFunction): void {
  req.user = { id: 1, role: 'admin', device_id: 'solo' };
  next();
}

/**
 * Choose the right middleware for the current deployment mode.
 * Reads env + settings at call time so tests can flip it.
 */
export function pickAuthMiddleware(opts: { mode: 'server' | 'desktop'; clientMode?: 'solo' | 'team' }) {
  if (opts.mode === 'server') return requireAuth;
  if (opts.mode === 'desktop' && opts.clientMode === 'team') return requireAuth;
  // desktop + solo (or unset clientMode)
  return soloModeBypass;
}

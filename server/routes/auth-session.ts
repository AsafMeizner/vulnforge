/**
 * Session-based auth — JWT access tokens + rotating refresh tokens.
 *
 * Mounted at /api/session/* to coexist with the legacy /api/auth/*
 * API-token flow from phase 14/15.
 *
 *   POST /api/session/login      — password → access+refresh+device_id
 *   POST /api/session/refresh    — rotate refresh; returns new pair
 *   POST /api/session/logout     — revoke device's refresh tokens
 *   POST /api/session/bootstrap  — first-admin setup on fresh server install
 *   GET  /api/session/me         — whoami (requires access token)
 *
 * Verifies existing scrypt password hashes transparently and upgrades
 * them to bcrypt on successful login (see verifyPasswordAny).
 */
import { Router, type Request, type Response } from 'express';

import {
  getUserByUsername,
  getUserById,
  createUser,
  updateUser,
  updateUserPassword,
  countUsers,
  insertRefreshToken,
  getRefreshTokensForDevice,
  markRefreshTokenUsed,
  revokeRefreshToken,
  revokeAllRefreshTokensForDevice,
  type UserRow,
  type RefreshTokenRow,
} from '../db.js';
import {
  hashPassword as hashBcrypt,
  verifyPasswordAny,
} from '../auth/passwords.js';
import { signAccessToken, JWT_CONFIG } from '../auth/jwt.js';
import {
  mintRefreshToken,
  mintDeviceId,
  hashRefreshToken,
  verifyRefreshToken,
  evaluateRefreshRow,
  REFRESH_TTL_MS,
} from '../auth/refresh.js';

const router = Router();

// ── helpers ────────────────────────────────────────────────────────────────

function sanitizeUser(u: UserRow) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    display_name: u.display_name,
    email: u.email,
  };
}

async function issueTokenPair(user: UserRow, device_id: string, device_name: string) {
  if (typeof user.id !== 'number') throw new Error('issueTokenPair: user.id required');
  const { raw, expires_at } = mintRefreshToken();
  const token_hash = await hashRefreshToken(raw);
  insertRefreshToken({
    user_id: user.id,
    token_hash,
    device_id,
    device_name,
    expires_at,
    revoked: 0,
    created_at: Date.now(),
    last_used_at: null,
  });
  return {
    access_token: signAccessToken({ sub: user.id, role: user.role, device_id }),
    refresh_token: raw,
    expires_in: JWT_CONFIG.ACCESS_TOKEN_TTL_SECONDS,
    user: sanitizeUser(user),
  };
}

// ── POST /login ────────────────────────────────────────────────────────────

router.post('/login', async (req: Request, res: Response) => {
  try {
    const { username, password, device_name } = req.body ?? {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'username + password required' });
    }
    const user = getUserByUsername(username);
    if (!user || !user.id) {
      return res.status(401).json({ error: 'invalid credentials' });
    }
    const result = await verifyPasswordAny(password, user.password_hash);
    if (!result.ok) {
      return res.status(401).json({ error: 'invalid credentials' });
    }
    if (user.active === 0) {
      return res.status(403).json({ error: 'account disabled' });
    }

    // Transparent upgrade from scrypt → bcrypt.
    if (result.needs_upgrade) {
      try {
        const newHash = await hashBcrypt(password);
        updateUserPassword(user.id, newHash);
      } catch { /* non-fatal — user can log in now, upgrade next time */ }
    }

    const device_id = mintDeviceId();
    const pair = await issueTokenPair(user, device_id, String(device_name || 'Unknown device'));
    updateUser(user.id, { last_login: new Date().toISOString() });
    res.json({ ...pair, device_id });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /refresh ──────────────────────────────────────────────────────────

router.post('/refresh', async (req: Request, res: Response) => {
  try {
    const { refresh_token, device_id } = req.body ?? {};
    if (typeof refresh_token !== 'string' || typeof device_id !== 'string') {
      return res.status(400).json({ error: 'refresh_token + device_id required' });
    }

    const rows = getRefreshTokensForDevice(device_id);
    let matched: RefreshTokenRow | null = null;
    for (const row of rows) {
      if (await verifyRefreshToken(refresh_token, row.token_hash)) {
        matched = row;
        break;
      }
    }

    const outcome = evaluateRefreshRow(matched);
    if (outcome === 'not-found' || !matched) {
      revokeAllRefreshTokensForDevice(device_id);
      return res.status(401).json({ error: 'refresh token invalid', code: 'REPLAY_OR_MISSING' });
    }
    if (outcome === 'revoked') return res.status(401).json({ error: 'refresh token revoked', code: 'REVOKED' });
    if (outcome === 'expired') return res.status(401).json({ error: 'refresh token expired', code: 'EXPIRED' });

    const user = getUserById(matched.user_id);
    if (!user || !user.id) return res.status(401).json({ error: 'user not found' });

    revokeRefreshToken(matched.id!);
    markRefreshTokenUsed(matched.id!, Date.now());
    const pair = await issueTokenPair(user, matched.device_id, matched.device_name);
    res.json({ ...pair, device_id: matched.device_id });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /logout ───────────────────────────────────────────────────────────

router.post('/logout', (req: Request, res: Response) => {
  try {
    const { device_id } = req.body ?? {};
    if (typeof device_id !== 'string' || device_id.length === 0) {
      return res.status(400).json({ error: 'device_id required' });
    }
    revokeAllRefreshTokensForDevice(device_id);
    res.json({ ok: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST /bootstrap ────────────────────────────────────────────────────────
// First-admin setup on a fresh server install. Gated by a one-time token
// the installer prints to stdout and sets in process.env. Cleared on use.

router.post('/bootstrap', async (req: Request, res: Response) => {
  try {
    if (countUsers() > 0) {
      return res.status(409).json({ error: 'bootstrap already complete', code: 'ALREADY_BOOTSTRAPPED' });
    }
    const expected = process.env.VULNFORGE_BOOTSTRAP_TOKEN;
    if (!expected) {
      return res.status(503).json({ error: 'bootstrap not enabled; set VULNFORGE_BOOTSTRAP_TOKEN' });
    }
    const { bootstrap_token, username, password, email, display_name } = req.body ?? {};
    if (bootstrap_token !== expected) {
      return res.status(401).json({ error: 'invalid bootstrap token' });
    }
    if (typeof username !== 'string' || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'username + password(>=8) required' });
    }
    const password_hash = await hashBcrypt(password);
    const id = createUser({
      username,
      password_hash,
      role: 'admin',
      email: String(email || ''),
      display_name: String(display_name || username),
      active: 1,
    });
    const user = getUserById(id);
    if (!user) return res.status(500).json({ error: 'user create failed' });

    delete process.env.VULNFORGE_BOOTSTRAP_TOKEN;

    const device_id = mintDeviceId();
    const pair = await issueTokenPair(user, device_id, 'bootstrap');
    res.json({ ...pair, device_id });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET /me ────────────────────────────────────────────────────────────────
// Mount this one behind the auth middleware.

router.get('/me', (req: Request, res: Response) => {
  if (!req.user) return res.status(401).json({ error: 'not authenticated' });
  const user = getUserById(req.user.id);
  if (!user) return res.status(404).json({ error: 'user not found' });
  res.json({ ...sanitizeUser(user), device_id: req.user.device_id ?? null });
});

export default router;
export const sessionConfig = {
  refresh_ttl_ms: REFRESH_TTL_MS,
  access_ttl_s: JWT_CONFIG.ACCESS_TOKEN_TTL_SECONDS,
};

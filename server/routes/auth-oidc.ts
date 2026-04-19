/**
 * OIDC HTTP routes - SSO flow for team-server logins.
 *
 * Mounted at /api/auth/oidc/*. Disabled unless `isOidcEnabled()` returns
 * true (check happens per-request so admin can toggle without restart).
 *
 *   GET  /api/auth/oidc                      list configured providers (name only)
 *   GET  /api/auth/oidc/:name/start          302 to IdP authorize endpoint
 *   GET  /api/auth/oidc/:name/callback       IdP redirects here; renders paste page
 *   POST /api/auth/oidc/exchange             desktop trades one-time code for JWT pair
 */
import { Router, type Request, type Response, NextFunction } from 'express';

import {
  isOidcEnabled,
  getOidcProvider,
  listOidcProviders,
  buildAuthorizeUrl,
  handleCallback,
  consumeOneTimeCode,
  mapRoleFromProvider,
} from '../auth/oidc.js';
import {
  getUserByUsername,
  getUserById,
  createUser,
  insertRefreshToken,
  type UserRow,
} from '../db.js';
import { hashPassword } from '../auth/passwords.js';
import { signAccessToken, JWT_CONFIG } from '../auth/jwt.js';
import {
  mintRefreshToken,
  mintDeviceId,
  hashRefreshToken,
} from '../auth/refresh.js';

const router = Router();

function guardEnabled(res: Response): boolean {
  if (!isOidcEnabled()) {
    res.status(503).json({ error: 'OIDC disabled on this server', code: 'OIDC_DISABLED' });
    return false;
  }
  return true;
}

function redirectUriFor(req: Request, name: string): string {
  const publicUrl = process.env.VULNFORGE_PUBLIC_URL || `${req.protocol}://${req.get('host')}`;
  return `${publicUrl.replace(/\/$/, '')}/api/auth/oidc/${encodeURIComponent(name)}/callback`;
}

// ── List providers ─────────────────────────────────────────────────────────

router.get('/', (_req: Request, res: Response, next: NextFunction) => {
  if (!isOidcEnabled()) return res.json({ providers: [], enabled: false });
  const providers = listOidcProviders().map(p => ({ name: p.name, enabled: !!p.enabled }));
  res.json({ providers, enabled: true });
});

// ── Start flow ─────────────────────────────────────────────────────────────

router.get('/:name/start', async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!guardEnabled(res)) return;
    const { name } = req.params;
    const provider = getOidcProvider(String(name));
    if (!provider) return res.status(404).json({ error: `unknown provider: ${name}` });
    const url = await buildAuthorizeUrl(provider, redirectUriFor(req, String(name)));
    res.redirect(302, url);
  } catch (err: any) {
    next(err);
  }
});

// ── Callback ───────────────────────────────────────────────────────────────

router.get('/:name/callback', async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!guardEnabled(res)) return;
    const { name } = req.params;
    const { code, state, error } = req.query as Record<string, string | undefined>;
    if (error) {
      return res.status(400).send(renderError(`provider returned error: ${error}`));
    }
    if (!code || !state) {
      return res.status(400).send(renderError('missing code or state'));
    }
    const outcome = await handleCallback(
      String(name),
      redirectUriFor(req, String(name)),
      String(code),
      String(state),
    );
    if (outcome.ok === false) return res.status(400).send(renderError(outcome.error));

    // Render a tiny HTML page telling the user to paste the code into their desktop.
    res.type('html').send(renderPastePage(outcome.one_time_code, outcome.email));
  } catch (err: any) {
    res.status(500).send(renderError(err.message));
  }
});

// ── Exchange ───────────────────────────────────────────────────────────────

router.post('/exchange', async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!guardEnabled(res)) return;
    const { one_time_code, device_name } = req.body ?? {};
    if (typeof one_time_code !== 'string') {
      return res.status(400).json({ error: 'one_time_code required' });
    }
    const rec = consumeOneTimeCode(one_time_code);
    if (!rec) return res.status(401).json({ error: 'invalid or expired code' });

    const provider = getOidcProvider(rec.provider_name);
    if (!provider) return res.status(404).json({ error: 'provider disappeared' });

    // Look up or create the user.
    const username = rec.upstream_email || `${rec.provider_name}:${rec.upstream_sub}`;
    let user: UserRow | null = getUserByUsername(username);
    if (!user) {
      // Synthesize a random bcrypt hash - user never uses password login.
      const randomPw = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
      const password_hash = await hashPassword(randomPw + 'OidcOnlyAccount!');
      const role = mapRoleFromProvider(provider, rec.upstream_email, []);
      const id = createUser({
        username,
        password_hash,
        role: role as any,
        email: rec.upstream_email || '',
        display_name: rec.upstream_email?.split('@')[0] || username,
        active: 1,
      });
      user = getUserById(id);
    }
    if (!user || !user.id) return res.status(500).json({ error: 'user create failed' });

    const device_id = mintDeviceId();
    const pair = mintRefreshToken();
    const token_hash = await hashRefreshToken(pair.raw);
    insertRefreshToken({
      user_id: user.id,
      token_hash,
      device_id,
      device_name: String(device_name || 'SSO login'),
      expires_at: pair.expires_at,
      revoked: 0,
      created_at: Date.now(),
      last_used_at: null,
    });
    const access_token = signAccessToken({ sub: user.id, role: user.role, device_id });
    res.json({
      access_token,
      refresh_token: pair.raw,
      expires_in: JWT_CONFIG.ACCESS_TOKEN_TTL_SECONDS,
      device_id,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        display_name: user.display_name,
        email: user.email,
      },
    });
  } catch (err: any) {
    next(err);
  }
});

// ── Paste page HTML ────────────────────────────────────────────────────────

function renderPastePage(oneTimeCode: string, email: string | null): string {
  const safeCode = oneTimeCode.replace(/[<>"']/g, '');
  const safeEmail = email ? email.replace(/[<>"']/g, '') : '';
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>VulnForge - Sign-in complete</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 560px;
         margin: 80px auto; padding: 0 16px; line-height: 1.5; color: #222; }
  h1 { font-size: 22px; }
  .code { font-family: ui-monospace, monospace; font-size: 18px;
          background: #f5f5f5; border: 1px solid #ddd; border-radius: 6px;
          padding: 12px 16px; user-select: all; word-break: break-all; }
  p { color: #555; }
  .hint { font-size: 14px; margin-top: 24px; color: #888; }
</style></head>
<body>
  <h1>Signed in${safeEmail ? ' as ' + safeEmail : ''}</h1>
  <p>Copy the one-time code below and paste it back into the VulnForge desktop app.</p>
  <div class="code" id="code">${safeCode}</div>
  <p class="hint">This code expires in 2 minutes and can be used exactly once.</p>
</body></html>`;
}

function renderError(msg: string): string {
  const safe = msg.replace(/[<>"']/g, '');
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>VulnForge - Sign-in error</title>
<style>body{font-family:system-ui;max-width:560px;margin:80px auto;padding:0 16px}
.err{background:#fff5f5;border:1px solid #fcc;color:#900;padding:12px 16px;border-radius:6px}</style>
</head><body><h1>Sign-in failed</h1><div class="err">${safe}</div></body></html>`;
}

export default router;

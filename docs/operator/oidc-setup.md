# OIDC / SSO setup

VulnForge supports login via any OpenID Connect identity provider in addition to local password accounts. Configure providers from the admin UI (Settings → Deployment → Identity Providers) or by inserting rows into the `oidc_providers` table directly.

Examples for the most common providers below. The flow itself is standard PKCE-enhanced authorization code.

## Google

1. In Google Cloud Console → APIs & Services → Credentials → Create OAuth Client ID → "Web application".
2. Authorized redirect URI: `https://<your-server>/api/auth/oidc/google/callback`.
3. Save the client ID + secret.
4. In VulnForge admin UI, add provider:
   - name: `google`
   - issuer_url: `https://accounts.google.com`
   - scopes: `openid email profile`

## GitHub

GitHub's OAuth is OAuth 2.0, not strictly OIDC, so the adapter uses the legacy OAuth flow plus a `/user` profile fetch.

1. GitHub → Settings → Developer settings → OAuth Apps → New.
2. Callback URL: `https://<your-server>/api/auth/oidc/github/callback`.
3. In VulnForge, add provider:
   - name: `github`
   - issuer_url: `https://github.com` (adapter recognizes this specially)
   - scopes: `read:user user:email`

## Okta

1. Okta admin → Applications → Create App Integration → OIDC → Web Application.
2. Sign-in redirect URI: `https://<your-server>/api/auth/oidc/okta/callback`.
3. Sign-out redirect URI: `https://<your-server>/`.
4. In VulnForge:
   - name: `okta`
   - issuer_url: `https://<your-okta-domain>/oauth2/default`
   - scopes: `openid email profile groups`

## Role mapping

Every provider row has a `role_mapping_json` field — maps upstream `groups` (or email domain) to VulnForge roles.

```json
{
  "email_domain": {
    "acme.corp": "researcher"
  },
  "groups": {
    "vuln-admins": "admin",
    "vuln-team":   "researcher"
  },
  "default": "viewer"
}
```

On callback, VulnForge checks `groups` first, then `email_domain`, then `default`. Users without a mapping default to `viewer` (read-only) — always safer than admin-by-default.

## Desktop login flow

The desktop opens the system browser for the OIDC dance (never an embedded webview — safer, respects SSO cookies). Server's callback displays a one-time code, user pastes into desktop, desktop exchanges via `POST /api/auth/oidc/exchange` for the JWT pair.

## Disabling password login

Once OIDC is set up and tested, you can disable the local password flow: set `settings.allow_password_login=false`. The `/api/session/login` endpoint then returns `403 password auth disabled`.

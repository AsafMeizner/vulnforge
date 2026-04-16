# Secret handling

## Where secrets live

| Secret | Location | Format |
|---|---|---|
| JWT signing secret | `/var/lib/vulnforge/.env::VULNFORGE_JWT_SECRET` | Base64, 48 bytes of entropy |
| Bootstrap token | `.env::VULNFORGE_BOOTSTRAP_TOKEN` (one-time) | Hex, 24 bytes |
| User password hashes | `users.password_hash` DB column | `$2a$12$...` bcrypt |
| Refresh token hashes | `refresh_tokens.token_hash` | `$2a$06$...` bcrypt (raw token has 256 bits of entropy so cost 6 is enough) |
| OIDC client secrets | `oidc_providers.client_secret` | Plain TEXT — protect the DB file |
| Integration tokens | `integrations.config` JSON field | Plain TEXT |
| AI provider API keys | `ai_providers.config` JSON field | Plain TEXT |

The DB file is the secondary trust boundary: anything inside must be treated as sensitive. File permissions on `/var/lib/vulnforge/vulnforge.db` should be `600` owned by the service user.

## Rotation procedures

### JWT signing secret

Rotating invalidates every outstanding access + refresh token instantly. Every user has to log back in.

```bash
# 1. Generate new secret
NEW=$(openssl rand -base64 48)

# 2. Update env
sudo sed -i "s|^VULNFORGE_JWT_SECRET=.*|VULNFORGE_JWT_SECRET=$NEW|" /var/lib/vulnforge/.env

# 3. Restart
sudo systemctl restart vulnforge-server
```

Schedule: annually, or immediately on suspected compromise.

### OIDC client secret

From IdP admin UI → regenerate client secret → update the matching row in `oidc_providers.client_secret` (via admin UI or direct SQL). Restart not required — secret is read per-request.

### Integration tokens

Per-integration rotation. In VulnForge admin UI → Integrations → pick one → click "Rotate token" → paste new upstream-provided token. Old one is discarded.

### User password

Users rotate their own via Profile → Change password. Admin can force-reset by setting `users.password_hash` to a bcrypt hash of a temporary password and setting `users.must_change_password=1` (flag added per phase 14 plan).

### Leaked refresh token

```sql
-- Revoke all active refresh tokens for a user
UPDATE refresh_tokens SET revoked = 1 WHERE user_id = 42;
```

Or via admin UI → Users → pick user → "Sign out all devices". User gets a fresh login prompt on all their desktops.

## What NEVER gets logged

- Raw passwords (hashed before any log touches them).
- Raw refresh tokens (only hashes are stored; the raw value appears in responses only).
- JWT signing secret.
- OIDC client secrets, integration API keys.
- Bootstrap token after it's been consumed.

The logging surface is deliberately narrow. `console.log` + `console.error` at `info` level include request paths, status codes, user ids, and ms timings — never request bodies or response bodies.

## Bootstrap token single-use enforcement

`/api/session/bootstrap` consumes the token by calling `delete process.env.VULNFORGE_BOOTSTRAP_TOKEN` after successful admin creation. A second POST returns 409 "already bootstrapped". Admin still needs to remove the token from the `.env` file (not done automatically because the server shouldn't edit its own config file).

## Environment file discipline

- Perms: `600` (rw owner only).
- Ownership: service user (`vulnforge`).
- Never in git: `.env` is `.gitignored`; `.env.server.example` contains only placeholders.
- Never in logs, crash dumps, or debug output.

# Threat model

VulnForge is a security research tool. Users trust it with sensitive findings, exploit code, and vendor communications. The threat model below guides every security decision.

## Trust boundaries

| Boundary | Model |
|---|---|
| Desktop process ↔ user | Full trust. The user runs the code. |
| Desktop ↔ team server | Mutual authentication via JWT. Server is trusted to enforce RBAC. Clients are NOT trusted to enforce scope. |
| Team server ↔ other team members' desktops | Authenticated + authorized by role. Server mediates all cross-member visibility. |
| Team server ↔ public internet | Hostile. TLS via reverse proxy (nginx). JWT is the only auth mechanism. |
| Server-proxied AI / integration endpoints ↔ upstream (OpenAI, Jira, Slack) | Server holds creds; clients never see them. Upstream response treated as untrusted input. |
| Pool-scope data ↔ other organizations | Anonymized before submission. Server anonymizes, not client (defense in depth). |
| Plugin binaries on disk ↔ running process | Plugins are code execution. Admins must vet plugins before installing. |

## Attacker personas

### 1. Compromised user account

*Assumption*: attacker has access to one team member's desktop/device.

Mitigations:
- Refresh tokens bound to `device_id`; admin UI shows logged-in devices and allows remote revocation.
- Rotating refresh tokens: replay of an old token revokes the whole device session.
- Per-role RBAC: a `viewer` account can't delete things or exfiltrate by modification.
- Access token 15-minute TTL: a leaked access token stops working quickly.

Not mitigated:
- A live-compromised desktop can read `private`-scoped data. This is by design — the private scope is not meant to survive device compromise.

### 2. Malicious insider with admin access

*Assumption*: a legitimate admin acts in bad faith.

Mitigations:
- Audit log records every admin action (role changes, permission grants, refresh-token revocations).
- Per-role permissions are granular — use `researcher` for normal operators, `admin` only for ops.
- Logs can be shipped to external SIEM (operator choice — not built-in).

Not mitigated:
- Admin can change anyone's role, including their own. Defense: multiple admins + audit review.

### 3. External attacker, no credentials

*Assumption*: attacker can reach the server's public endpoint.

Mitigations:
- Every non-bootstrap endpoint requires a valid JWT.
- Login rate limit (50 attempts/minute per IP — enforced via `express-rate-limit` in production).
- bcrypt cost 12 makes password cracking expensive.
- WebSocket auth via token validation on upgrade — no unauthenticated upgrades.
- CORS restricted to the server's public URL.
- Sync transport explicitly excludes `UNSYNCABLE_TABLES` regardless of request.

### 4. Compromised AI provider or integration

*Assumption*: the upstream Jira/Slack/OpenAI endpoint is malicious or compromised.

Mitigations:
- AI responses are treated as untrusted input. Prompts include "response is suggested patch, not ground truth" framing.
- Integration webhooks are validated against a signing secret per provider.
- Integration tokens stored server-side (team mode) or per-user (solo) — compromise of one doesn't expose others.

### 5. Supply-chain attack

*Assumption*: an npm package is compromised.

Mitigations:
- `package-lock.json` pins exact versions.
- Production image has no dev deps (multi-stage build).
- Server runs as non-root user with read-only system paths via systemd directives.

## Data classification

| Class | Examples | Storage |
|---|---|---|
| Secrets | JWT signing secret, OAuth client secrets, API tokens | Env file with 600 perms, never in DB, never logged |
| Credentials | User bcrypt hashes, refresh token bcrypt hashes | DB, never emitted |
| Private research | Rows tagged `sync_scope='private'` | Desktop SQLite only, never transmitted |
| Team research | Rows tagged `sync_scope='team'` | Team server + every member's desktop |
| Pool submissions | Rows tagged `sync_scope='pool'` | Anonymized server-side, published to pool |
| Audit events | Who did what | Append-only `audit_log`, optionally shipped externally |

## Secret handling

See [`secret-handling.md`](secret-handling.md) for rotation procedures.

## Sync-specific threats

See [`sync-security.md`](sync-security.md).

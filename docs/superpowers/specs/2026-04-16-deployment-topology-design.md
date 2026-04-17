# Subsystem B - Deployment Topology Design

**Date:** 2026-04-16
**Status:** Approved
**Supersedes:** N/A
**Depends on:** Phase 14/15 (user accounts + RBAC), Theme 1 (notes providers)

## 1. Purpose

Evolve VulnForge from a single-user desktop app into a dual-mode platform:

- **Solo mode** - one downloadable artifact; desktop runs frontend + Express backend + MCP + SQLite. No network required.
- **Team mode** - a separately-installable server that multiple desktops connect to. Desktops remain **local-first** (full local stack) and sync findings/projects/notes/settings to the team server.

One codebase produces three artifacts: desktop installer, server Docker image, bare server tarball. Mode is selected at install time and can be switched later from Settings.

## 2. Goals / Non-goals

**Goals**

- Single repository, single code body, two operational modes.
- Local-first UX - work fully offline in both modes.
- 3-tier data visibility: `private` / `team` / `pool`.
- Optional server-proxied capabilities (AI providers, integrations).
- Per-job scan execution choice: local desktop or server worker pool.
- Strong auth: bcrypt + optional OIDC; JWT with rotating refresh tokens.
- Documentation overhaul + operator install scripts.
- Local `todo/` folder convention for persistent, gitignored task tracking.

**Non-goals (explicitly deferred)**

- CRDT-based collaborative editing. Findings are not co-authored documents - last-write-wins is sufficient.
- Multi-server federation. One team ↔ one server.
- Built-in SCIM / automatic user provisioning. Admins invite manually or via OIDC just-in-time.
- Marketplace distribution - covered by subsystem C.
- AI memory backends (Notion, etc.) - covered by subsystem E.

## 3. Decisions (summarized from brainstorm)

| #   | Decision                                                      | Rationale                                                              |
| --- | ------------------------------------------------------------- | ---------------------------------------------------------------------- |
| 1   | Local-first + sync in team mode                               | Best UX; desktop already ships full stack; scans survive flaky network |
| 2   | Per-job executor choice (local or server)                     | Light scans on laptop, heavy scans on beefy server; user controls      |
| 3   | Bcrypt passwords + optional OIDC                              | Fast bootstrap; SSO for enterprises via standard OIDC config           |
| 4   | WS deltas + REST backfill                                     | Reuses existing WS infra; simple cursor-based backfill; REST fallback  |
| 5   | 3-tier scopes (`private`/`team`/`pool`) on every syncable row | Baked-in visibility avoids scattered permission checks                 |
| 6   | Server-proxied capabilities (AI + integrations)               | Company keys stay on server; clients see capability names only         |

## 4. Architecture

### 4.1 Modes

```
┌──────────────────────────────────────────────────────────┐
│ SOLO MODE                                                │
│                                                          │
│  Electron shell ← frontend ← Express ← SQLite            │
│                              ↑                           │
│                          MCP server                      │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ TEAM MODE (N desktops + 1 server)                        │
│                                                          │
│  Desktop A ←→ WS sync ↘                                  │
│  Desktop B ←→ WS sync  ─→  VulnForge Server              │
│  Desktop C ←→ WS sync ↗    (SQLite + worker pool         │
│                              + OIDC + RBAC)              │
│                                                          │
│  Each desktop keeps its own local SQLite + MCP.          │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Mode detection

`server/index.ts` branches on `process.env.VULNFORGE_MODE`:

- `desktop` (default if Electron parent detected): current behavior.
- `server`: skips Electron-specific init, enables worker pool, OIDC routes, multi-user features.
- `unset`: auto-detects based on parent process.

Client (desktop) mode is separate - stored in local `settings` table:

- `deployment_client_mode`: `solo` (no server config) or `team` (has `team_server_url`).

First-launch wizard sets this. Settings → Deployment can switch later.

### 4.3 One codebase, three artifacts

| Artifact            | Build command                 | Output                                    |
| ------------------- | ----------------------------- | ----------------------------------------- |
| Desktop installer   | `npm run build:desktop`       | `dist/VulnForge-Setup-*.exe` etc.         |
| Server Docker image | `npm run build:server:docker` | Multi-arch image `vulnforge/server:<ver>` |
| Server bare tarball | `npm run build:server:tar`    | `vulnforge-server-<ver>.tar.gz`           |

All three `import` the same `server/` TypeScript, compiled with different bundle entry points and packaging wrappers.

## 5. Data model changes

### 5.1 Three data categories

**Category A - Syncable (with 3-tier scope):**
`projects`, `vulnerabilities`, `scan_findings`, `pipeline_runs`, `notes`, `hypotheses`, `session_state`, `reports`, `checklists`, `checklist_items`, `scans`.

Every row in these tables gets the sync columns below.

**Category B - Strictly per-machine (never leave the device):**
`plugins_installed`, `notes_providers`, `settings` rows marked `local_only`, any table holding local filesystem paths, local API keys, refresh tokens, UI prefs.

Tracked by `UNSYNCABLE_TABLES` constant in `server/sync/model.ts`.

**Category C - Server-proxied capabilities:**
`ai_providers`, `integrations`. Exist on BOTH desktop and server independently. Server publishes a **capability manifest** to connected clients listing server-configured ones by name + capability, without secrets. Client UI shows both local and (if enabled) server capabilities in provider pickers.

### 5.2 Sync columns (added to each Category A table)

| Column                 | Type                              | Notes                                                                                                        |
| ---------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `sync_id`              | TEXT UNIQUE                       | ULID minted on desktop; canonical once server accepts                                                        |
| `sync_scope`           | TEXT NOT NULL DEFAULT `'private'` | `private` / `team` / `pool`. Named `sync_scope` (not `scope`) to avoid collision with `session_state.scope`. |
| `owner_user_id`        | INTEGER                           | Creator. In solo mode = single hardcoded user (id=1)                                                         |
| `updated_at_ms`        | INTEGER NOT NULL                  | ms epoch; client write clock                                                                                 |
| `server_updated_at_ms` | INTEGER                           | ms epoch; server write clock for ordering                                                                    |
| `tombstone`            | INTEGER NOT NULL DEFAULT 0        | 1 = soft-deleted, retained so deletion syncs                                                                 |
| `sync_status`          | TEXT NOT NULL DEFAULT `'local'`   | `local` / `pending` / `synced` / `conflict`                                                                  |

Migrations backfill existing rows with ULIDs, `Date.now()`, `sync_scope='private'`.

### 5.3 New tables

**`refresh_tokens`** - one row per logged-in device.

```
id INTEGER PK, user_id INT, token_hash TEXT UNIQUE, device_id TEXT,
device_name TEXT, expires_at INTEGER, revoked INTEGER DEFAULT 0,
created_at INTEGER, last_used_at INTEGER
```

**`oidc_providers`** (server only) - configured IdPs.

```
id INTEGER PK, name TEXT UNIQUE, issuer_url TEXT, client_id TEXT,
client_secret TEXT, scopes TEXT, role_mapping_json TEXT,
enabled INTEGER DEFAULT 1, created_at INTEGER
```

**`permissions`** - role-based ACL.

```
id INTEGER PK, role TEXT, resource TEXT, action TEXT,
UNIQUE(role, resource, action)
```

Seeded on bootstrap with defaults: `admin → *:*`, `analyst → findings:read/write pipelines:run integrations:use`, `viewer → *:read`.

**`pipeline_jobs`** (server only) - job queue for worker pool.

```
id INTEGER PK, sync_id TEXT UNIQUE, project_id INT, requested_by_user_id INT,
executor TEXT CHECK(executor IN ('local','server')),
status TEXT, priority INTEGER DEFAULT 5,
stages_json TEXT, worker_id TEXT,
queued_at INTEGER, claimed_at INTEGER, finished_at INTEGER, error TEXT
```

**`sync_outbox`** (client only) - pending pushes.

```
id INTEGER PK, table_name TEXT, sync_id TEXT, operation TEXT,
payload_json TEXT, attempts INTEGER DEFAULT 0, last_error TEXT,
created_at INTEGER
```

**`sync_cursors`** (client only) - last-pull state per table.

```
table_name TEXT PRIMARY KEY, cursor INTEGER NOT NULL
```

**`audit_log`** (server only) - auth and admin events.

```
id INTEGER PK, user_id INT, device_id TEXT, action TEXT,
target TEXT, metadata_json TEXT, created_at INTEGER
```

### 5.4 Settings keys (additions)

Stored in existing `settings` table, all marked `local_only`:

- `deployment_client_mode` - `solo` / `team`
- `team_server_url`
- `team_server_device_id`
- `team_server_device_name`
- `jwt_refresh_token` - encrypted via Electron `safeStorage`
- `default_row_scope` - default scope for new rows (`private` by default)

Server-side `settings`:

- `server_name`, `server_public_url`, `jwt_signing_secret` (generated on install), `allow_signup`, `allow_oidc_only`, `capability_manifest_enabled`.

## 6. Sync protocol

### 6.1 Transport

Primary: WebSocket at `wss://server/sync` with JWT in `Sec-WebSocket-Protocol`.
Fallback: REST `GET /api/sync/pull` and `POST /api/sync/push`. Same cursor semantics.

### 6.2 Messages (WS JSON envelopes)

| Direction | Type            | Body                                       |
| --------- | --------------- | ------------------------------------------ |
| S→C       | `capabilities`  | `{ai:[...], integrations:[...]}`           |
| C→S       | `sync:hello`    | `{cursors: {table: ms, ...}}`              |
| S→C       | `sync:batch`    | `{table, rows, next_cursor, done}`         |
| C→S       | `sync:ack`      | `{table, cursor}`                          |
| C→S       | `sync:push`     | `{table, rows}`                            |
| S→C       | `sync:accept`   | `{sync_ids: [ ...], server_updated_at_ms}` |
| S→C       | `sync:conflict` | `{table, sync_id, current_row}`            |
| S→C       | `sync:upsert`   | `{table, row}` (live)                      |
| S→C       | `sync:delete`   | `{table, sync_id}` (live)                  |
| any       | `ping` / `pong` | heartbeat                                  |

### 6.3 Cursor model

One cursor per Category A table, value = last seen `server_updated_at_ms` for that table. Stored in client's `sync_cursors`.

Client opens connection → sends `sync:hello` with all cursors → server streams all rows where `server_updated_at_ms > cursor` in batches of 200 → client ACKs after applying each batch → once all tables signal `done`, server transitions to live mode.

### 6.4 Conflict resolution

Server-clock last-write-wins:

- `incoming_updated_at_ms > existing.server_updated_at_ms` → accept, set `server_updated_at_ms = Date.now()`, broadcast upsert.
- Otherwise → reject, send `sync:conflict` with current server row. Client marks local `sync_status='conflict'` and surfaces a resolution UI (keep mine / keep theirs / merge fields).

Field-level merge whitelist (applied server-side before row-level check):

- `scan_findings.notes` - string concatenation with separator
- `vulnerabilities.status` - highest status wins (`accepted` > `investigating` > `open`)
- `checklist_items.checked` - OR merge

### 6.5 Tombstones

Delete = `UPDATE ... SET tombstone=1, updated_at_ms=now()`. Treated as an upsert in sync. GC removes tombstoned rows older than 30 days via daily sweep.

### 6.6 Offline and backpressure

Writes while disconnected → `sync_outbox`. Flushed in insertion order on reconnect. Exponential backoff per row (max 5 attempts before surfacing as error).

Client batches pushes in 100ms windows, ≤500 rows/batch.
Server paginates pulls at 200 rows/batch, waits for ACK before next.
Per-user rate limit: 50 writes/second.

### 6.7 Pool scope

Rows with `scope='pool'` go through `POST /api/pool/push` which:

1. Anonymizes per a `POOL_ANONYMIZE` map (per-table rules: strip `owner_user_id`, redact URLs to host+path, remove file paths that aren't known-OSS).
2. Inserts into server's pool tables (separate namespace, read-only to clients).
3. Pool pulls are snapshot-based, cached 1h, not live.

## 7. Authentication

### 7.1 Tokens

- **Access JWT** - 15-min TTL, HS256, claims `{user_id, role, scopes[], exp, device_id}`. Memory only on client.
- **Refresh token** - 30-day TTL, opaque 256-bit, hashed server-side in `refresh_tokens`. Rotated on every use.

### 7.2 Flows

| Flow                    | Endpoint                                                                                                              |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Password login          | `POST /api/auth/login` - `{email, password, device_name}` → access + refresh                                          |
| Refresh                 | `POST /api/auth/refresh` - `{refresh_token}` → new access + new refresh (old invalidated)                             |
| OIDC start              | `GET /api/auth/oidc/:provider/start` - 302 to IdP                                                                     |
| OIDC callback           | `GET /api/auth/oidc/:provider/callback` - exchanges code, creates/links user, returns one-time code for desktop paste |
| OIDC desktop exchange   | `POST /api/auth/oidc/exchange` - `{one_time_code}` → access + refresh                                                 |
| Logout                  | `POST /api/auth/logout` - revokes refresh token                                                                       |
| Bootstrap (first admin) | `POST /api/auth/bootstrap` - `{one_time_token, email, password}`                                                      |

### 7.3 Solo mode

Auth system present but short-circuited: `assertPermission()` middleware detects `VULNFORGE_MODE !== 'server'` + `deployment_client_mode = 'solo'` → always allow, hardcoded `req.user = {id: 1, role: 'admin'}`.

### 7.4 RBAC

`assertPermission(req, resource, action)` checks `permissions` table. Resources: `findings`, `projects`, `pipelines`, `integrations`, `ai`, `plugins`, `users`, `settings`. Actions: `read`, `write`, `delete`, `admin`.

## 8. Scan execution

### 8.1 Per-job routing

Pipeline runs carry `executor: 'local' | 'server'`.

- `local`: existing path - pipeline runs in the desktop's Express process.
- `server`: client `POST /api/pipelines/enqueue` with `executor='server'` → server inserts `pipeline_jobs` row → worker claims → runs → streams progress over WS to requesting client.

UI: run dropdown next to "Start" button. Hidden when no server capability.

### 8.2 Worker pool

Server spawns `N = max(1, cpu_count - 1)` worker processes at boot. Each worker polls `pipeline_jobs` via atomic claim (SQLite `BEGIN IMMEDIATE` + `UPDATE ... WHERE status='queued' AND worker_id IS NULL LIMIT 1 RETURNING`).

Queue fairness: per-user in-flight cap = `ceil(N / active_users)`.

Resource limits per job: 4GB RAM, 30-min wall time, configurable per project. Enforced via `ulimit` (unix) / Job Object (Windows).

### 8.3 Cancellation

Client `POST /api/pipelines/:id/cancel` → server marks job `cancelled` → worker checks signal between stages → cleans up working dir.

Existing pause/resume (obs 855) composes naturally: `paused` is a separate status, worker releases claim on pause, re-claims on resume.

## 9. Capability manifest

Server maintains a per-user-visible list of server-proxied capabilities.

On WS connect (after auth), server sends:

```json
{
  "type": "capabilities",
  "ai": [
    {
      "name": "team-triage",
      "task_tags": ["triage", "embed"],
      "provider_type": "ollama-proxied",
      "available": true
    }
  ],
  "integrations": [
    {
      "name": "team-jira",
      "type": "jira",
      "actions": ["create_ticket", "update_ticket", "comment"]
    }
  ]
}
```

Client shows these in AI routing + integrations pickers as `Server: team-triage` etc.

Invocation: `POST /api/server/ai/invoke` with `{capability, task, payload}` → server runs the AI call with its own creds, streams response back. Same shape for `POST /api/server/integrations/:name/:action`.

Admin toggles capability exposure via `capability_manifest_enabled` setting + per-role `ai`/`integrations` permissions.

## 10. Packaging & distribution

### 10.1 Desktop installer

`npm run build:desktop` → electron-builder produces `.exe` / `.dmg` / `.AppImage` in `dist/`.

First-launch wizard added to `src/pages/FirstLaunch.tsx`:

1. Solo vs Team radio
2. If Team: server URL + login form
3. Writes `deployment_client_mode`, `team_server_url` to settings
4. On success, moves to main app

### 10.2 Server Docker image

`Dockerfile.server` - multi-stage:

- Stage 1: node:20 + `npm ci` + `npm run build:server`
- Stage 2: node:20-slim + copy `dist-server/` + non-root user + volume `/data`

`docker-compose.server.yml` ships server + volume mount + optional nginx reverse proxy with Let's Encrypt.

Environment variables replace the interactive install wizard: `VULNFORGE_ADMIN_EMAIL`, `VULNFORGE_PUBLIC_URL`, `VULNFORGE_JWT_SECRET`, `VULNFORGE_DB_PATH=/data/vulnforge.db`, etc.

### 10.3 Bare server tarball

`npm run build:server:tar` → `tsc` → pack into `vulnforge-server-<ver>.tar.gz` containing `dist-server/`, `package.json` (prod deps only), `install-server.sh`, `install-server.ps1`, `scripts/migrate.mjs`, `scripts/bootstrap.mjs`, `systemd/vulnforge-server.service`.

`install-server.sh` steps:

1. Preflight: check Node 20+, Python 3.10+, git
2. Prompt: listen host/port, admin email, public URL, OIDC setup (y/n)
3. Generate JWT secret, write `.env`
4. `npm ci --omit=dev`
5. Create systemd unit / Windows service
6. Run `node scripts/bootstrap.mjs` → creates tables + prints one-time admin token
7. Start service, print success URL

Upgrade path: stop service → replace `dist-server/` → `node scripts/migrate.mjs` → start service.

### 10.4 Version compatibility

Client sends `X-VulnForge-Version` header on every request. Server rejects with `426 Upgrade Required` on major mismatch, adds `X-Upgrade-Advisory: true` on minor mismatch.

## 11. Documentation

### 11.1 README overhaul

Top-level `README.md` becomes a single-page router with 3 quick-start paths (solo, docker server, bare server) and links to `docs/`. Retains dev setup, architecture diagram, license.

### 11.2 `docs/` tree

```
docs/
  README.md
  architecture/
    overview.md
    deployment-topology.md
    sync-protocol.md
    data-model.md
    plugin-system.md            (placeholder)
    memory-backends.md          (placeholder)
  operator/
    install-server.md
    install-docker.md
    upgrade.md
    backup-restore.md
    oidc-setup.md
    capabilities-admin.md
    rbac.md
    monitoring.md
  user/
    first-launch.md
    team-mode-switching.md
    privacy-scopes.md
    ai-providers.md
    integrations.md             (placeholder)
    memory.md                   (placeholder)
  developer/
    contributing.md
    building.md
    testing.md
    electron-internals.md
    plugin-authoring.md         (placeholder)
    extension-authoring.md      (placeholder)
    migrations.md
    mcp-tools.md
  security/
    threat-model.md
    secret-handling.md
    sync-security.md
```

Inline examples on every page. `typedoc`-generated reference under `docs/reference/` (gitignored).

### 11.3 CI check

Lint step flags PRs editing `server/sync/`, `server/integrations/`, `server/plugins/`, or `electron/` without a matching `docs/` edit. `[skip-docs]` in commit body bypasses.

## 12. Local `todo/` tracking convention

Gitignored folder for persistent session-spanning task tracking.

```
todo/
  README.md
  HANDOFF_PROMPT.md
  HANDOFF_PROMPT.brief.md
  _active.md
  _backlog.md
  subsystems/
    B-deployment-topology.md
    C-plugin-marketplace.md
    D-ts-plugin-wrappers.md
    E-memory-backends.md
    A-integrations.md
    _done/
  sessions/
    YYYY-MM-DD-session-notes.md
  ideas.md
  known-issues.md
```

- Checkbox lists `- [ ]` / `- [x]`; tagged with spec section numbers `[B5.2]` etc.
- `_active.md` holds ≤1 item.
- Completed subsystem files move to `subsystems/_done/`.
- `HANDOFF_PROMPT.md` = full re-hydration prompt for new sessions; `HANDOFF_PROMPT.brief.md` = compact fallback.

## 13. Implementation sequence

Each item below maps to a discrete commit. Ordered to keep `main` green throughout.

1. Spec doc + `todo/` scaffolding + `.gitignore` entry. _(this commit)_
2. ULID utility + sync column migrations (non-breaking - columns unused).
3. `server/sync/model.ts` - `UNSYNCABLE_TABLES`, `SYNCABLE_TABLES`, scope defaults, helpers.
4. Auth: `refresh_tokens` table, JWT middleware, `/api/auth/*` endpoints, bcrypt password hash on existing users.
5. RBAC: `permissions` table, seed, `assertPermission` middleware, solo-mode short-circuit.
6. Sync REST: `/api/sync/pull`, `/api/sync/push` with cursor + conflict handling.
7. Sync WebSocket channel `/sync` with capability manifest on connect.
8. Client-side sync engine (`src/lib/sync.ts`): outbox, cursor store, WS connect, apply deltas.
9. Mode detection in `server/index.ts`; first-launch wizard `src/pages/FirstLaunch.tsx`; Settings → Deployment panel.
10. Capability manifest: `ai_providers`/`integrations` `source` column on client, server manifest endpoint, proxy routes.
11. Worker pool foundation: `pipeline_jobs` table, worker entry `server/workers/scan-worker.ts`, claim loop.
12. Per-job `executor` field threaded through pipeline API and UI Start button.
13. Pool scope: `/api/pool/push`, `POOL_ANONYMIZE` map, pool read endpoints.
14. OIDC scaffolding (behind `oidc_enabled` flag): provider config table, `openid-client` integration, start/callback/exchange routes.
15. Packaging: `Dockerfile.server`, `docker-compose.server.yml`, `scripts/build-server-docker.mjs`, `scripts/build-server-tar.mjs`, `scripts/build-desktop.mjs`.
16. Install scripts: `scripts/install-server.sh`, `scripts/install-server.ps1`, `scripts/bootstrap.mjs`, `scripts/migrate.mjs`, `systemd/vulnforge-server.service`.
17. Docs scaffolding - create `docs/` tree with stubs, then fill operator/architecture/security pages.
18. README overhaul.
19. CI docs-lint check.

## 14. Testing strategy

- Unit: sync model functions, conflict resolver, tombstone GC, permission checks, scope filters.
- Integration: two in-process server instances + a mock client simulating push/pull/conflict round-trips; offline→online outbox flush; tombstone propagation.
- End-to-end (manual until E2E harness exists): solo → team migration; OIDC login; worker-pool scan.
- Regression: existing pipeline tests must pass unchanged (solo-mode path preserves current behavior).

## 15. Risks & mitigations

| Risk                                                         | Mitigation                                                                                                        |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Schema migrations break existing desktop DBs                 | Each migration wrapped in `BEGIN...COMMIT`; backfill uses safe defaults; version-stamp DB schema                  |
| Sync bugs silently lose data                                 | Every sync failure logs to `audit_log`; outbox retries with dead-letter after 5 failures visible in UI            |
| Server-proxied AI leaks one user's data to another           | Per-request `req.user.id` attached to upstream call; capability permissions enforced via RBAC                     |
| Clock drift between client and server causes false conflicts | Server clock is the only ordering clock; client clock informational only                                          |
| JWT secret stolen → all tokens compromised                   | Rotation script rotates secret + invalidates all refresh tokens; documented in `docs/security/secret-handling.md` |
| Worker pool on server becomes noisy neighbor                 | Per-job ulimits + per-user queue cap; admin can evict jobs                                                        |

## 16. Open questions (tracked in `todo/subsystems/B-deployment-topology.md`)

- Do we support a "headless" desktop client for CI use? (Probable yes, low priority.)
- Should pool scope submissions be reviewable by admin before publication?
- Where do audit logs get shipped in team mode (file, syslog, external SIEM)?

---

_End of spec._

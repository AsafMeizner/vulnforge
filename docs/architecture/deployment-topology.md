# Deployment topology

VulnForge ships as **one codebase**, **three artifacts**, **two operational modes**.

## Modes

### Solo mode

The desktop installer bundles frontend + Express backend + MCP server + local SQLite. No network is required to work; the app is fully usable offline. All rows default to `sync_scope='private'` and never leave the machine.

Target user: individual researcher.

### Team mode

A separately installed **server process** runs the shared core. Each team member still runs the full desktop app locally (it retains its own SQLite, MCP server, plugin manager, and pipeline engine) — but the desktop also connects to the team server and **syncs** rows marked `sync_scope='team'` in real time.

Target user: security team inside a company.

The desktop in team mode is **local-first**: you keep working when the network is flaky, writes accumulate in the local sync outbox, and reconcile on reconnect. The server is the source of truth for **conflict ordering only**, not for the data itself.

## Three artifacts, one codebase

| Artifact | Built by | Process environment |
|---|---|---|
| Desktop installer (`.exe`/`.dmg`/`.AppImage`) | `npm run build:desktop` | `VULNFORGE_MODE=desktop` (implicit when Electron is the parent) |
| Server Docker image (`vulnforge/server:<ver>`) | `npm run build:server:docker` | `VULNFORGE_MODE=server` |
| Server bare tarball (`vulnforge-server-<ver>.tar.gz`) | `npm run build:server:tar` | `VULNFORGE_MODE=server` |

`server/deployment/mode.ts` is the single detection point. All mode-dependent behavior (worker pool, multi-user, OIDC, capability manifest) flows from `isServerMode()` / `isDesktopMode()`.

## Visibility model

Every syncable row carries a `sync_scope` column with three values:

- `private` — desktop-only. Never touches the sync wire even if it would otherwise qualify.
- `team` — syncs to the team server and out to all members.
- `pool` — opt-in, anonymized, shared across orgs through a separate `/api/pool/*` endpoint (not regular sync).

See [`../user/privacy-scopes.md`](../user/privacy-scopes.md) for the user-facing guide.

## Server-proxied capabilities

Keys for AI providers and integrations do **not** sync across the wire. Instead, the server exposes them as **named capabilities** (via the capability manifest sent on WebSocket connect). Clients pick `Local: claude-opus` or `Server: team-triage` in their AI routing UI; the server-picked invocation is proxied through `/api/server/ai/invoke` so secrets stay server-side.

Admin toggle: `capability_manifest_enabled` setting or `VULNFORGE_CAPABILITY_MANIFEST=false` env var disables exposure entirely.

## Per-job scan execution

Pipelines carry `executor: 'local' | 'server'`. The client chooses per run in the UI "Run on" dropdown. Server-executed jobs enter the `pipeline_jobs` queue and are claimed by worker processes (`ceil(cpu_count/active_users)` fairness cap) for CPU-intensive work.

## Further reading

- Sync protocol: [`sync-protocol.md`](sync-protocol.md)
- Data model: [`data-model.md`](data-model.md)
- Full design record: [`../superpowers/specs/2026-04-16-deployment-topology-design.md`](../superpowers/specs/2026-04-16-deployment-topology-design.md)

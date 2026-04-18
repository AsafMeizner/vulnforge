# Data model - sync categories

Every table in VulnForge falls into one of three categories, determined by where its data can legitimately live.

## Category A - Syncable (with 3-tier scope)

Rows carry 7 sync columns. Each row picks a visibility scope.

| Column                 | Type        | Purpose                                               |
| ---------------------- | ----------- | ----------------------------------------------------- |
| `sync_id`              | TEXT UNIQUE | ULID minted at write time (sortable, globally unique) |
| `sync_scope`           | TEXT        | `private` / `team` / `pool`                           |
| `owner_user_id`        | INTEGER     | Who created it (solo mode: id=1 hardcoded)            |
| `updated_at_ms`        | INTEGER     | Client write clock (informational)                    |
| `server_updated_at_ms` | INTEGER     | Server write clock (ordering authority)               |
| `tombstone`            | INTEGER     | `0` / `1` - soft-delete marker                        |
| `sync_status`          | TEXT        | `local` / `pending` / `synced` / `conflict`           |

Tables in this category:

```
projects        vulnerabilities    scan_findings   pipeline_runs
notes           session_state      reports         checklists
checklist_items scans
```

`SYNCABLE_TABLES` in `server/sync/model.ts` is the single source of truth.

## Category B - Strictly per-machine (never sync)

Hold local filesystem paths, API keys, refresh tokens, UI prefs - meaningless or dangerous on another machine.

```
plugins            on-disk binaries and paths
notes_providers    vault paths, OAuth tokens
ai_providers       local API keys (see also Category C for server version)
integrations       local OAuth tokens (see also Category C)
api_tokens         long-lived MCP client tokens
refresh_tokens     NEVER leave their device
sync_outbox        client-only pending pushes
sync_cursors       client-only per-table cursor state
audit_log          server-only (desktop writes locally only)
sandbox_snapshots  local VM/container state
```

`UNSYNCABLE_TABLES` in `server/sync/model.ts` lists every Category B table; the transport guard rejects any attempt to sync them.

## Category C - Server-proxied capabilities

`ai_providers` and `integrations` are special: they exist independently on the desktop (user's own keys) AND on the server (team-shared keys). The server publishes them as **named capabilities** via the manifest sent on WebSocket connect. Clients see capability names + supported actions, not secrets.

When a client picks a `Server: ...` capability:

- AI invocation → `POST /api/server/ai/invoke` with `{capability, task, payload}`.
- Integration action → `POST /api/server/integrations/:name/:action`.

The server runs the actual upstream call with its own creds and streams the response back. Per-user RBAC (`ai:use`, `integrations:use`) gates manifest visibility.

## Scope semantics

- `private` - lives on the desktop only. Even in team mode, never serialized to the sync wire.
- `team` - all authenticated team members see it. Most rows in most workflows end up here.
- `pool` - opt-in, anonymized, crosses organizational boundaries. Separate endpoint (`/api/pool/push`), anonymization map, 1-hour snapshot cache on reads.

Setting: `settings.default_row_scope` (default: `private`). Users can override per-row via the scope pill in the row UI.

## Migration notes

The 7 sync columns were added to existing tables via idempotent `ALTER TABLE` statements in `migrateSchema()` (`server/db.ts`). Existing rows were backfilled with fresh ULIDs, `Date.now()`, and `sync_scope='private'` - so existing installs continue to function as solo-only without any data exposure.

## References

- Server code: `server/sync/model.ts` (constants + helpers), `server/db.ts` (schema + backfill)

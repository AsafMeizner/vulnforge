# Sync protocol

Primary transport: **WebSocket** at `/sync`. Fallback: **REST** at `/api/sync/pull` + `/api/sync/push`. Both share the same cursor semantics.

## Authentication

- REST: standard `Authorization: Bearer <access_token>` header.
- WebSocket: `?token=<access_token>` query parameter (browser WebSocket API cannot set headers). Alternatively `Sec-WebSocket-Protocol: bearer,<token>`.

## Cursors

One per syncable table. Value = the row's `server_updated_at_ms` column. The client keeps its last-seen value in local `sync_cursors` table.

## Message envelopes

### Inbound (client → server)

```json
{"type":"sync:hello","cursors":{"projects":1776360000000,"vulnerabilities":0,"...":0}}
{"type":"sync:push","table":"scan_findings","rows":[ ... partial SyncableRows ... ]}
{"type":"sync:ack","table":"scan_findings","cursor":1776360000200}
{"type":"ping"}
```

### Outbound (server → client)

```json
{"type":"capabilities","ai":[...],"integrations":[...],"mode":"server"}
{"type":"sync:batch","table":"projects","rows":[...],"next_cursor":1776360000123,"done":false}
{"type":"sync:accept","table":"scan_findings","sync_ids":["01KP..."],"server_updated_at_ms":1776360000456}
{"type":"sync:conflict","table":"scan_findings","sync_id":"01KP...","current":{ ... full current row ... }}
{"type":"sync:upsert","table":"projects","row":{ ... }}
{"type":"sync:delete","table":"projects","sync_id":"01KP..."}
{"type":"pong","ts":1776360000789}
{"type":"error","error":"...","code":"SOME_CODE"}
```

## Connection lifecycle

1. Desktop obtains JWT access + refresh tokens via `/api/session/login`.
2. Opens `wss://server/sync?token=<access>`.
3. Server validates token → sends `capabilities` manifest.
4. Client sends `sync:hello` with per-table cursors.
5. Server streams `sync:batch` messages for each table until all tables report `done=true`.
6. Server transitions to live mode - emits `sync:upsert` / `sync:delete` for server-side writes.
7. Client writes accumulate; flushed via `sync:push` batches (≤500 rows, ≤100ms windows).

## Conflict resolution

**Server-clock last-write-wins with field-level merge for a whitelist.**

Server compares incoming `updated_at_ms` to the stored `server_updated_at_ms`:

- Incoming newer → accepted; server stamps `server_updated_at_ms = Date.now()`, broadcasts upsert.
- Incoming older → **rejected**, server sends `sync:conflict` with the current row. Client marks local row `sync_status='conflict'` and surfaces a UI resolution prompt.

Before the row-level decision, the server applies **field-level merges** for a narrow whitelist (see `server/sync/model.ts::FIELD_MERGE`):

- `scan_findings.notes` - string concat with separator (both analysts' notes preserved).
- `scan_findings.merged_tools` - JSON array union.
- `vulnerabilities.status` - rank-max (higher-ranked status wins: `resolved` > `accepted` > `confirmed` > `investigating`).
- `checklist_items.checked` - logical OR.

## Tombstones

Deletes don't remove rows immediately. They set `tombstone=1, updated_at_ms=now()`. Sync treats tombstones as upserts - the `sync:delete` message carries only the `sync_id`, not the row. A daily sweep (30-day retention, configurable) hard-deletes rows where `server_updated_at_ms < now - 30d AND tombstone=1`.

## Offline queue

Writes while disconnected land in the local `sync_outbox` table (`sync_id` unique + `attempts` + `last_error`). The client drains it in FIFO order on reconnect, with exponential backoff per row. Rows hitting `attempts >= 5` surface as an error banner - never silently lost.

## Rate limits & backpressure

- Client batches writes in ≤100ms windows, max 500 rows per push.
- Server paginates pulls at 200 rows per `sync:batch`, waits for ACK before next batch.
- Per-user rate limit: 50 writes/second. Well above normal usage; catches runaway loops.

## Pool scope

`sync_scope='pool'` rows do **NOT** flow through regular sync. They go through `POST /api/pool/push`, which anonymizes per `POOL_ANONYMIZE` map (strip `owner_user_id`, redact URLs to scheme+host+path, redact paths to basename) before inserting into server-side `pool_*` tables. Pool pulls are snapshot-based, 1-hour TTL cache, not live.

## References

- Server code: `server/sync/model.ts`, `server/sync/repo.ts`, `server/sync/ws.ts`, `server/routes/sync.ts`

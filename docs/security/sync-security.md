# Sync security

Multi-device sync introduces failure modes regular single-user apps don't have. The design intentionally puts the server in charge of conflict ordering, scope enforcement, and audit, not the clients.

## Defense-in-depth layers

### 1. Transport

- WebSocket only over `wss://` in production. Configure TLS at the reverse proxy layer.
- JWT validated on WS upgrade; invalid/missing token → immediate close with code 4401.
- Access tokens 15-minute TTL limit blast radius of a leaked token.

### 2. Scope enforcement

The server, not the client, decides what syncs.

- `UNSYNCABLE_TABLES` list rejected at the sync repo layer - even admin can't push/pull them.
- Rows with `sync_scope='private'` rejected on push; pool-scoped rows rejected on standard push (must use `/api/pool/push`).
- `userCanSeeRow()` in the pull path filters by scope even though the SQL already filtered - defense in depth.

### 3. Conflict resolution

- Server clock is authoritative. Client-provided `updated_at_ms` is informational only.
- Rows with incoming `updated_at_ms <= server_updated_at_ms` are rejected with `sync:conflict` - callers resolve explicitly, never silently.
- Field-merge whitelist is narrow (4 columns across 3 tables) and each merge is a deterministic commutative operation - no data is lost to the merge itself.

### 4. RBAC at route level

- Every sync route calls `assertPermission(req, resource, action)`.
- Per-table resource mapping in `server/routes/sync.ts::toResource()`.
- Permissions are DB rows - rotatable without redeploy.

### 5. Rate limits

- Per-user write limit: 50 rows/second. Catches runaway loops.
- Push batches capped at 500 rows.
- WebSocket server reads heartbeats; idle connections closed after 10 minutes.

## Specific threats

### T1: Malicious client pushes a private row

_Blocked at_ `pushRows()`:

```typescript
if (incoming.sync_scope && !isTeamSyncScope(incoming.sync_scope)) {
  continue; // silently drop
}
```

Private rows never enter the server DB even if a client tries.

### T2: Replay of an old refresh token

_Blocked at_ `/api/session/refresh`:

The refresh row is found by `device_id` + hash match. If the raw token doesn't match any active row for that device_id, **all refresh tokens for that device_id are revoked** as a defensive signal that the device is either compromised or a replay is in progress.

### T3: Concurrent edits clobber each other

_Resolution via_ `resolveConflict()`:

- Row-level: later `updated_at_ms` wins (server clock tiebreak).
- Field-level merge for whitelist fields (notes, merged_tools, status, checked) - both users' work survives.
- Non-whitelist fields: last writer wins. Document this in user-facing UI so there are no surprises.

### T4: Tombstone resurrection

If client A deletes a row (tombstone=1) and client B hasn't synced yet, A's delete propagates first. When B pushes its (stale) copy of the row, the server sees a tombstone with newer `server_updated_at_ms` and rejects B's push with conflict.

### T5: Sync DoS via endless push

Rate limiter (50 writes/sec/user) + push batch size limit (500 rows) + WebSocket heartbeat timeout together bound impact. An attacker with valid credentials can DoS their own view but not the server as a whole.

### T6: Leaky capability manifest

Server-proxied AI + integrations expose _names_ and _actions_ only - never secrets. RBAC gates who sees which capabilities. A `viewer`-role client sees an empty manifest for both lists even if the server has them configured.

### T7: Pool submission leaks identity

`anonymizeForPool()` runs server-side BEFORE the row hits the pool tables. `owner_user_id` stripped, URLs reduced to scheme+host+path, paths reduced to basename. Client can preview the anonymized form before committing.

Clients cannot bypass anonymization by crafting a custom request - the pool endpoint is the only write path into the pool tables, and it always runs the anonymizer.

## Audit

Every auth event (login success/fail, refresh accepted/rejected, logout, device revocation) writes to `audit_log`. Admins read via the admin UI or via a SELECT - currently not streamed to an external SIEM (operator's choice to add - see [`../operator/monitoring.md`](../operator/monitoring.md) when we write it).

## Incident response checklist

On suspected breach:

1. Rotate JWT signing secret (see [`secret-handling.md`](secret-handling.md)).
2. Revoke all refresh tokens: `UPDATE refresh_tokens SET revoked = 1`.
3. Review `audit_log` for login + role-change events in the window.
4. If plugin compromise suspected, `systemctl stop vulnforge-server` + review `plugins/` for unexpected binaries.
5. Notify affected users via external channel (email/Slack) - the platform itself might be untrusted during IR.

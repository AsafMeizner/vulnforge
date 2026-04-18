# Repository instructions for GitHub Copilot

Copilot code review reads these instructions alongside the diff.
Keep the list short and focused on VulnForge-specific conventions -
general "write clean code" reminders are noise.

## What this project is

VulnForge is an AI-powered vulnerability research platform. It runs in two
modes:

- **Solo desktop** (Electron): frontend + Express backend + MCP + SQLite all
  in one process.
- **Team server** (Docker or bare-metal): the same `server/` code, without
  Electron. Desktops stay local-first and sync rows over WebSocket.

User / operator / developer / security docs live under `docs/`. Start at
`docs/README.md`.

## Conventions to enforce in review

### Style & structure

- **ESM only.** Always `import` - never `require`.
- **Inline styles + CSS variables** in React components (no CSS-in-JS library,
  no Tailwind class salad). Follow existing patterns under `src/`.
- **Hash-based routing** on the frontend.

### Database (sql.js + WASM)

- Reads go through `execQuery()`, writes through `execRun()`.
- **Every mutation must be followed by `persistDb()`** - missing that call is
  a silent data-loss bug on crash.
- Schema changes go in `migrateSchema()` via `ALTER TABLE ADD COLUMN` wrapped
  in try/catch (idempotency). Never modify/drop columns.
- New syncable tables must be added to `SYNCABLE_TABLES` in both
  `server/sync/model.ts` and the mirror list in `server/db.ts`.

### API shapes

- List endpoints: `res.json({ data, total })`.
- Error shape: `res.json({ error: "...", code?: "ENUM" })`.

### Auth & sync

- Route handlers MUST call `assertPermission(req, resource, action, res)` on
  writes. Read endpoints may rely on `userCanSeeRow()` filtering.
- `sync_scope='private'` rows must never appear on the wire. The sync layer
  already rejects them - do not add code paths that bypass the check.
- Server-side AI and integration **secrets** never leave the server. Clients
  invoke capabilities by name via `/api/server/ai/invoke` +
  `/api/server/integrations/:name/:action`.

### WebSocket

- All WS broadcasts go through `broadcast()` / `broadcastProgress()` /
  `broadcastSyncDelta()` - don't hand-roll `ws.send` loops.
- `/ws` and `/sync` share one upgrade handler in `server/index.ts`. Don't
  re-introduce per-WSS `server:` bindings.

### MCP

- New tools live in `server/mcp/tools.ts`. Args validated via Zod. No hidden
  side effects - tools should map to existing server functions.

### Shell / process spawning

- Never shell out with user-influenced input. Use the repo's
  `execFileNoThrow.ts` helper or `spawn(cmd, [argv...], { shell: false })`.
- Direct shell invocation via `child_process` is banned outside vetted
  scripts - the review checklist catches this.

### Secrets at rest (CR-08/09/10)

- Any column holding an API key, OIDC client secret, or integration config
  MUST be passed through `encryptSecret()` on the way in and
  `decryptSecret()` on the way out. Helpers live in `server/lib/crypto.ts`.
- Both helpers are idempotent via the `vf1:` prefix check, so re-encrypting
  an already-encrypted value is a no-op.
- Every new boot-time migration that wraps plaintext rows must check
  `isEncrypted(row.value)` before calling `encryptSecret()`.

### Outbound URLs (SSRF - CR-12)

- Any user-controlled URL (AI `base_url`, OIDC `issuer_url`, integration
  webhooks, etc.) MUST be validated via
  `await assertSafeExternalUrl(raw, { field })` from `server/lib/net.ts`
  BEFORE the value is stored OR before the fetch fires.
- The helper rejects RFC1918, loopback, CGNAT, link-local, cloud-metadata,
  and IPv4-mapped-IPv6 bypasses. Desktop mode transparently allows loopback
  (Ollama); server mode refuses.
- If the caller receives URLs from an untrusted response (e.g. an IdP's
  OIDC discovery doc), every URL that the server will subsequently fetch
  must be re-validated the same way.

### Prompt injection (CR-14)

- Every AI prompt builder that interpolates user / attacker-controllable
  data MUST:
  1. Wrap the system prompt in `withInjectionGuard(...)` from
     `server/ai/prompts/fence.ts`.
  2. Wrap each untrusted field in `fenceUntrusted('label', text)`.
  3. Run short inline fields through a local `sanitizeInline()` to strip
     tag syntax + newlines.
- Code snippets, file contents, scan tool output, finding descriptions,
  agent tool results - all count as untrusted.

### Tests

- `vitest` is the runner. Integration tests instantiate a real DB in
  `os.tmpdir()` per file - never touch `vulnforge.db` in the repo root.
- Every new pure module gets a unit test. Touching `server/sync/*`,
  `server/auth/*`, `server/workers/*` without updating or adding a test
  should be flagged.

### Docs-lint

- Editing `server/sync/`, `server/auth/`, `server/integrations/`,
  `server/workers/`, `server/deployment/`, `electron/`, `Dockerfile.server`,
  or `scripts/install-server.*` REQUIRES a matching edit under `docs/` or
  `README.md`, unless the commit body contains `[skip-docs]`. The CI
  `docs-lint` step enforces this.

## Things to gently push back on

- **Silent error swallowing.** `try { ... } catch {}` that discards the
  error without a clear reason (fallback path, known-transient) is a smell.
- **Feature-flag scaffolding for things nobody asked for.** YAGNI.
- **Optimistic assumptions about schema.** Always guard with try/catch for
  tables that may not exist on older DBs (e.g. `oidc_providers`,
  `refresh_tokens` before B13.4 ran).
- **Mixing legacy API-token auth with JWT session auth.** The bridge lives
  in `server/auth/auth.ts::authMiddleware` - JWT first, then API token.
  Don't duplicate that logic elsewhere.

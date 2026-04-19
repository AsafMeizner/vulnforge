# Changelog

All notable changes to VulnForge are documented here. Dates are ISO-8601
in UTC. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
loosely; semver-ish but the project is pre-1.0 so minor bumps can carry
breaking changes.

## [0.1.0] — 2026-04-19

First public release. Foundational functionality + a comprehensive
security sweep done before shipping. Status: alpha.

### Highlights

- **Solo desktop + team server** share one `server/` codebase. Packaged
  Electron apps run a local backend against loopback; the same binary
  powers a multi-user deployment with JWT + OIDC SSO + live sync to
  connected desktops.
- **48 custom Python static-analysis tools** + **10 integrated
  plugins** (Semgrep, Trivy, CodeQL, Nuclei, Grype, OSV-Scanner,
  Bandit, Safety, Nettacker, Garak).
- **AI routing** across Claude, OpenAI, Gemini, Ollama, Claude CLI.
  Per-task fallback chains, server-mode key proxying so desktops
  never see the team's API keys.
- **101 MCP tools** exposed at `/mcp` for external AI agents (Claude
  Code, custom orchestrators, CLI).
- **Runtime analysis**: libFuzzer, gdb, tcpdump, nmap, angr, radare2,
  Docker sandboxes, git-bisect, core-dump triage, QEMU stub.
- **Zero-dep CLI** (`vulnforge` binary) for headless status /
  findings / triage / hunt / chat from any terminal.
- **22 React pages** · hash routing · inline styles + CSS vars ·
  theme-aware favicon + logos · keyboard-first UX (command palette,
  quick capture, shortcut overlay).

### Security (CR-01..CR-27)

Every CRITICAL + HIGH + explicitly-called-out MEDIUM finding from
two successive audits was closed before the release. Detail is in
`docs/security/` and per-commit under the tag `v0.1.0`.

- **At-rest encryption** (AES-256-GCM, `vf1:` envelope) on AI provider
  API keys, OIDC client secrets, integration configs. Master key from
  `VULNFORGE_DATA_KEY` env or a chmod-600 keyfile.
- **SSRF guard** on every outbound fetch that takes a URL from user
  input (AI base_url, OIDC issuer + discovery endpoints, integration
  webhooks, NVD sync, Ollama, Gemini). Rejects RFC1918, loopback
  (server mode), CGNAT, cloud metadata, and IPv4-mapped-v6 bypasses.
  DNS resolution happens inside the guard to close the rebind
  window.
- **Prompt-injection fences** on every AI prompt builder (triage,
  verify, report, remediation, deep-triage 4-stage chain, root-cause
  semantic clusterer, agent loop). System prompts go through
  `withInjectionGuard()`; user-derived fields go through
  `fenceUntrusted()`; short fields go through an inline sanitiser.
- **Electron IPC hardening**: `open-path` restricted to paths under
  `userData` or paths the user picked via a native dialog.
  Executable extensions refused unconditionally.
- **WebSocket**: cross-origin upgrades refused against an explicit
  allowlist; subscribe requires job ownership in server mode;
  pipeline events route per-job instead of broadcast; no fallback to
  global broadcast when a job has no subscribers.
- **Error wrapper**: global CR-11 middleware wraps every 5xx to
  `{ error: 'Internal server error', request_id }` in production.
  195 `err.message` leak sites across 28 route files were migrated
  to `next(err)` in one mechanical sweep.
- **JWT** pins `iss` + `aud` claims. JWKS-backed OIDC id_token
  signature verification with `iss`/`aud`/`exp`/`nonce` checks.
- **RBAC default**: viewer role is read-only across `/api/*` via a
  global middleware + per-route `assertPermission` checks on
  sensitive routers.
- **CORS**: refuses the literal `*` when `credentials: true` (CSRF
  vector). Electron default allowlist is `app://vulnforge` +
  loopback Vite origins.
- **SQL**: `safeSetClause()` validates column names against
  `[a-z_][a-z0-9_]*` before building UPDATE statements. Mass-assignment
  allowlist on AI provider writes. Default list limit 100, cap 1000.
- **Passwords**: `crypto.timingSafeEqual` on all credential compares.
- **Logging**: request-URL redaction (code / state / token / key /
  id_token / access_token / secret / password).

### Architecture hygiene

- Inline `/api/ai/*` handlers (14 endpoints, 380 LOC in
  `server/index.ts`) moved to `server/routes/ai.ts` with permission
  gates + mass-assignment allowlist + CR-11 error wrapper + CR-14
  fence + agent step cap.
- `isDesktopMode()` unified from two conflicting definitions to one
  canonical helper in `server/deployment/mode.ts`.
- Duplicate `/api/health`, duplicate `getWss()` export, and
  hardcoded Windows drive-letter paths removed.
- Pipeline plugin runs now await before the scan stage closes
  (stops orphan findings appearing after the run is marked
  `completed`).

### Developer experience

- CI matrix: typecheck × 4 (server + frontend + electron + preload),
  vitest on Node 20 + 22, build on linux + mac + windows, docker
  image build, markdown link-check, npm audit, docs-lint.
- `scripts/link-check.mjs` catches dead internal markdown links.
- `scripts/migrate-err-handler.mjs` turns the `err.message` leak
  sweep into a reusable one-shot.
- `scripts/docs-lint.mjs` enforces that changes under
  `server/sync/`, `server/auth/`, `server/integrations/`,
  `server/workers/`, `server/deployment/`, `server/lib/crypto.ts`,
  `server/lib/net.ts`, `server/ai/prompts/fence.ts`, `electron/`,
  `Dockerfile.server`, or `scripts/install-server.*` come with
  matching doc updates (or a `[skip-docs]` marker in the commit).

### Tests

267 vitest tests across 22 files. Dedicated coverage on:
`crypto.ts` (envelope roundtrip, idempotency, tamper detection),
`net.ts` (every blocklist branch), `fence.ts` (closure / nested /
case / length), `jwt.ts` (iss / aud rejection), `mode.ts` (every
detection signal), `passwords.ts`, `permissions.ts`, `refresh.ts`,
`ulid.ts`, `sync-model.ts`, plus 11 integration tests against real
SQLite in tmpdir.

### Accessibility

- Every input has `aria-label`.
- Every clickable `<div>` has `role="button"`, `tabIndex={0}`, and
  an `onKeyDown` handler that accepts Enter and Space.
- Severity colour dots carry `aria-label` + `title` so colour-blind
  users see the level too.

### Known limitations

- Key rotation (for the at-rest encryption master key) requires a
  manual decrypt-and-re-encrypt cycle. A future `vf2:` envelope will
  support online rotation.
- Integration webhook URLs are stored encrypted but the individual
  webhook-post code paths don't yet pin DNS resolution; the SSRF
  guard runs but the fetch briefly re-resolves. Narrow window;
  see `docs/security/ssrf-guard.md` "TOCTOU limits" section.
- Some frontend pages (`FindingDetail.tsx`, `Plugins.tsx`,
  `AIPage.tsx`) are single-component monoliths — they render
  correctly but a future pass should split them per-tab for
  performance on lower-end machines.
- `seed.ts` remains gitignored and is not shipped. It contained
  development-only data.

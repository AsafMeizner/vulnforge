# VulnForge

AI-powered vulnerability research platform. Finds, triages, verifies, and reports security vulnerabilities in open-source projects.

Runs in two modes from the same `server/` codebase:

- **Solo desktop** (Electron): frontend + Express backend + MCP + SQLite in one process, bound to 127.0.0.1.
- **Team server** (Docker or bare-metal): same server, multi-user, 0.0.0.0 bind, JWT + OIDC SSO, sync protocol to desktop clients.

## Stack

- **Frontend:** React 19 + Vite + TypeScript (hash-based routing, inline styles + CSS variables)
- **Backend:** Express + TypeScript + SQLite (sql.js with WASM)
- **AI:** Multi-provider (Claude, OpenAI, Gemini, Ollama, Claude CLI) with task-based routing + fallback chain
- **Scanner:** 48 custom Python static analysis tools + 10 integrated plugins (Semgrep, Trivy, CodeQL, Nuclei, Grype, OSV-Scanner, Bandit, Safety, Nettacker, Garak)
- **Protocol:** MCP server at `/mcp` with **101 tools** for external AI agent integration
- **CLI:** Zero-dep `vulnforge` binary (`cli/vulnforge.mjs`) for headless status / findings / triage / hunt / chat

## Commands

- `npm run dev` - Start frontend (Vite) + backend (tsx watch) concurrently
- `npm run dev:server` - Backend only, port 3001
- `npm run dev:client` - Frontend only
- `npm run dev:server:team` - Backend in team-server mode (explicit `VULNFORGE_MODE=server`)
- `npm run build` - Vite production frontend build
- `npm run build:server` - Compile `server/` to `dist-server/`
- `npm run build:electron` - Compile `electron/main.ts` + `preload.ts`
- `npm run build:desktop` - Full Electron installer (uses electron-builder)
- `npm run electron:dev` - Dev-mode Electron with HMR
- `npm test` - Full vitest suite (267 tests across 22 files)
- `npm run test:coverage` - Coverage report (v8)
- `npm run migrate` - Run DB migrations standalone

## Architecture

```
src/                    - React frontend (pages, components, lib)
server/                 - Express backend
  ai/                   - AI routing, providers, prompts, agent, remediation
    prompts/
      fence.ts          - CR-14 prompt-injection fence wrapper
      triage.ts / verify.ts / report.ts - fenced prompt builders
  auth/                 - JWT, OIDC, API-token, password hashing, RBAC
  deployment/           - mode detection (server vs desktop)
  integrations/         - Jira / Linear / Slack / GitHub / Trello
  lib/
    crypto.ts           - AES-256-GCM at-rest encryption (CR-08/09/10)
    net.ts              - SSRF guard for outbound URLs (CR-12)
  mcp/                  - MCP server (101 tools)
  pipeline/             - Autonomous pipeline + detectors (supply-chain, injection, dataflow)
  routes/               - 30 REST route modules (incl. routes/ai.ts)
  scanner/              - Scan queue, tool runner, parser, filter
  sync/                 - Client-server sync protocol (private/shared/pool scopes)
  workers/              - Server-side job queue workers
cli/                    - `vulnforge` CLI binary (wired in package.json "bin")
electron/               - Electron main + preload (hardened IPC)
tests/
  unit/                 - Standalone units (ssrf-guard, prompt-fence, jwt, etc.)
  integration/          - Full-stack against real SQLite in tmpdir
```

## Key Patterns

- **ESM only** - use `import`, never `require`.
- **Database:** `execQuery()` for reads, `execRun()` for writes, always `persistDb()` after mutations. Schema changes go in `migrateSchema()` via idempotent `ALTER TABLE ADD COLUMN` in try/catch.
- **API shapes:** lists = `res.json({ data, total })`; errors = `res.json({ error, code? })`.
- **Auth:** write routes call `assertPermission(req, resource, action, res)`. JWT first, then API-token fallback in `authMiddleware`.
- **WebSocket:** `broadcast()` (all clients) / `broadcastToJob(jobId, msg)` (subscribed clients) / `broadcastProgress(cat, id, data)`. `/ws` and `/sync` share one upgrade handler in `server/index.ts`.
- **AI routing:** task-based with fallback chain. Configure in AI page or via `set_ai_routing` MCP tool.
- **Pipeline:** Clone → Git Analysis → Attack Surface → Scan + CVE Hunt + Config Audit → Filter (5-tier) → Chain Detection → AI Verify → Review.

## Security patterns (recent hardening - CR-01..CR-15)

- **Secrets at rest:** every column holding API keys, OIDC client_secrets, or integration configs goes through `encryptSecret()` / `decryptSecret()` from `server/lib/crypto.ts`. Master key is env-var first (`VULNFORGE_DATA_KEY`) then `<dataDir>/master.key` (chmod 600) then refuses to start in server-prod. Migration (`migrateAIProviderSecrets`, `migrateOidcSecrets`, `migrateIntegrationSecrets`) wraps plaintext rows at boot; the `vf1:` prefix marker makes it idempotent.
- **Outbound URLs (SSRF):** any user-controlled URL (AI `base_url`, OIDC `issuer_url`, OIDC discovery endpoints) goes through `assertSafeExternalUrl(url, { field })` from `server/lib/net.ts`. Rejects RFC1918 / loopback / CGNAT / cloud-metadata / IPv4-mapped v6. Desktop mode allows loopback for Ollama; server mode refuses.
- **Prompt injection:** every AI prompt builder that interpolates user data must use `fenceUntrusted(label, text)` and `withInjectionGuard(systemPrompt)` from `server/ai/prompts/fence.ts`. Short fields go through a local `sanitizeInline()` that strips tag syntax + newlines.
- **IPC:** Electron `open-path` handler accepts only paths under `app.getPath('userData')` or paths the user explicitly picked via a dialog in this session. Executable extensions (`.exe`, `.ps1`, `.sh`, …) are refused regardless.
- **WebSocket:** upgrade handler rejects cross-origin connections unless the `Origin` is in `VULNFORGE_CORS_ORIGIN`. `broadcastToJob` never falls back to `broadcast` (prevents cross-user info leak when no subscribers).
- **Error responses:** production returns `{ error: 'Internal server error', request_id }` - no stack traces. Dev returns the real message + first 8 stack frames.

## MCP Server

External AI agents connect at `http://localhost:3001/mcp` (SSE + JSON-RPC 2.0). 101 tools across:

- **Pipeline:** `start_pipeline`, `get_pipeline_status`, `cancel_pipeline`
- **Findings:** `list_vulnerabilities`, `get_vulnerability`, `accept_scan_finding`, `reject_scan_finding`
- **Analysis:** `run_tool`, `triage_finding`, `hunt_cve_pattern`, `map_attack_surface`, `cluster_findings_by_root_cause`
- **Investigation:** `start_investigation`, `propose_next_step`, `execute_investigation_step`
- **Sandbox / runtime:** `start_sandbox`, `pause_sandbox`, `resume_sandbox`, `start_runtime_job`
- **Remediation:** `generate_fix_diff`, `autonomous_remediate`, `analyze_change_impact`
- **Config:** `get_ai_routing`, `set_ai_routing`, `list_integrations`, `create_ticket`
- **Export:** `export_sarif`, `export_cve_json`, `export_workspace`, `get_audit_log`

## Deployment-mode detection

`isDesktopMode()` / `isServerMode()` from `server/deployment/mode.ts`. Precedence:

1. `VULNFORGE_MODE` env (`server` | `desktop`) - explicit override.
2. `process.versions.electron` present → `desktop`.
3. `ELECTRON_RUN_AS_NODE=1` → `desktop`.
4. Default → `server`.

Many behaviours branch on mode: loopback allow-list in SSRF guard, bootstrap-admin gate in auth, default host binding (127.0.0.1 vs 0.0.0.0).

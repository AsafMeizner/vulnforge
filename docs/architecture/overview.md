<p align="center">
  <img src="../assets/logo-wide-white.png#gh-dark-mode-only" alt="VulnForge" width="360">
  <img src="../assets/logo-wide.png#gh-light-mode-only" alt="VulnForge" width="360">
</p>

# Architecture overview

VulnForge is a multi-layer platform. Top to bottom:

```
┌─────────────────────────────────────────────────────────────────┐
│ React 19 frontend — 18 pages, hash routing, inline styles       │
│   Settings / Hunt / Findings / Integrations / AI / Runtime ...  │
└───────────────────────────────┬─────────────────────────────────┘
                                │ REST + WebSocket
┌───────────────────────────────▼─────────────────────────────────┐
│ Express backend (server/index.ts)                                │
│                                                                 │
│ ┌─ Auth ─────┬─ Sync ─────┬─ MCP ─────┬─ Pipeline ─┬─ Runtime ─┐│
│ │JWT+refresh │WS + REST   │30+ tools  │Clone→…→    │libFuzzer, ││
│ │bcrypt+OIDC │+conflict   │SSE+JSON-  │verify      │gdb,       ││
│ │RBAC        │resolution  │RPC        │            │nmap, ...  ││
│ └────────────┴────────────┴───────────┴────────────┴───────────┘│
│                                                                 │
│ ┌─ Plugins manager ───────┬─ Integrations ──┬─ Notes providers ─┐
│ │ 10 scanners             │ Jira/Trello/    │ Local / Obsidian  │
│ │ (Semgrep, Trivy, CodeQL)│ Slack/Linear/GH │ (Notion planned)  │
│ └─────────────────────────┴─────────────────┴───────────────────┘│
└───────────────────────────────┬─────────────────────────────────┘
                                │
                       SQLite (sql.js + WASM)
                       36 tables, migrations idempotent
```

## Deployment modes

- **Solo desktop** — Electron wraps the whole stack. Frontend loads `http://localhost:3001`.
- **Team server** — same backend code runs without Electron, with multi-user auth + worker pool + capability manifest + OIDC. Multiple desktops connect via WebSocket sync.

Full deployment detail: [`deployment-topology.md`](deployment-topology.md).

## Request paths

| Surface | Path | Auth |
|---|---|---|
| REST API | `/api/*` | JWT (bypassed in solo mode) |
| Legacy API tokens | `/api/auth/*` | API token (phase 14/15 flow, still supported) |
| Session / JWT flow | `/api/session/*` | None (login) / JWT |
| Sync REST | `/api/sync/*` | JWT + per-route RBAC |
| Sync WebSocket | `/sync?token=<jwt>` | JWT in query param |
| Pipeline WebSocket | `/ws` | (currently unauthenticated — separate from sync) |
| MCP | `/mcp` | API token or unauth (solo) |

## Data

One SQLite file (`vulnforge.db` by default). Three data categories — see [`data-model.md`](data-model.md).

- Syncable rows carry 7 sync columns; flow over `/sync`.
- Unsyncable rows (keys, tokens, local-only config) never leave the device.
- Capability rows (`ai_providers`, `integrations`) exist on both sides but only capability **names** are exposed across the wire.

## Pipeline

Fixed stages, same code path on desktop and server:

1. **Clone** — git
2. **Git analysis** — blame, commit age, recency patches
3. **Attack surface** — entry points, trust boundaries
4. **Scan** — 48 Python tools + 10 plugins run in parallel
5. **CVE hunt** — 17 known pattern variants
6. **Config audit** — Dockerfile/CI/K8s
7. **Filter** — 5-tier false-positive filter
8. **Chain detection** — multi-step vulns
9. **AI verify** — LLM sanity check, severity
10. **Review** — user accepts/rejects

In team mode, clients can choose per-run whether stages run locally or on the server's worker pool.

## AI routing

Task-based. Each task category (`triage`, `verify`, `deep-analysis`, `embed`, `summary`, …) routes to a provider per rules in the `routing_rules` table. Local and server-proxied capabilities appear side by side in the routing UI.

## MCP

30+ tools expose platform capabilities to external AI agents (e.g. Claude Code). Tools cover: pipeline control, findings CRUD, runtime jobs, notes, AI routing config, integrations. See [`../developer/mcp-tools.md`](../developer/mcp-tools.md).

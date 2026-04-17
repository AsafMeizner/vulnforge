<p align="center">
  <img src="docs/assets/logo-wide-white.png#gh-dark-mode-only" alt="VulnForge" width="560">
  <img src="docs/assets/logo-wide.png#gh-light-mode-only" alt="VulnForge" width="560">
</p>

<p align="center">
  <strong>AI-powered vulnerability research platform.</strong><br>
  Find, triage, verify, exploit, and report security vulnerabilities all from one open-source app.
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#deployment-modes">Deployment</a> ·
  <a href="#features">Features</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="docs/">Docs</a> ·
  <a href="#mcp-server">MCP</a> ·
  <a href="#license">License</a>
</p>

<p align="center">
  <img alt="Node" src="https://img.shields.io/badge/node-%E2%89%A520-brightgreen">
  <img alt="Python" src="https://img.shields.io/badge/python-%E2%89%A53.10-blue">
  <img alt="TypeScript" src="https://img.shields.io/badge/typescript-strict-3178c6">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey">
  <img alt="Status" src="https://img.shields.io/badge/status-alpha-orange">
</p>

---

## What it is

VulnForge is a single platform for the whole vulnerability-research workflow: **discover → analyze → verify → exploit → disclose**.
It combines static analysis, dynamic analysis, historical intelligence, and an AI copilot - and can run either as a **solo desktop app** or as a **team server** that multiple desktops sync against.

- **Static:** 48 custom Python tools + 10 integrated scanners (Semgrep, Trivy, CodeQL, Nuclei, Grype, OSV-Scanner, Bandit, Safety, Nettacker, Garak).
- **Dynamic:** libFuzzer, gdb, tcpdump, nmap, angr, radare2, Docker sandboxes, git bisect, core-dump analysis.
- **AI:** Claude, OpenAI, Gemini, Ollama, or Claude CLI - task-based routing with per-task fallback chains.
- **Integrations:** Jira, Linear, Trello, Slack, GitHub Issues. Team-mode can proxy them through the server so keys stay central.
- **Interop:** MCP server exposes **93 tools** to external AI agents (Claude Code, custom orchestrators).

> **Status:** alpha. Foundations and data model are stable; some UI surfaces for subsystem B (team-mode wizard wiring, worker pool UI) are still landing.

---

## Quick start

### 1 · Solo desktop

```bash
git clone https://github.com/AsafMeizner/vulnforge.git
cd vulnforge
npm install
npm run dev
```

Open <http://localhost:5173>. Backend runs on port 3001. First launch shows a wizard - pick **Solo**.

For a signed installer: `npm run build:desktop` → installer lands in `release/`.

### 2 · Team server (Docker)

```bash
cp .env.server.example .env.server
# edit .env.server - set VULNFORGE_PUBLIC_URL, generate VULNFORGE_JWT_SECRET
docker compose -f docker-compose.server.yml --env-file .env.server up -d
docker logs vulnforge-server          # grab the printed bootstrap token
```

On your desktop: first-launch wizard → **Team** → paste the server URL and bootstrap token.

### 3 · Team server (bare metal)

```bash
tar xf vulnforge-server-<version>.tar.gz
sudo ./scripts/install-server.sh          # Linux / macOS
# or
.\scripts\install-server.ps1              # Windows (Administrator)
```

The installer preflights Node/Python/git, prompts for your public URL, generates secrets, creates a systemd (or Windows) service, runs migrations, and prints the first-admin bootstrap token. Full walkthrough: [docs/operator/install-server.md](docs/operator/install-server.md).

### 4 · First hunt

1. **Hunt** → paste a GitHub URL → **Start Hunt**
2. Watch: _Clone → Analyze → Scan → Filter → Verify → Review_
3. **Review** → accept or reject each finding
4. Optional: **AI → Providers** to add keys, **Routing** for a preset

---

## Deployment modes

One codebase, three artifacts, two operational modes:

| Mode             | Who for                | What it is                                                                                                                            |
| ---------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **Solo desktop** | Individual researcher  | Electron app bundles frontend + Express server + MCP + SQLite. Works fully offline.                                                   |
| **Team server**  | Small teams, companies | Separately installed server process. Desktops stay **local-first** (keep their own SQLite + MCP) and sync scoped rows over WebSocket. |

Team mode adds:

- **3-tier scope per row:** `private` (never leaves device) · `team` (syncs to server) · `pool` (anonymized, cross-org)
- **Server-proxied capabilities:** team AI keys + integration tokens live on the server; clients see capability names only
- **Per-job scan routing:** run heavy scans on server workers, quick checks on the laptop
- **JWT auth** with rotating refresh tokens, optional OIDC, RBAC (`admin` / `researcher` / `viewer`)

Full design: [docs/architecture/deployment-topology.md](docs/architecture/deployment-topology.md).

---

## Features

<details>
<summary><strong>Core pipeline</strong></summary>

- **Hunt** - paste a Git URL or local path → auto-clone, select tools by language, scan, 5-tier FP filter, AI verify, stage for review
- **Pause/Resume** - pause mid-pipeline and resume later
- **Batch mode** - scan multiple targets in parallel
- **No-AI mode** - works without any AI provider; add AI later

</details>

<details>
<summary><strong>Static analysis (48 Python tools + 10 plugins)</strong></summary>

- 48 custom Python tools - memory safety, crypto, protocol, concurrency, supply chain
- 10 integrated plugins - Semgrep · Bandit · CodeQL · Trivy · Nuclei · Grype · OSV-Scanner · Safety · Nettacker · Garak
- **CVE variant hunting** - 17 known CVE patterns searched across every target
- **Config auditing** - Dockerfile, CI/CD, `.env`, compiler flags, Kubernetes
- **Attack surface mapping** - entry points, trust boundaries, pre-auth code
- **Dependency reachability** - filters unreachable dependency vulns via call graph

</details>

<details>
<summary><strong>Runtime & dynamic analysis</strong></summary>

- **Fuzzing** - libFuzzer + auto-harness generation + crash triage
- **Debugging** - gdb breakpoint validation + core-dump analysis
- **Network** - tcpdump / tshark capture + nmap scanning
- **Symbolic execution** - angr for crafted inputs
- **Binary analysis** - radare2 / rizin disassembly
- **Docker sandboxes** - isolated containers with pause/resume, snapshots, resource monitoring, file transfer
- **Memory forensics** - core-dump stack/register extraction

</details>

<details>
<summary><strong>AI copilot</strong></summary>

- **Investigate mode** - interactive, step-gated AI investigation
- **Assumption extraction** - AI lists all implicit assumptions in a function
- **Hypothesis auto-generation** - AI suggests research directions
- **5 providers** - Claude · OpenAI · Gemini · Ollama · Claude CLI
- **Auto-fallback** on rate-limit exhaustion
- **7 routing presets** - Smart Split, All Claude, All OpenAI, All Gemini, All Local, Budget, Claude CLI
- **Team-server proxy (team mode)** - route any task through the server's keys

</details>

<details>
<summary><strong>Research workspace</strong></summary>

- **Hypothesis journal** with kanban board (open → investigating → confirmed → disproved)
- **Persistent notes** with markdown + YAML frontmatter
- **Pluggable backends** - Local filesystem, Obsidian vault (Notion / Logseq planned)
- **Quick capture** - `Ctrl/Cmd + N` from anywhere
- **Server-side session** - investigation context survives restarts

</details>

<details>
<summary><strong>Exploit development</strong></summary>

- **PoC workbench** - write exploit code linked to findings
- **Proof ladder** - pattern → manual → traced → PoC → weaponized
- **8 exploit templates** - format string, buffer overflow, heap UAF, SQL injection, SSRF, etc.

</details>

<details>
<summary><strong>Historical intelligence</strong></summary>

- **NVD sync** - fetch CVEs, cross-reference dependencies
- **Git bisect** - find the commit that introduced a bug
- **Patch analysis** - extract patterns from security commits

</details>

<details>
<summary><strong>Integrations & disclosure</strong></summary>

- **Ticketing** - Jira, Linear, Trello, GitHub Issues
- **Messaging** - Slack
- **Vendor management** - contacts, platforms, response times
- **SLA tracking** - on-track / warning / overdue indicators
- **Bounty analytics** - total payouts, averages, per-program ROI

</details>

<details>
<summary><strong>Compliance & export</strong></summary>

- **SARIF 2.1** - GitHub / GitLab / Azure DevOps compatible
- **CVE JSON 5.0** - CNA submission
- **Workspace backup** - full JSON dump
- **Audit trail** - every action logged

</details>

<details>
<summary><strong>Pro UX</strong></summary>

- **Command palette** (`Ctrl/Cmd + K`) - jump to any page
- **Keyboard shortcuts** (`?`) - full cheat sheet
- **Grouped navigation** - 22 pages in collapsible sidebar sections
- **Theme-aware favicon** - follows your OS light/dark setting live

</details>

---

## Architecture

```
src/                      React 19 + Vite (22 pages, hash routing, inline styles)
server/                   Express + SQLite (sql.js WASM)
  ai/                     Multi-provider routing + investigation
  auth/                   JWT + refresh + bcrypt + RBAC + OIDC
  sync/                   Sync model, REST repo, WS channel, capability manifest
  workers/                Server-side scan worker pool
  deployment/             Mode detection (solo vs server)
  pipeline/               Autonomous pipeline + analysis modules
    runtime/              10 executor types (fuzz, debug, network, sandbox, …)
    notes/                Pluggable note backends (Local + Obsidian)
    history/              NVD sync, patch analysis
    export/               SARIF, CVE JSON, backup
  scanner/                Scan queue, tool runner, parser, filter
  plugins/                Plugin manager + catalog
  integrations/           Jira · Linear · Trello · Slack · GitHub Issues
  mcp/                    MCP server (93 tools)
  routes/                 27 REST route modules
  data/                   CVE patterns, exploit templates
public/brand/             Logos (square + wide, black + white)
docs/                     Operator / user / dev / architecture / security
```

**Database:** 38 SQLite tables across the full platform - projects, vulnerabilities, scan_findings, pipeline_runs, notes, runtime_jobs, fuzz_crashes, bisect_results, cve_intel, exploits, proof_ladder, vendors, disclosures, integrations, integration_tickets, users, refresh_tokens, permissions, oidc_providers, pipeline_jobs, audit_log, and more. See [docs/architecture/data-model.md](docs/architecture/data-model.md).

---

## Building artifacts

```bash
npm run build:desktop        # .exe / .dmg / .AppImage installers  → release/
npm run build:server:docker  # multi-arch Docker image              → vulnforge/server:<ver>
npm run build:server:tar     # bare-metal tarball                   → vulnforge-server-<ver>.tar.gz
```

Per-platform details and CI templates: [docs/developer/building.md](docs/developer/building.md).

---

## Commands

| Command                       | Description                                       |
| ----------------------------- | ------------------------------------------------- |
| `npm run dev`                 | Frontend + backend in desktop mode                |
| `npm run dev:server`          | Backend only                                      |
| `npm run dev:server:team`     | Backend in server mode (multi-user + worker pool) |
| `npm run dev:client`          | Frontend only                                     |
| `npm run build`               | Production frontend build                         |
| `npm run build:server`        | Compile server → `dist-server/`                   |
| `npm run build:desktop`       | Electron installer                                |
| `npm run build:server:docker` | Server Docker image (`--push` for multi-arch)     |
| `npm run build:server:tar`    | Server bare-metal tarball                         |
| `npm run migrate`             | Run DB migrations (idempotent)                    |
| `npm test`                    | Vitest unit + integration suite                   |
| `npm run test:watch`          | Vitest in watch mode                              |
| `npm run test:coverage`       | Coverage report (v8)                              |

---

## MCP server

External AI agents connect at `http://localhost:3001/mcp` (SSE + JSON-RPC).

**93 tools** covering pipeline control, findings CRUD, notes / session state, runtime jobs (fuzz · debug · capture · scan · sandbox), exploits + proof ladder, disclosure + vendor management, CVE intel, investigation sessions, SARIF / CVE export, audit log, and more.

Authoring guide: [docs/developer/mcp-tools.md](docs/developer/mcp-tools.md).

Quick probe:

```bash
curl -s -X POST http://localhost:3001/mcp \
  -H 'accept: application/json, text/event-stream' \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq '.result.tools | length'
```

---

## Documentation

All long-form docs live under [`docs/`](docs/):

| Audience         | Pages                                                                                                                                                                                                                                                 |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Architecture** | [overview](docs/architecture/overview.md) · [deployment topology](docs/architecture/deployment-topology.md) · [sync protocol](docs/architecture/sync-protocol.md) · [data model](docs/architecture/data-model.md)                                     |
| **Operator**     | [install (bare metal)](docs/operator/install-server.md) · [install (Docker)](docs/operator/install-docker.md) · [upgrade](docs/operator/upgrade.md) · [OIDC setup](docs/operator/oidc-setup.md) · [backup / restore](docs/operator/backup-restore.md) |
| **User**         | [first launch](docs/user/first-launch.md) · [privacy scopes](docs/user/privacy-scopes.md) · [team-mode switching](docs/user/team-mode-switching.md) · [AI providers](docs/user/ai-providers.md)                                                       |
| **Developer**    | [building](docs/developer/building.md) · [migrations](docs/developer/migrations.md) · [MCP tools](docs/developer/mcp-tools.md)                                                                                                                        |
| **Security**     | [threat model](docs/security/threat-model.md) · [secret handling](docs/security/secret-handling.md) · [sync security](docs/security/sync-security.md)                                                                                                 |

Architectural decision records: [`docs/superpowers/specs/`](docs/superpowers/specs/).

---

## Stats

- **Frontend:** 22 pages · React 19 · hash routing · inline styles + CSS vars
- **Backend:** 27 REST route modules · 38 DB tables · 93 MCP tools
- **Static analysis:** 48 Python tools + 10 integrated plugins + 17 CVE patterns + 15 config checks
- **Runtime:** 10 executor types - libFuzzer, gdb, tcpdump, nmap, angr, radare2, core-dump, git-bisect, Docker sandbox, QEMU stub
- **Tests:** 82 vitest tests across 9 files (unit + integration against real SQLite)

---

## Contributing

Issues and PRs welcome. Before submitting:

```bash
npm test                                # must stay green
npx tsc --noEmit -p tsconfig.server.json # zero errors
```

Changes to `server/sync/`, `server/auth/`, `server/integrations/`, `server/workers/`, `server/deployment/`, `electron/`, or `Dockerfile.server` must include a matching update under `docs/`. The CI lint enforces this; add `[skip-docs]` to a commit message if a change truly needs no doc update.

See [docs/developer/building.md](docs/developer/building.md) for the full dev workflow.

---

## License

[MIT](LICENSE) © 2026 Asaf Meizner.

# VulnForge

**AI-powered vulnerability research platform.** Find, triage, verify, exploit, and report security vulnerabilities in open-source and proprietary software — all from one app.

VulnForge combines 48 custom static analysis tools, 10 integrated security plugins, runtime analysis (fuzzing, debugging, network capture, sandboxed execution), historical intelligence (NVD sync, git bisect), and AI-powered investigation into a single platform.

---

## Features

### Core Pipeline
- **Hunt** — paste a Git URL or local path → auto-clone, select tools by language, scan, 5-tier FP filtering, AI verify, stage for review
- **Pause/Resume** — pause mid-pipeline and resume later
- **Batch mode** — scan multiple targets in parallel
- **No-AI mode** — works without any AI provider; add AI later

### Analysis Tools
- **48 Python tools** — memory safety, crypto, protocol, concurrency, supply chain
- **10 plugins** — Semgrep, Bandit, CodeQL, Trivy, Nuclei, Grype, OSV-Scanner, Safety, Nettacker, Garak
- **CVE variant hunting** — 17 known CVE patterns searched across all targets
- **Configuration auditing** — Dockerfile, CI/CD, .env, compiler flags, Kubernetes
- **Attack surface mapping** — entry points, trust boundaries, pre-auth code
- **Dependency reachability** — filters unreachable dependency vulns via call graph

### Runtime & Dynamic Analysis
- **Fuzzing** — libFuzzer + auto-harness generation + crash triage
- **Debugging** — gdb breakpoint validation + core dump analysis
- **Network** — tcpdump/tshark capture + nmap scanning
- **Symbolic execution** — angr for crafted inputs
- **Binary analysis** — radare2/rizin disassembly
- **Docker sandboxes** — isolated containers with pause/resume, snapshots, resource monitoring, file transfer
- **Memory forensics** — core dump stack/register extraction

### Research Workspace
- **Hypothesis journal** with kanban board (open → investigating → confirmed → disproved)
- **Persistent notes** with markdown + YAML frontmatter
- **Pluggable backends** — Local filesystem, Obsidian vault
- **Quick capture** — Ctrl/Cmd+N from anywhere
- **Server-side session** — investigation context survives restarts

### Exploit Development
- **PoC workbench** — write exploit code linked to findings
- **Proof ladder** — pattern → manual → traced → PoC → weaponized
- **8 exploit templates** — format string, buffer overflow, heap UAF, SQL injection, SSRF, etc.

### AI Copilot
- **Investigate mode** — interactive step-gated AI investigation
- **Assumption extraction** — AI lists all implicit assumptions in a function
- **Hypothesis auto-generation** — AI suggests research directions
- **5 providers** — Claude, OpenAI, Gemini, Ollama, Claude CLI
- **Auto-fallback** on rate limit exhaustion
- **7 routing presets** — Smart Split, All Claude, All OpenAI, All Gemini, All Local, Budget, Claude CLI

### Historical Intelligence
- **NVD sync** — fetch CVEs, cross-reference dependencies
- **Git bisect** — find the commit that introduced a bug
- **Patch analysis** — extract patterns from security commits

### Disclosure & Bounty Ops
- **Vendor management** — contacts, platforms, response times
- **SLA tracking** — on-track / warning / overdue indicators
- **Bounty analytics** — total payouts, averages, per-program ROI

### Compliance & Export
- **SARIF 2.1** — GitHub/GitLab/Azure DevOps compatible
- **CVE JSON 5.0** — for CNA submission
- **Workspace backup** — full JSON dump
- **Audit trail** — every action logged

### Pro UX
- **Command palette** (Ctrl/Cmd+K) — jump to any page
- **Keyboard shortcuts** (?) — full cheat sheet
- **Grouped navigation** — 18 pages in collapsible sidebar sections

### MCP Server (70+ tools)
External AI agents connect at `http://localhost:3001/mcp` for full platform access.

---

## Deployment modes

VulnForge ships in two flavors from one codebase:

| Mode | Who for | What it is |
|---|---|---|
| **Solo desktop** | Individual researchers | Download the installer. Frontend + server + MCP + SQLite all run locally. No network required. |
| **Team server** | Small teams / companies | Run a shared server. Every member's desktop stays local-first (own SQLite + MCP) and **syncs** findings / projects / notes to the server over WebSocket. |

In team mode the server can optionally host **shared AI providers** and **integrations** — keys live on the server, clients invoke them by name. Per-job scan routing lets light scans run on the laptop and heavy scans on beefy server workers.

Full design: [`docs/architecture/deployment-topology.md`](docs/architecture/deployment-topology.md).

---

## Quick start

### Path 1 — Solo desktop

```bash
# Prerequisites: Node.js 20+, Python 3.10+, Git

git clone https://github.com/your-org/vulnforge.git
cd vulnforge
npm install
npm run dev           # dev
# or
npm run build:desktop # produce an installer
```

Open http://localhost:5173. Backend runs on port 3001. First launch shows a wizard — pick **Solo**.

### Path 2 — Team server via Docker

```bash
cp .env.server.example .env.server
# edit .env.server — set VULNFORGE_PUBLIC_URL, generate VULNFORGE_JWT_SECRET
docker compose -f docker-compose.server.yml --env-file .env.server up -d
```

Check logs: `docker logs vulnforge-server` — copy the printed bootstrap token. On your desktop, first-launch wizard → **Team** → paste server URL + bootstrap token.

### Path 3 — Team server bare metal

```bash
# From the server tarball on any Linux host
tar xf vulnforge-server-<version>.tar.gz
sudo ./scripts/install-server.sh
# Windows equivalent:  .\scripts\install-server.ps1
```

The installer prompts for the public URL, generates secrets, creates a systemd service (or Windows service), runs migrations, prints the first-admin bootstrap token.

---

## Building artifacts

```bash
npm run build:desktop        # .exe / .dmg / .AppImage installers (dist/)
npm run build:server:docker  # multi-arch Docker image vulnforge/server:<ver>
npm run build:server:tar     # vulnforge-server-<ver>.tar.gz
```

Build details: [`docs/developer/building.md`](docs/developer/building.md).

### First Hunt
1. Click **Hunt** → paste a GitHub URL → **Start Hunt**
2. Watch: Clone → Analyze → Scan → Filter → Verify → Review
3. Click **Review Findings** → Accept or Reject each

### Configure AI (optional)
1. **AI** page → **Providers** tab → enable a provider + enter API key
2. **Routing** tab → click **Smart Split** preset

---

## Architecture

```
src/                         — React 19 + Vite (18 pages, inline styles)
server/                      — Express + SQLite (sql.js + WASM)
  ai/                        — Multi-provider routing, investigation
  pipeline/                  — Autonomous pipeline + all analysis modules
    runtime/                 — 10 executor types (fuzz, debug, network, sandbox, etc.)
    notes/                   — Pluggable note backends
    history/                 — NVD sync, patch analysis
    export/                  — SARIF, CVE JSON, backup
    ai/                      — Investigate mode, assumption extraction
  scanner/                   — Scan queue, tool runner, parser, filter
  plugins/                   — Semgrep, Trivy, CodeQL, etc.
  mcp/                       — MCP server (70+ tools)
  routes/                    — 12 REST route modules
  data/                      — CVE patterns, exploit templates
.claude/                     — Claude Code plugin (6 skills + MCP config)
```

### Database: 22 SQLite tables
projects, vulnerabilities, scan_findings, pipeline_runs, runtime_jobs, fuzz_crashes, captures, notes, notes_providers, session_state, bisect_results, cve_intel, cve_project_matches, exploits, proof_ladder, vendors, disclosures, disclosure_events, sandbox_snapshots, routing_rules, audit_log, tools, plugins, ai_providers, checklists, checklist_items, reports, scans.

---

## Commands

| Command | Description |
|---------|-------------|
| `npm run dev` | Start frontend + backend (development, desktop mode) |
| `npm run dev:server` | Backend only |
| `npm run dev:server:team` | Backend in server mode (multi-user + worker pool) |
| `npm run dev:client` | Frontend only |
| `npm run build` | Production frontend build |
| `npm run build:server` | Compile server TypeScript → `dist-server/` |
| `npm run build:desktop` | Build desktop installers (all platforms available on current host) |
| `npm run build:server:docker` | Build server Docker image (`--push` for multi-arch publish) |
| `npm run build:server:tar` | Build bare-metal server tarball |
| `npm run migrate` | Run DB migrations (idempotent) |

---

## Documentation

All long-form docs live under [`docs/`](docs/):

- **Architecture**: [overview](docs/architecture/overview.md) · [deployment topology](docs/architecture/deployment-topology.md) · [sync protocol](docs/architecture/sync-protocol.md) · [data model](docs/architecture/data-model.md)
- **Operator**: [install (bare metal)](docs/operator/install-server.md) · [install (Docker)](docs/operator/install-docker.md) · [upgrade](docs/operator/upgrade.md) · [OIDC setup](docs/operator/oidc-setup.md) · [backup / restore](docs/operator/backup-restore.md)
- **User**: [first launch](docs/user/first-launch.md) · [privacy scopes](docs/user/privacy-scopes.md) · [team-mode switching](docs/user/team-mode-switching.md)
- **Developer**: [building](docs/developer/building.md) · [migrations](docs/developer/migrations.md) · [MCP tools](docs/developer/mcp-tools.md)
- **Security**: [threat model](docs/security/threat-model.md) · [secret handling](docs/security/secret-handling.md) · [sync security](docs/security/sync-security.md)

Design records of architectural decisions: [`docs/superpowers/specs/`](docs/superpowers/specs/).

---

## MCP Server

External AI agents connect at `http://localhost:3001/mcp` (SSE + JSON-RPC).

70+ tools covering: pipeline control, findings CRUD, notes/session, runtime jobs (fuzz/debug/capture/scan/sandbox), exploits/proof-ladder, disclosure/vendor management, CVE intel, investigation sessions, SARIF/CVE export, audit log.

---

## Project Stats

- **Frontend**: 18 pages, 55 modules, ~500KB bundle
- **Backend**: 12 route modules, 22 DB tables, 70+ MCP tools
- **Analysis**: 48 Python tools + 10 plugins + 17 CVE patterns + 15 config checks
- **Runtime**: 10 executor types (libFuzzer, gdb, tcpdump, nmap, angr, radare2, core-dump, git-bisect, Docker sandbox, QEMU stub)

---

## License

MIT

# VulnForge

AI-powered vulnerability research platform. Finds, triages, verifies, and reports security vulnerabilities in open-source projects.

## Stack

- **Frontend**: React 19 + Vite + TypeScript (hash-based routing, inline styles, CSS variables)
- **Backend**: Express + TypeScript + SQLite (sql.js with WASM)
- **AI**: Multi-provider (Claude, OpenAI, Gemini, Ollama, Claude CLI) with task-based routing
- **Scanner**: 48 Python static analysis tools + 10 integrated plugins (Semgrep, Trivy, CodeQL, etc.)
- **Protocol**: MCP server at /mcp with 30+ tools for external AI agent integration

## Commands

- `npm run dev` - Start both frontend (Vite) and backend (tsx watch) concurrently
- `npm run dev:server` - Backend only on port 3001
- `npm run dev:client` - Frontend only
- `npm run build` - Production build

## Architecture

```
src/                    - React frontend (pages, components, lib)
server/                 - Express backend
  ai/                   - AI routing, providers, prompts, agent
  pipeline/             - Autonomous pipeline (git, scan, filter, verify, chains, CVE hunt)
  scanner/              - Scan queue, tool runner, parser, filter
  plugins/              - External tool integrations
  mcp/                  - MCP server (30+ tools)
  routes/               - REST API endpoints
  data/                 - CVE patterns database
```

## Key Patterns

- ESM modules throughout (use `import`, never `require`)
- Database: `execQuery()` for reads, `execRun()` for writes, always call `persistDb()` after mutations
- API responses: always `res.json({ data, total })` for lists
- WebSocket: `broadcast()` for all clients, `broadcastProgress(category, id, data)` for pipeline updates
- AI routing: task-based with fallback chain - configure in AI page or via `set_ai_routing` MCP tool
- Pipeline: Clone → Git Analysis → Attack Surface → Scan + CVE Hunt + Config Audit → Filter (5-tier) → Chain Detection → AI Verify → Review

## MCP Server

External AI agents connect at `http://localhost:3001/mcp` (SSE + JSON-RPC). 30+ tools including:

- Pipeline: `start_pipeline`, `get_pipeline_status`, `cancel_pipeline`
- Findings: `list_vulnerabilities`, `accept_scan_finding`, `reject_scan_finding`
- Analysis: `run_tool`, `triage_finding`, `hunt_cve_pattern`, `map_attack_surface`
- Config: `get_ai_routing`, `set_ai_routing`

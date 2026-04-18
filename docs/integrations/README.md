# VulnForge Integrations

This directory contains plugins, configurations, and instructions for connecting VulnForge to external AI tools and editors.

## Available Integrations

### Claude Code (`.claude/` in project root)
The Claude Code plugin is already set up in the project root at `.claude/plugin.json`. It provides 6 skills (hunt, scan, triage, review, report, status) and connects to VulnForge's MCP server automatically.

**Setup**: Just open VulnForge's directory in Claude Code. The plugin auto-discovers.

### VS Code Extension (planned)
See `vscode/README.md` for the roadmap of the VS Code extension that will show findings inline.

### Generic MCP Agents
See `agents/README.md` for instructions on connecting any MCP-compatible AI agent (Copilot, Cursor, Antigravity, Open Claw, etc.).

## MCP Connection Details

All integrations connect to VulnForge via MCP:

```
URL: http://localhost:3001/mcp
Transport: SSE (Server-Sent Events) + JSON-RPC 2.0
Authentication: None (local server)
```

### For tools that support MCP natively (Claude Code, Cursor):
Add to your MCP config (e.g., `.mcp.json` or settings):
```json
{
  "mcpServers": {
    "vulnforge": {
      "url": "http://localhost:3001/mcp",
      "transport": "sse"
    }
  }
}
```

### For tools that use HTTP REST instead of MCP:
Use the REST API at `http://localhost:3001/api/*` directly. See the API docs in the README.

### For tools that need WebSocket events:
Connect to `ws://localhost:3001/ws` for real-time pipeline/scan/runtime progress.

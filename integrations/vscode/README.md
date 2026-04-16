# VulnForge VS Code Extension (Planned)

## Roadmap

The VS Code extension will provide:

1. **Inline finding annotations** — show vulnerability findings as diagnostics (red/yellow squiggles) on the affected lines
2. **Finding panel** — sidebar panel listing all findings for the open workspace
3. **Quick actions** — right-click a finding to: accept, reject, triage, create exploit, start investigation
4. **Note capture** — create research notes from the editor (linked to current file/line)
5. **Status bar** — show active pipeline status, finding count
6. **Command palette** — VulnForge commands available via Ctrl+Shift+P

## Architecture

The extension communicates with VulnForge via the REST API at `http://localhost:3001/api`.

For real-time updates, it connects to the WebSocket at `ws://localhost:3001/ws`.

## Development Setup (future)

```bash
cd integrations/vscode
npm install
npm run compile
# Press F5 in VS Code to launch extension development host
```

## Current Workaround

Until the extension is built, you can use VulnForge's MCP server with VS Code's built-in MCP support (if available) or with the Copilot Chat extension by adding the MCP server configuration.

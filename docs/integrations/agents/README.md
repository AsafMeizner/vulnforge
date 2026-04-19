# Connecting AI Agents to VulnForge

VulnForge exposes 101 tools via MCP (Model Context Protocol) for any AI agent to use.

## Connection

```
MCP Endpoint: http://localhost:3001/mcp
Transport: SSE (Server-Sent Events) + JSON-RPC 2.0
```

## For MCP-native agents (Claude Code, Cursor, Cline)

Add to your project's `.mcp.json`:

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

## For GitHub Copilot

Copilot doesn't natively support MCP yet. Use the REST API instead:

```
Base URL: http://localhost:3001/api
```

Key endpoints:

- `POST /api/pipeline/start` - start a vulnerability hunt
- `GET /api/vulnerabilities` - list findings
- `POST /api/ai/chat` - chat with VulnForge's AI
- `GET /api/runtime` - list runtime jobs

## For OpenClaw

OpenClaw is MCP-native. See the [dedicated OpenClaw guide](../openclaw/README.md)
for a step-by-step walkthrough, the CLI one-liner
(`vulnforge openclaw install`), and a ready-to-paste
`openclaw.json` snippet. Short version:

```bash
vulnforge openclaw install          # solo desktop
vulnforge openclaw install \        # team server
  --url https://vulnforge.acme.corp --token vf_...
```

## For Antigravity / Custom Agents

These agents typically support either MCP or HTTP tool calling:

### If MCP supported:

Use the SSE endpoint: `http://localhost:3001/mcp`
Call `tools/list` to discover all 101 tools.

### If HTTP tool calling:

Use the REST API. Each MCP tool has a corresponding REST endpoint:

| MCP Tool               | REST Equivalent                         |
| ---------------------- | --------------------------------------- |
| `start_pipeline`       | `POST /api/pipeline/start`              |
| `list_vulnerabilities` | `GET /api/vulnerabilities`              |
| `start_sandbox`        | `POST /api/runtime` with `type=sandbox` |
| `start_investigation`  | `POST /api/ai-investigate/sessions`     |
| `create_note`          | `POST /api/notes`                       |
| `export_sarif`         | `GET /api/export/sarif`                 |

## WebSocket Events

For real-time progress, connect to `ws://localhost:3001/ws`.

Message types:

- `pipeline:stage` - hunt pipeline progress
- `runtime:*` - runtime job events (fuzz stats, crashes, etc.)
- `scan:*` - individual tool scan events
- `triage:*` - AI triage events

## Example: Autonomous Agent Loop

```python
# Python example using requests
import requests
import time

BASE = "http://localhost:3001/api"

# 1. Start a hunt
r = requests.post(f"{BASE}/pipeline/start", json={"url": "https://github.com/target/repo"})
pipeline_id = r.json()["pipelineId"]

# 2. Poll until ready
while True:
    status = requests.get(f"{BASE}/pipeline/{pipeline_id}").json()
    if status["status"] in ("ready", "failed"):
        break
    time.sleep(5)

# 3. Review findings
findings = requests.get(f"{BASE}/scan-findings", params={"pipeline_id": pipeline_id, "status": "pending"}).json()
for f in findings["data"]:
    print(f"[{f['severity']}] {f['title']}")
    # Accept or reject
    requests.put(f"{BASE}/scan-findings/{f['id']}/accept")
```

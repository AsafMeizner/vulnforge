# MCP tool authoring

VulnForge exposes 30+ tools to external AI agents (Claude Code, custom orchestrators) via the Model Context Protocol at `http://localhost:3001/mcp` (SSE + JSON-RPC).

## Where tools live

`server/mcp/tools.ts` - one file, registered via `setupMcpServer(app)` in `server/index.ts`.

Each tool follows a shape:

```typescript
server.tool(
  "tool_name",
  "One-line description shown to the agent",
  {
    // Zod schema for arguments
    arg1: z.string(),
    arg2: z.number().optional(),
  },
  async ({ arg1, arg2 }) => {
    // ... do the thing, call into DB / pipeline / etc.
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }
);
```

## Adding a new tool

1. Open `server/mcp/tools.ts`.
2. Add a `server.tool(...)` call before the `setupMcpServer` export.
3. Use Zod for argument validation - bad args fail fast with a clear error.
4. Call into existing server-side code (DB functions, sync repo, pipeline) - don't duplicate logic.
5. Return structured content. JSON strings are fine; the agent can parse.
6. Document it here. If end users need to know about the tool, add a row to the MCP section in the main `README.md`.

## Naming conventions

- `list_*` - returns arrays (use pagination for big sets).
- `get_*` - single record by id.
- `create_*`, `update_*`, `delete_*` - write operations.
- `run_*`, `start_*`, `hunt_*` - kicks off a pipeline / long-running operation.
- `set_*`, `configure_*` - mutates config.

Follow existing names rather than inventing new patterns - external agents often call tools by guessing names.

## Auth

MCP clients authenticate via API token (phase-14 flow, `/api/auth/tokens`). Currently NOT integrated with the JWT session flow - MCP is a separate auth lane. Future work: unify under JWT so team-mode tokens can drive MCP sessions too.

## Team-mode MCP

In server mode, `/mcp` is exposed too. Each user can have their own API token and see only their allowed resources via RBAC.

In desktop mode, `/mcp` effectively trusts localhost - the same process owns both the user's UI and MCP.

## Testing

From Claude Code:

```
claude mcp add vulnforge http://localhost:3001/mcp
```

Then ask the agent to call your new tool. Watch the server logs for the request.

From curl for sanity:

```bash
curl -N http://localhost:3001/mcp -H 'Accept: text/event-stream'
```

You'll see the SSE handshake. Actual JSON-RPC body goes over POST with a session id - easier to test via the Claude Code CLI or the MCP SDK directly.

## Common pitfalls

- **Blocking the event loop**: don't run expensive sync work in the tool handler. Use async and `await`.
- **Side-effecting state not captured in DB**: other tools need to observe your changes. Write through the DB functions, not in-memory stores.
- **Swallowing errors**: let them bubble. The MCP framework turns thrown errors into structured tool errors the agent can reason about.
- **Huge responses**: the MCP transport has size limits. Return cursors / pagination for anything bigger than a few hundred rows.

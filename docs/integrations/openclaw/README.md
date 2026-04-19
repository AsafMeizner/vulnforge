# Connect OpenClaw to VulnForge

[OpenClaw](https://openclaw.ai) is an MCP-native AI agent — it already
speaks the protocol VulnForge's `/mcp` endpoint exposes, so wiring
them up is one config edit. Once connected, OpenClaw gets 101
VulnForge tools: pipeline control, findings CRUD, AI triage, fuzz
jobs, exploit workbench, disclosure, SARIF / CVE export — the full
workflow, drivable from an OpenClaw conversation.

This guide covers **solo desktop** (OpenClaw on the same machine as
VulnForge) and **team server** (OpenClaw pointed at a shared
deployment with JWT auth).

## Prerequisites

- VulnForge **v0.1.0** or newer (`vulnforge --version`).
- OpenClaw installed (`openclaw --version` should print a version).
- For team server: a VulnForge API token — grab one from
  **Settings → API tokens → + Create token** in the VulnForge UI.

## Option A — CLI (recommended)

The `vulnforge` CLI that ships with every release knows how to wire
itself into OpenClaw:

```bash
# solo desktop (assumes VulnForge is running locally on :3001)
vulnforge openclaw install

# team server
vulnforge openclaw install \
  --url https://vulnforge.acme.corp \
  --token vf_1234567890abcdef
```

The command:

1. Detects OpenClaw via `openclaw --version`.
2. Finds the live VulnForge backend — checks `$VULNFORGE_PORT`, then
   the `.vulnforge-port` file written by a running server, then falls
   back to probing `localhost:3001`..`localhost:3010`. This matters
   in dev mode where VulnForge hops ports on `EADDRINUSE`.
3. Generates the MCP server entry with the right URL, transport, and
   auth header for your mode.
4. Calls `openclaw mcp set vulnforge '<json>'` to register it.
5. Hits `/api/health` on the exact URL it just wrote into the config,
   so a stale URL or a down backend surfaces immediately instead of
   only when you open a conversation.

If OpenClaw isn't on `PATH` the command falls back to printing the
JSON snippet for you to paste manually — same file, same contents,
no guessing.

> **Note on ports:** the snippets below use `localhost:3001`, which
> is VulnForge's default. If the port was taken and the server hopped
> forward, check the `.vulnforge-port` file (cwd of the server) or
> the `VULNFORGE_READY_PORT=<port>` line it prints on startup, and
> substitute that port in the URL. The `vulnforge openclaw install`
> CLI does this discovery automatically.

## Option B — paste the config yourself

If you'd rather edit OpenClaw's config directly, the file you're
looking for is `mcp.servers` inside `openclaw.json`. The canonical
snippet for VulnForge:

### Solo desktop (no auth)

```json
{
  "mcp": {
    "servers": {
      "vulnforge": {
        "url": "http://localhost:3001/mcp",
        "transport": "sse",
        "connectionTimeoutMs": 10000
      }
    }
  }
}
```

### Team server (JWT auth)

```json
{
  "mcp": {
    "servers": {
      "vulnforge": {
        "url": "https://vulnforge.acme.corp/mcp",
        "transport": "sse",
        "headers": {
          "Authorization": "Bearer vf_YOUR_TOKEN_HERE"
        },
        "connectionTimeoutMs": 15000
      }
    }
  }
}
```

A machine-readable copy of both of the above lives at
[`openclaw.mcp.json`](./openclaw.mcp.json) in this directory — safe
to copy-paste wholesale into a fresh `openclaw.json`.

## Verifying the connection

After either Option A or Option B:

```bash
openclaw mcp list                  # vulnforge should appear
openclaw mcp show vulnforge        # confirms url + transport
```

From inside an OpenClaw conversation:

```
you > what tools does vulnforge expose?
openclaw > [calls vulnforge.tools/list]
         > VulnForge exposes 101 tools across 11 categories:
         > • Pipeline (9):  start_pipeline, get_pipeline_status, ...
         > • Findings (16): list_vulnerabilities, generate_fix_diff, ...
         > ...
```

If the agent reports "no tools" or "connection refused", jump to
[Troubleshooting](#troubleshooting).

## What OpenClaw can do with VulnForge

A handful of worked examples — paste any of these into an OpenClaw
conversation after connecting.

### 1 — Hunt and triage a new repo

```
Please run a full vulnforge hunt against
https://github.com/org/some-library, wait for it to finish, and give
me a one-paragraph summary of the top 3 findings by severity.
```

OpenClaw will call `start_pipeline`, poll `get_pipeline_status`
until it sees `status: "ready"`, read from `list_vulnerabilities`
and `get_vulnerability`, and summarise.

### 2 — Generate a fix for a finding

```
Read vulnerability 42 from vulnforge, generate a patch diff, and
open a draft PR against my fork with the fix.
```

Chains `get_vulnerability` → `generate_fix_diff` →
`autonomous_remediate` with `mode: "pr"`.

### 3 — Export compliance reports

```
Export all HIGH and CRITICAL findings from vulnforge's default
project as SARIF and save to ./vulnforge-sarif.json so I can
upload to GitHub code scanning.
```

Uses `export_sarif` with a filter and OpenClaw's local file-write
capability for the save.

### 4 — Cross-reference a CVE

```
Check VulnForge's historical intel — does CVE-2026-32875 match any
of the dependencies in my current project?
```

Calls `cross_reference_cves` against the project's dependency
inventory.

## Security notes

- The MCP server at `/mcp` is gated by the same auth middleware as
  `/api` — anonymous access is only allowed in desktop mode. In
  team mode, requests without a valid Bearer token return 401.
- The API token you put in the Authorization header has whatever
  role VulnForge assigned it. Mint a **read-only** token for
  conversational agents that just need to read findings. Mint an
  **editor** token for agents that write (triage, fix generation,
  disclosure). See [docs/security/secret-handling.md](../../security/secret-handling.md).
- OpenClaw itself caches MCP responses in its context. Don't ask it
  to dump secrets (API keys, integration tokens) — even though
  VulnForge's at-rest encryption keeps the DB-leak surface narrow,
  secrets read into conversation context can land in whatever model
  transcript OpenClaw logs locally.
- **Token handling trade-offs.** `vulnforge openclaw install` runs
  `openclaw mcp set <name> <json>`, which passes the full entry
  (including the Bearer token) as a command-line argument. On
  multi-user systems the token is briefly visible via `ps` /
  `/proc/<pid>/cmdline` to same-UID processes for the duration of
  the spawn. OpenClaw's CLI doesn't offer a stdin or file-based
  alternative. If argv exposure is a concern:

  ```bash
  # 1. Generate the config to a chmod-600 file instead of calling openclaw
  umask 077
  vulnforge openclaw show-config \
    --url https://vulnforge.acme.corp \
    --token vf_... \
    > vulnforge-openclaw.json

  # 2. Merge it into ~/.config/openclaw/openclaw.json by hand.
  ```

  The CLI also prints a `⚠ the output below contains your VulnForge
  API token in cleartext` warning when stdout would include a real
  token, so you don't forget to treat the scrollback as sensitive.
- Remote (non-loopback) installs **require** `--token`. The CLI
  fails fast if you try `vulnforge openclaw install --url
  https://…` without one, rather than silently registering an
  entry that would 401 on every tool call.

## Troubleshooting

### `openclaw mcp list` doesn't show `vulnforge`

```bash
openclaw mcp show vulnforge
```

If the output is empty, the `openclaw mcp set vulnforge ...`
command didn't take. Re-run `vulnforge openclaw install` — it
will print the exit status and the `✓ vulnforge backend reachable`
line (or a `⚠ unreachable` warning with the underlying error) so
you can tell which step failed.

If you want to inspect exactly what the CLI will write without
calling `openclaw`, use the preview flag:

```bash
vulnforge openclaw install --show-config
```

### "Connection refused" on tools/list

VulnForge backend isn't running. Check:

```bash
curl -s http://localhost:3001/api/health
```

Expect `{"status":"ok",...}`. If you get a connection-refused
error, start VulnForge (desktop: open the app; server:
`docker compose -f docker-compose.server.yml up -d`).

### "401 unauthorized" on tools/list (team mode)

Your Bearer token is wrong or expired. Regenerate from
**Settings → API tokens** in the VulnForge UI and re-run
`vulnforge openclaw install --token <new-value>`.

### "CORS policy" errors

`/mcp` accepts same-origin and any origin in the server's CORS
allowlist. Set `VULNFORGE_CORS_ORIGIN` on the server to include
OpenClaw's origin if it's running in a browser context. If OpenClaw
is running as a local process (the common case), CORS doesn't apply.

### Tool calls succeed but OpenClaw picks the "wrong" tool

VulnForge's 101 tools use a consistent naming pattern
(`list_*` / `get_*` / `create_*` / `update_*` / `delete_*` +
verb-based ones like `start_pipeline`, `hunt_cve_pattern`). If
OpenClaw is picking weird tools, give it a more specific prompt
that names the tool explicitly, or read
[docs/developer/mcp-tools.md](../../developer/mcp-tools.md) to
understand the catalog and prime OpenClaw with relevant tool
names.

## See also

- [OpenClaw official MCP documentation](https://docs.openclaw.ai/cli/mcp)
- [VulnForge MCP tool reference](../../developer/mcp-tools.md)
- [VulnForge API endpoints](../../api/ai-endpoints.md)
- [Connecting any MCP-native agent](../agents/README.md) — generic
  instructions for Cursor, Cline, Claude Code, custom orchestrators

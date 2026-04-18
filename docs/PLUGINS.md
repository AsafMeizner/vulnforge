# Writing a VulnForge plugin

A VulnForge plugin is an external tool (scanner, fuzzer, SAST, verifier, etc.)
wrapped in a small manifest so the app can install it, run it, parse its
findings, and expose it to AI agents + the REST / MCP API.

Two flavours:

1. **Built-in integration** — TypeScript module in
   `server/plugins/integrations/*.ts`. Ships with the app. Used when the
   tool has bespoke CLI parsing that benefits from being in-tree.
2. **External plugin** — standalone git repo you point VulnForge at.
   Installed via **Plugins → Add from URL** or
   `POST /api/plugins/install-from-url`. Great for community tools and
   internal-only scanners you don't want to upstream.

This doc focuses on **external plugins** since that's the zero-code-change
path: add a repo, get tools.

---

## TL;DR

Minimum viable plugin repo:

```
my-awesome-scanner/
├── vulnforge-plugin.json    # the manifest (required)
├── install.sh               # optional: one-shot installer
├── run.sh                   # optional: wrapper that emits findings
└── README.md
```

Register it:

```bash
curl -X POST http://localhost:3001/api/plugins/install-from-url \
  -H 'content-type: application/json' \
  -d '{
    "url": "https://github.com/yourname/my-awesome-scanner",
    "name": "my-awesome-scanner",
    "description": "SAST for Brainfuck",
    "type": "scanner"
  }'
```

Then hit **Plugins → Install** in the UI (or `POST /api/plugins/:id/install`)
to clone + run `install.sh`, and **Plugins → Enable** to make it runnable.
VulnForge auto-exposes every enabled plugin to:

- **REST**: `POST /api/plugins/:id/run` with `{ target }` returns findings
- **MCP**: `run_tool` with `{ tool_name: "my-awesome-scanner", target }`
- **AI routing**: `routeAI({ task: "scan-custom" })` can invoke it

---

## The manifest (`vulnforge-plugin.json`)

Committed in the repo root. All fields validated at install time.

```jsonc
{
  "name": "my-awesome-scanner",         // unique; must match the DB row
  "version": "1.2.0",
  "type": "scanner",                    // scanner | fuzzer | verifier | triage | reporter
  "category": "SAST",                   // free-form grouping shown in Plugins UI

  "description": "One-line summary shown on plugin cards",
  "long_description": "Multi-paragraph markdown explaining what it does.",

  "website_url": "https://github.com/yourname/my-awesome-scanner",
  "source_url":  "https://github.com/yourname/my-awesome-scanner",

  // How VulnForge brings it to life. Runs in the plugin's install dir
  // after git clone. Env is inherited. Exit non-zero = install failed.
  "install_command": "bash install.sh",

  // How VulnForge runs it against a target. Two placeholders are
  // substituted at launch time:
  //   {{target}}   absolute path to the project root being scanned
  //   {{output}}   absolute path VulnForge expects results at
  // Anything else is passed through verbatim.
  "run_command": "bash run.sh --project {{target}} --out {{output}}",

  // How to interpret what the run command produces:
  //   "json"          findings[] or {"findings":[...]} at {{output}}
  //   "sarif"         SARIF 2.1.0 at {{output}}
  //   "markdown"      plain markdown; VulnForge's parser finds "### [SEV]" blocks
  //   "text"          raw stdout, each line becomes a low-severity finding
  //   "stdout-json"   run_command writes JSON to stdout (no output file needed)
  "parse_output": "json",

  // System dependencies the plugin needs. VulnForge checks each with
  // `which <name>` before enabling, and surfaces missing ones with a
  // "Click to install" prompt that shells out to the appropriate
  // package manager (go/pip/cargo/etc.).
  "requires": ["go", "git"],

  // Optional: structured config the UI renders as a form.
  "config_schema": {
    "type": "object",
    "properties": {
      "severity_threshold": { "type": "string", "enum": ["low","med","high","critical"], "default": "med" },
      "timeout_seconds":    { "type": "number", "default": 300 }
    }
  },

  // Optional: tasks this plugin can handle in the AI routing system.
  // When a task lists this plugin, routeAI() can dispatch to it.
  "ai_tasks": ["scan", "triage"]
}
```

---

## The finding format

Whatever your `run_command` produces at `{{output}}` (or stdout) must
reduce to an array of finding objects. VulnForge accepts a few shapes;
the canonical one is:

```jsonc
[
  {
    "title":        "strncpy without explicit NUL termination",
    "severity":    "High",                // Critical | High | Medium | Low | Info
    "confidence":  "High",                // High | Medium | Low
    "cwe":         "CWE-170",             // optional
    "cvss":        7.5,                   // optional, numeric
    "file":        "src/parser.c",
    "line_start":  142,
    "line_end":    142,

    "description":  "Markdown OK. Use **bold**, `code`, ```fenced blocks```.",
    "impact":       "OOB read on subsequent string ops. Crafted input → crash.",
    "code_snippet": "strncpy(dest, src, n);",
    "suggested_fix":"```c\\ndest[n - 1] = '\\\\0';\\n```",
    "reproduction_steps": "1. Compile. 2. Feed N-byte src with no NUL.",

    "tool_name":   "my-awesome-scanner",  // fills in automatically if omitted
    "raw":         { "rule_id": "CWE-170-strncpy" }  // free-form; stored as JSON blob
  }
]
```

Anything not listed here is ignored. Missing optional fields are fine
— only `title` + `severity` are strictly required for a row to land.

---

## Letting the AI and MCP call your plugin

Once enabled, your plugin is automatically exposed to:

### REST API

```bash
# Run against a project
curl -X POST http://localhost:3001/api/plugins/42/run \
  -H 'content-type: application/json' \
  -d '{ "target": "/path/to/project", "config": { "severity_threshold": "high" } }'
```

Returns `202 Accepted` immediately with a `run_id`. Poll
`GET /api/plugins/runs/:run_id` for progress, or subscribe to the
WebSocket channel `plugin-run` for real-time events.

### MCP server (for external AI agents)

Agents connecting to `http://localhost:3001/mcp` see your plugin under
the generic `run_tool` handler:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "run_tool",
    "arguments": {
      "tool_name": "my-awesome-scanner",
      "target":    "/path/to/project",
      "config":    { "severity_threshold": "high" }
    }
  }
}
```

The result is the parsed finding array, same shape as the REST run.

### VulnForge's own AI routing

If your manifest lists `"ai_tasks": ["scan"]`, VulnForge can pick your
plugin when a user runs AI-Scan on a project:

```ts
routeAI({ task: "scan", target: "/path/to/project" });
// dispatched to highest-priority enabled provider for "scan";
// may be another plugin, may be a built-in integration.
```

Priority is controlled via **AI → Routing** in the UI or
`POST /api/ai/routing`.

---

## The install lifecycle

```
   register      install         enable          run
   ────────  →   ───────   →    ──────   →    ──────
  POST          POST           POST          POST
  /install-     /plugins/      /plugins/     /plugins/
  from-url      :id/install    :id/enable    :id/run

  manifest      git clone      requires[]    run_command
  validated     +install_      re-checked,   executed,
  + DB row      command        enabled=1     output parsed,
  created                                    findings stored
```

Each step is idempotent — repeated calls don't double-clone or
double-enable. Disabling a plugin does **not** delete its clone on
disk; `POST /api/plugins/:id/uninstall` is the destructive path.

---

## Sandboxing + safety notes

- **install_command** and **run_command** run with the server's own
  uid/gid. If you wouldn't run an arbitrary shell script from the
  internet under that uid, don't install untrusted plugins.
- Path-traversal characters (`..`) and non-http(s)/ssh URLs are
  rejected at install-from-url time.
- Plugins cannot write outside their own install dir unless
  `run_command` explicitly does so. VulnForge sets
  `PWD=<install_dir>` and passes the output path as
  `{{output}}` so you don't have to compute it.
- AI routing only exposes plugins marked `ai_tasks` in the manifest.
  Other plugins are still user-runnable via REST / UI but won't be
  auto-dispatched by AI agents.

---

## Built-in integrations (for reference)

Look in `server/plugins/integrations/` for the TypeScript surface:

```
bandit.ts        Python SAST (pip install bandit)
codeql.ts        GitHub CodeQL
garak.ts         LLM red-team framework
grype.ts         SBOM vulnerability matcher
nettacker.ts     OWASP Nettacker network scanner
nuclei.ts        ProjectDiscovery nuclei
osv-scanner.ts   Google OSV dependency checker
safety.ts        Python safety (CVE DB)
semgrep.ts       Semgrep SAST
trivy.ts         Aqua Trivy
```

Each exports a `{ name, install, run, parse }` object. Mirror that
structure in your external plugin's `run.sh` + finding output and
VulnForge will treat it identically.

---

## Troubleshooting

| Symptom                                   | Fix                                                                 |
|-------------------------------------------|---------------------------------------------------------------------|
| "url must be http(s):// or git@"           | Remove `..` or weird chars; use a real clone URL                   |
| Install works but enable fails on `go`     | Click the green "Install go" chip in Plugins → Dependencies        |
| Run completes but 0 findings               | Check `parse_output` matches what `run_command` produces           |
| Findings appear with title "(no title)"    | Include a `title` string on every finding object                   |
| AI routing never picks my plugin           | Add `"ai_tasks": ["scan"]` to the manifest, re-install             |
| `POST /plugins/:id/run` returns 404         | Plugin isn't enabled — check the toggle in the UI                  |

File issues or plugin examples in the VulnForge repo's Discussions tab.

---
name: hunt
description: Start an autonomous vulnerability hunt on a Git repo, local path, or project
---

# VulnForge Hunt

Use this skill when the user wants to scan a repository or project for security vulnerabilities.

## Triggers
- "hunt <url>", "scan <url>", "test <url>", "check <repo> for vulnerabilities"
- "analyze this project for security issues"
- "find bugs in <project>"

## How to use

### Option 1: Via MCP (preferred — uses VulnForge's full pipeline)

Use the `start_pipeline` MCP tool:

```
start_pipeline({ url: "https://github.com/org/repo" })
```

Or for a local path:
```
start_pipeline({ path: "/path/to/project" })
```

Or for an existing project:
```
start_pipeline({ project_id: 1 })
```

Then monitor progress:
```
get_pipeline_status({ pipeline_id: "<returned_id>" })
```

When status is "ready", review findings:
```
list_scan_findings({ pipeline_id: "<id>", status: "pending" })
```

### Option 2: Via API (curl)

```bash
curl -X POST http://localhost:3001/api/pipeline/start \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/org/repo"}'
```

### Pipeline stages

The hunt runs automatically through:
1. **Clone** — git clone the repo
2. **Git Analysis** — find security-relevant commits and recently changed files
3. **Attack Surface** — map entry points, trust boundaries, pre-auth code
4. **Scan** — run 20-40 tools selected by language + CVE variant hunt + config audit
5. **Filter** — 5-tier false positive removal (regex → dedup → AI batch → dep reachability → chain detection)
6. **Verify** — AI reads actual source code, traces data flow, checks git blame
7. **Ready** — findings staged for user review

### After the hunt

Show the user the pipeline summary and offer to review findings:
- Accept: promotes finding to permanent vulnerability database
- Reject: marks as false positive with reason
- Skip: leave for later

Use `accept_scan_finding` / `reject_scan_finding` MCP tools to action findings.

---
name: status
description: Check VulnForge dashboard status and configuration
---

# VulnForge Status

Check overall platform status — findings, projects, pipelines, AI configuration.

## Triggers
- "status", "dashboard", "how many findings?"
- "what projects are imported?", "any active pipelines?"
- "which AI is configured?"

## MCP tools

Dashboard stats:
```
get_dashboard_stats()
```

List projects:
```
list_projects()
```

Active pipelines:
```
list_pipelines({ active_only: true })
```

Recent findings:
```
list_vulnerabilities({ limit: 10, sort: "found_at", order: "desc" })
```

AI routing config:
```
get_ai_routing()
```

## Quick health check

1. `get_dashboard_stats()` — total findings, severity breakdown
2. `list_pipelines({ active_only: true })` — any running?
3. `get_ai_routing()` — which models handle which tasks?

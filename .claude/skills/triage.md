---
name: triage
description: Triage and verify vulnerability findings with AI
---

# VulnForge Triage

AI-powered triage of vulnerability findings — severity assessment, exploitability analysis, and fix suggestions.

## Triggers
- "triage finding #42", "analyze this vulnerability", "is this exploitable?"
- "triage all new findings"

## MCP tools

Triage a single finding:
```
triage_finding({ id: 42, save_result: true })
```

Get full finding details:
```
get_vulnerability({ id: 42 })
```

Generate a fix suggestion (via API):
```bash
curl -X POST http://localhost:3001/api/ai/suggest-fix -d '{"vuln_id": 42}'
```

Deep analysis:
```bash
curl -X POST http://localhost:3001/api/ai/deep-analyze -d '{"vuln_id": 42}'
```

## Triage tiers

- **Tier A**: Private disclosure — pre-auth, deterministic, real deployments
- **Tier B**: Open PR — real defect but needs another bug to exploit
- **Tier C**: Internal note — theoretical, requires unrealistic conditions

## AI routing

Configure which AI model handles triage:
```
set_ai_routing({ preset: "smart-split" })
```

Available presets: `smart-split`, `all-claude`, `all-openai`, `all-gemini`, `all-local`, `budget`, `claude-cli`

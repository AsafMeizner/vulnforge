---
name: report
description: Generate vulnerability disclosure reports
---

# VulnForge Report

Generate disclosure reports for verified vulnerabilities.

## Triggers
- "write a disclosure for finding #42"
- "generate report", "create advisory"
- "email the maintainer about this bug"

## Report types

- **email** — Professional vendor notification email
- **advisory** — Public security advisory (CVE format)
- **summary** — Brief overview for internal use

## MCP tools

```
generate_report({ vuln_id: 42, type: "email" })
generate_report({ vuln_id: 42, type: "advisory" })
generate_report({ vuln_id: 42, type: "summary" })
```

## Workflow

1. Verify the finding is accurate (use triage skill)
2. Generate a report
3. Review the report text
4. Update finding status to "Submitted"
5. Track vendor response

```
update_vulnerability({ id: 42, status: "Submitted", submit_to: "security@project.org" })
```

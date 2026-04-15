---
name: review
description: Review staged scan findings — accept or reject
---

# VulnForge Review

Review staged scan findings from pipeline runs. Accept verified vulnerabilities, reject false positives.

## Triggers
- "review findings", "show pending findings", "what did the scan find?"
- "accept finding #5", "reject finding #7"

## MCP tools

List findings from a pipeline:
```
list_scan_findings({ pipeline_id: "pipe-abc123", status: "pending" })
```

List all pending findings:
```
list_scan_findings({ status: "pending" })
```

Accept a finding (promotes to vulnerabilities table):
```
accept_scan_finding({ id: 5 })
```

Reject a finding:
```
reject_scan_finding({ id: 7, reason: "False positive — error handling catches this" })
```

Bulk accept:
```
bulk_accept_findings({ ids: [5, 6, 8, 12] })
```

## Review criteria

For each finding, consider:
1. Is the code path reachable from external input?
2. Does error handling already prevent exploitation?
3. What's the real-world impact if exploited?
4. Would the maintainer accept this as a security fix?

## After review

Accepted findings appear on the Findings page and can be:
- Triaged (AI severity assessment)
- Reported (disclosure email, advisory, summary)
- Tracked (submitted → fixed → resolved)

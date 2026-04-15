---
name: scan
description: Run specific security analysis tools on a project
---

# VulnForge Scan

Run targeted security analysis tools on a project.

## Triggers
- "run <tool> on <project>", "scan for memory bugs", "check for SQL injection"
- "run all tools", "run crypto scanner"

## Available tool categories

**Memory safety** (C/C++): integer_overflow_scanner, cross_arch_truncation, uaf_detector, double_free_scanner, null_deref_hunter, realloc_dangling_scanner, boundary_check_scanner, stack_clash_vla_scanner

**Crypto/timing**: crypto_misuse_scanner, timing_oracle_scanner, hardcoded_secrets_scanner

**Network/protocol**: preauth_tracer, protocol_smuggling_scanner, state_machine_scanner, command_injection_scanner, deserialization_trust_scanner

**Code quality**: dangerous_patterns, signed_unsigned_checker, error_path_divergence, cleanup_order_scanner, macro_safety_scanner

**Supply chain**: supply_chain_scanner, dependency_tree_auditor

## MCP tools

```
run_tool({ tool_name: "integer_overflow_scanner", project_id: 1 })
```

List all tools:
```
# GET http://localhost:3001/api/tools
```

Run a plugin:
```
run_plugin({ plugin_name: "semgrep", target: "/path/to/project" })
```

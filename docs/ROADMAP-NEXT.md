# VulnForge - Next Roadmap

All 9 original themes are shipped. This is the roadmap for what comes next.

## Status: Shipped

| Cycle | Theme              | Commit    | Key Features                                 |
| ----- | ------------------ | --------- | -------------------------------------------- |
| 1     | Research Workspace | `a9ed621` | Notes, hypotheses, session state, Obsidian   |
| 2     | Runtime Analysis   | `8f59ace` | libFuzzer, gdb, tcpdump, nmap                |
| 3     | Historical Intel   | `4b2b1dd` | NVD sync, git bisect, patch analysis         |
| 4     | Exploit Dev        | `77dd384` | PoC workbench, proof ladder, templates       |
| 5     | AI Copilot         | `d14e923` | Investigate mode, assumptions, hypotheses    |
| 6     | Advanced Runtime   | `3713b64` | angr, core dumps, radare2                    |
| 7     | Pro UX             | `cc26741` | Command palette, shortcut overlay            |
| 8     | Disclosure Ops     | `ce5a252` | Vendor CRM, SLA tracking, bounty analytics   |
| 9     | Compliance         | `4ede935` | SARIF/CVE export, audit trail, backup        |
| -     | Docker Sandbox     | `bc39f95` | Isolated containers, pause/resume, snapshots |
| -     | UX Audit           | `870c63a` | Checklists rewrite, nav groups, URL import   |

## What's Next

### Phase 10: QEMU Full VM Support

- Full OS VMs (Windows, Linux, custom images)
- Multi-architecture (x86_64, ARM, MIPS, RISC-V)
- VNC screen capture → AI vision integration
- QMP machine protocol for snapshots/memory dumps
- UEFI/BIOS firmware testing
- Nested virtualization for hypervisor testing

### Phase 11: Headless Mode + Electron

- ✓ Headless mode (`--headless` or `VULNFORGE_HEADLESS=1`)
- Electron packaging with system tray icon
- Auto-start on boot option
- Notification support (OS-native toasts)
- Single-binary distribution

### Phase 12: Feature-Selective Installer

- Interactive CLI installer (`npx vulnforge install`)
- Choose features: core, runtime (Docker/QEMU), AI providers, plugins
- Auto-install dependencies (Python tools, Docker, Ollama, etc.)
- Disk space estimation per feature
- Upgrade/uninstall support

### Phase 13: AI Agent Integrations

- VS Code extension (inline findings, note capture)
- Cursor/Copilot MCP bridge
- ~~Open Claw integration~~ — shipped v0.1.0, see [docs/integrations/openclaw/README.md](./integrations/openclaw/README.md)
- Antigravity adapter
- REST API client SDKs (Python, TypeScript)

### Phase 14: Collaboration Features

- Multi-user with RBAC
- Shared workspaces
- Real-time collaboration on findings
- Git-backed finding history
- Encrypted storage (age/sops)

### Phase 15: Advanced AI

- AI-driven exploit generation
- Automated PoC validation in sandboxes
- Teach mode (learn from user confirmations)
- Pattern mining (extract patterns from confirmed bugs)
- Formal verification hooks (CBMC, SMACK)
- AI screen reading (VNC → Claude Vision)

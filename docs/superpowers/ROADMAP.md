# VulnForge Pro Roadmap

**Goal**: Turn VulnForge from a static-analysis dashboard into a full professional vulnerability research copilot - covering hypothesis tracking, exploit development, runtime analysis, disclosure ops, and AI-assisted investigation.

**Approach**: Decompose into 9 themed sub-projects. Each theme goes through its own cycle: **brainstorm → spec → plan → implement → ship**. Themes are mostly independent and can be built in any order, but dependencies below suggest an optimal sequence.

---

## Themes

### Theme 1: Research Workspace

Captures the _mental model_ a researcher builds. Everything else hooks into this.

- **Hypothesis journal**: write down hunches ("parseHeader probably has a UAF"), link to code locations, track status (open → investigating → confirmed → disproved)
- **Persistent notes**: timestamped, markdown, linked to files/findings/projects
- **Project timeline**: unified view of commits + scan findings + notes + AI investigations on one axis
- **Session restore**: when you return to a project, resume your last investigation state
- **Proof ladder** (shared with Theme 2): confidence tier per finding (pattern → manual review → traced → PoC → weaponized)

**Dependencies**: none
**Dependents**: all other themes read from this data model

---

### Theme 2: Exploit Development Loop

Takes findings from "theoretically exploitable" to working PoC without leaving the app.

- **PoC workbench**: in-app Monaco editor for writing exploit code (Python/C), tied to a finding
- **Proof ladder tracking** (UI): per finding, track advancement through tiers, show evidence for each tier
- **Crash minimizer**: reduce large crashing inputs to minimal triggers
- **Reproduction harness generator**: from a finding, scaffold a standalone test that triggers the bug
- **Exploit template library**: format string, ROP, heap feng shui, type confusion, deserialization - pick template, fill in blanks
- **Symbolic constraint extraction**: for a target buffer write, extract the constraints symbolically (links to Theme 3C)

**Dependencies**: Theme 1 (proof ladder lives in workspace), Theme 3B (debugger for PoC validation)
**Integrates**: pwntools, Python sandbox, LLM for template synthesis

---

### Theme 3: Runtime & Dynamic Analysis

The biggest delta vs. pure static analysis. Split into 6 sub-themes that share infrastructure (tool runner, output storage, UI patterns) but can ship independently.

#### 3A: Fuzzing

- AFL++, libFuzzer, Honggfuzz integration
- Auto-harness generation from function signatures (LLM-assisted)
- Corpus management (add, minimize, replay)
- Coverage tracking (via compiler instrumentation)
- Crash triage (dedupe, exploitability classification)

#### 3B: Debugger

- gdb/lldb/cdb CLI wrappers
- Breakpoint-based PoC validation ("break at this line, check register state, verify crash")
- Core dump parsing (ELF/PE/Mach-O)
- Crash minimization via delta debugging
- pwndbg/gef integration for enhanced output

#### 3C: Symbolic Execution

- angr for x86/ARM binaries
- KLEE for C/C++ source
- Constraint solver hooks (Z3)
- "Reach this branch" automation - generate crafted inputs
- Integration with Theme 2 exploit workbench

#### 3D: Network Analysis

- Packet capture: tcpdump / tshark with display filter support
- HTTPS MITM: mitmproxy integration with session replay
- Port/service scanning: nmap wrapper with result storage
- Traffic simulation: Linux `tc` for latency/loss/reordering
- ngrep-style payload search in pcaps
- Protocol fuzzing: boofuzz integration

#### 3E: Memory Forensics

- Process memory dump: gcore (Linux), cdb minidump (Windows)
- Heap analyzer: parse glibc heap, detect UAF/double-free, show chunk layout
- Leak detection: find pointers to freed memory
- Stack trace reconstruction from core dumps

#### 3F: Binary Analysis

- Disassembly: radare2 / rizin
- Decompilation: Ghidra headless mode
- Binary diffing: radiff2 / BinDiff-style for 1-day hunting
- Symbol recovery, function signature matching
- ROP gadget finder (ropper)

**Dependencies**: none, but 3C is most useful with 3A corpus
**Integrates**: Everything mentioned as CLI subprocess with parsed output

---

### Theme 4: Historical Intelligence

Finds regressions, hunts variants, learns from history.

- **Git bisect wrapper**: given a finding, auto-bisect to find the commit that introduced it
- **Patch analyzer**: load a security patch, extract its pattern, save to CVE library
- **1-day variant hunter**: when a new CVE drops, auto-search all imported projects for the pattern
- **CVE pattern library UI**: browse, edit, test patterns
- **NVD/GHSA sync**: pull known CVEs for imported dependencies
- **Cross-project correlation**: "this bug pattern has shown up in 5 other projects"

**Dependencies**: Theme 1 (patch analysis creates timeline entries)
**Integrates**: Git CLI, NVD API, GHSA API, existing cve-patterns.json

---

### Theme 5: Disclosure & Bounty Ops

Manages the business side of vuln research.

- **Vendor relationship manager**: contacts, preferred formats, typical response times
- **Disclosure timeline**: per-finding SLA tracking (e.g., 90-day window)
- **HackerOne / Bugcrowd / Intigriti API integration**: submit, track status, fetch payouts
- **Bounty analytics**: time invested vs. payout, ROI per program, winning tools
- **Disclosure calendar**: cross-vendor view of all active submissions
- **Template library**: email templates per vendor, advisory templates

**Dependencies**: Theme 1 (vendor interactions stored in notes), verified findings pipeline
**Integrates**: Platform APIs

---

### Theme 6: Pro UX Overhaul

Makes the platform a daily driver for researchers who live in their editor.

- **VSCode extension**: navigate findings from editor, jump to line, mark FP
- **Vim plugin**: same via LSP or direct API
- **Monaco editor embedded** in-app: full IDE feel for research notebook
- **Visual call graph**: interactive, clickable, danger zones highlighted
- **Finding graph**: show relationships between findings (chains, same-file, same-author)
- **Jupyter-style notebooks**: mix markdown, code, tool output, AI responses in one doc
- **Keyboard-first navigation**: every action reachable without mouse

**Dependencies**: Themes 1-4 (needs real data to display)
**Integrates**: Monaco, VSCode API, LSP

---

### Theme 7: Collaboration & Compliance

Enterprise/team features.

- **Multi-workspace**: separate workspaces for different employers/programs
- **RBAC**: roles (owner, researcher, reviewer, viewer)
- **Audit trail**: who did what when
- **Export formats**: SARIF 2.1, CVE JSON 5.0, STIX 2.1, CycloneDX (SBOM)
- **Import formats**: SARIF from CI, Semgrep results, CodeQL results
- **Encrypted storage**: age/sops for sensitive findings at rest
- **Offline mode**: air-gapped operation support

**Dependencies**: mature single-user workflow
**Integrates**: Standard formats, crypto libraries

---

### Theme 8: AI Copilot Upgrade

Evolves the AI from triage bot to true pair-researcher.

- **Investigate mode**: pick a finding, AI walks through it with you - shows evidence, proposes next steps, you approve each action (replaces the one-shot agent with an interactive loop)
- **Hypothesis auto-generation**: feed codebase to LLM, get prioritized list of "places to investigate"
- **Assumption extraction**: LLM reads a function and lists its assumptions (non-null inputs, bounds, invariants); user marks which are enforced
- **Teach mode**: when you confirm a bug, walk the reasoning with the AI and save it as a training example
- **Pattern mining**: confirmed findings get auto-extracted into patterns for future hunts
- **Contract verification**: formal verification hooks for small critical functions (CBMC, SMACK)

**Dependencies**: Themes 1, 4 (needs journal data + history), existing AI router
**Integrates**: Existing provider infrastructure, optionally CBMC/SMACK

---

### Theme 9: Polish & Infrastructure

Not a single big feature - a collection of reliability and DX improvements.

- **Docker reproducible environments**: per-project containerized build/run
- **Pre-built vulnerable target images**: DVWA, WebGoat, juice-shop, known-CVE-vulnerable binaries
- **Distributed scan workers**: farm scans across multiple machines
- **Settings UX**: unified settings page with search
- **Onboarding tour**: first-run walkthrough
- **Keyboard shortcut overlay** (? key)
- **Export/import of entire VulnForge workspace** (for backup/migration)
- **Performance profiling**: scan runtime analytics, slow tool detection
- **Finding linking graph** (visual): see how findings relate across projects

**Dependencies**: mature platform
**Integrates**: Docker API, optional Redis for distributed jobs

---

## Build Order

| Cycle | Themes             | Approx. effort | Rationale                                           |
| ----- | ------------------ | -------------- | --------------------------------------------------- |
| **1** | Theme 1            | Medium         | Data model everything else depends on               |
| **2** | Theme 3A + 3B + 3D | Large          | Highest delta in new bugs; prerequisite for Theme 2 |
| **3** | Theme 4            | Medium         | Immediate value on every finding, independent       |
| **4** | Theme 2            | Large          | Needs Theme 1 + 3B as foundation                    |
| **5** | Theme 8            | Medium-Large   | Needs data from 1-4 to be truly useful              |
| **6** | Theme 3C + 3E + 3F | Large          | Specialist runtime features complementing 3A/3B     |
| **7** | Theme 6            | Large          | Pro UX shipped once core is solid                   |
| **8** | Theme 5            | Medium         | Only matters with mature finding flow               |
| **9** | Theme 7 + 9        | Large          | Team/polish once single-user is excellent           |

Each cycle produces:

- A design spec in `docs/superpowers/specs/YYYY-MM-DD-<theme>-design.md`
- An implementation plan alongside
- Code, tests, and a commit

---

## Meta principles

1. **Integrate, don't reimplement** - every runtime tool is a CLI wrapper + parser + storage
2. **Small, independent units** - each sub-feature should be usable without the rest
3. **No-AI fallback** - the platform must work without any AI provider (already true)
4. **Offline-first** - don't assume network, don't require cloud
5. **Import/export everything** - no vendor lock-in, SARIF/CVE-JSON as native formats

# Theme 3 (Cycle 2): Runtime & Dynamic Analysis — Core MVP

**Status**: Approved, in implementation
**Scope**: 3A Fuzzing (libFuzzer), 3B Debugger (gdb), 3D Network (tcpdump/tshark + nmap)
**Deferred**: AFL++, Honggfuzz, LLM harness-gen, mitmproxy, core dump parsing, lldb/cdb, symbolic execution, binary analysis

## Goal

Move VulnForge beyond static analysis to runtime bug hunting. Wrap battle-tested CLI tools behind a unified "runtime job" framework so future tools (AFL++, lldb, mitmproxy, angr, radare2) become drop-in additions.

## Unified Runtime Job Framework

Every runtime operation is a **runtime job** with the same lifecycle:

```
queued → starting → running → (paused|completed|failed|cancelled)
```

### Data model

```sql
CREATE TABLE runtime_jobs (
  id TEXT PRIMARY KEY,                  -- UUID
  project_id INTEGER,
  finding_id INTEGER,                   -- optional: job is scoped to a specific finding
  type TEXT NOT NULL,                   -- fuzz | debug | capture | portscan | mitm
  tool TEXT NOT NULL,                   -- libfuzzer | afl | gdb | lldb | tcpdump | tshark | nmap | mitmproxy
  status TEXT DEFAULT 'queued',
  config TEXT DEFAULT '{}',             -- tool-specific JSON config
  output_dir TEXT,                      -- working/output directory on disk
  stats TEXT DEFAULT '{}',              -- JSON counters: exec_count, crashes, coverage, packets, etc.
  error TEXT,
  started_at TEXT DEFAULT (datetime('now')),
  completed_at TEXT,
  FOREIGN KEY (project_id) REFERENCES projects(id),
  FOREIGN KEY (finding_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE fuzz_crashes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  stack_hash TEXT,                      -- for dedup (md5 of normalized stack trace)
  input_path TEXT NOT NULL,             -- path to crashing input file
  input_size INTEGER,
  signal TEXT,                          -- SIGSEGV, SIGABRT, SIGBUS, etc.
  stack_trace TEXT,                     -- text
  exploitability TEXT DEFAULT 'unknown',-- high | medium | low | unknown
  minimized INTEGER DEFAULT 0,
  linked_finding_id INTEGER,
  discovered_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (job_id) REFERENCES runtime_jobs(id),
  FOREIGN KEY (linked_finding_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE captures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  pcap_path TEXT NOT NULL,
  packet_count INTEGER DEFAULT 0,
  bytes INTEGER DEFAULT 0,
  filter TEXT,                          -- BPF filter expression
  start_time TEXT,
  end_time TEXT,
  FOREIGN KEY (job_id) REFERENCES runtime_jobs(id)
);
```

### Job runner

```typescript
interface RuntimeJobSpec {
  type: 'fuzz' | 'debug' | 'capture' | 'portscan' | 'mitm';
  tool: string;
  projectId?: number;
  findingId?: number;
  config: Record<string, any>;
}

interface RuntimeJob extends RuntimeJobSpec {
  id: string;
  status: 'queued' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
  outputDir: string;
  stats: Record<string, any>;
  error?: string;
  startedAt: string;
  completedAt?: string;
}

class RuntimeJobRunner {
  start(spec: RuntimeJobSpec): Promise<string>      // returns job id
  stop(jobId: string): Promise<void>
  getStatus(jobId: string): RuntimeJob | null
  list(filter?: { status?, type?, projectId?, findingId? }): RuntimeJob[]
  onEvent(jobId: string, handler: (ev: JobEvent) => void): void
}
```

The runner dispatches to a tool-specific executor:
- `fuzz + libfuzzer` → `server/pipeline/runtime/fuzzers/libfuzzer.ts`
- `debug + gdb` → `server/pipeline/runtime/debuggers/gdb.ts`
- `capture + tcpdump|tshark` → `server/pipeline/runtime/network/pcap.ts`
- `portscan + nmap` → `server/pipeline/runtime/network/nmap.ts`

Each executor gets a `JobContext` (job id, output dir, `emit(event)` callback, `shouldStop()` check).

### WebSocket events

`broadcastProgress('runtime', jobId, { step, detail, progress, stats, status })` — pipeline already has this pattern.

Additional event types:
- `runtime:fuzz-crash` — new crash detected
- `runtime:packet` — new packet in capture (batched, not per-packet)
- `runtime:debug-break` — debugger hit a breakpoint
- `runtime:stats-update` — periodic counter update

## Tool Wrappers

### 3A: libFuzzer (`fuzzers/libfuzzer.ts`)

libFuzzer is a library built into clang via `-fsanitize=fuzzer`. You compile a harness that calls `LLVMFuzzerTestOneInput(data, size)`, and clang produces a self-contained fuzzer binary. Pros: no forkserver setup like AFL++, runs in-process, fast.

Config:
```typescript
{
  harness_path: string,       // path to compiled fuzzer binary
  corpus_dir: string,         // input corpus directory
  crash_dir: string,          // output crashes directory
  max_len?: number,           // max input size
  max_total_time?: number,    // seconds
  runs?: number,              // or number of runs
  dictionary?: string,        // path to dictionary file
  args?: string[],            // extra libFuzzer flags
}
```

Executor:
- spawns `harness_path CORPUS_DIR -artifact_prefix=CRASH_DIR/ -print_final_stats=1 [extra args]`
- streams stdout: parses libFuzzer output lines like `#1234 NEW cov: 5678 ft: 8901 corp: 23/500b lim: 50 exec/s: 12345 rss: 123Mb`
- on crash detection (`==ERROR:`): extract stack trace, compute stack hash, create `fuzz_crashes` row
- on completion: emit `runtime:stats-update` with final exec count, coverage, etc.

### 3A: Harness generator (`fuzzers/harness-gen.ts`)

Given a target function signature (e.g., `parse_packet(uint8_t *data, size_t len)`), generate a libFuzzer harness template:

```c
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    parse_packet((uint8_t*)Data, Size);
    return 0;
}
```

For functions with more complex signatures (e.g., struct inputs), generate a stub and leave TODO comments for the user to fill in. No LLM yet — just template-based generation. LLM-assisted generation is Cycle 2b.

### 3A: Crash triage (`fuzzers/crash-triage.ts`)

- `dedupe(crashes)` — group by `stack_hash`
- `classifyExploitability(crash)` — simple heuristic: SIGSEGV + write to controlled address = high; SIGABRT = medium; SIGFPE/SIGBUS = low
- `linkToFinding(crashId, findingId)` — update `linked_finding_id`

### 3B: gdb wrapper (`debuggers/gdb.ts`)

Thin wrapper around `gdb --batch -ex` for non-interactive commands, and `gdb --interpreter=mi` for interactive sessions.

Non-interactive operations:
- `runWithBreakpoint(binary, args, breakpoint, checkExpr?)` — run program under gdb, set breakpoint, return whether it hit + register state
- `analyzeCore(binary, corePath)` — load core dump, extract backtrace, register state, signal info
- `extractStackTrace(binary, corePath)` — just the stack

Interactive operations (deferred to Cycle 2b — need MI protocol parser).

Config:
```typescript
{
  binary_path: string,
  args?: string[],
  breakpoint?: string,         // e.g. "src/parser.c:234" or "function_name"
  check_expr?: string,         // e.g. "*(int*)ptr" to eval at breakpoint
  core_path?: string,          // for core dump analysis
  timeout?: number,            // default 60s
}
```

### 3D: Packet capture (`network/pcap.ts`)

Wraps `tcpdump` (capture) and `tshark` (parse).

Start capture:
```
tcpdump -i {iface} -w {pcap_path} -U {bpf_filter}
```

Parse:
```
tshark -r {pcap_path} -T json  (or -T fields for summary)
```

Config:
```typescript
{
  interface: string,            // 'eth0', 'lo', etc.
  filter?: string,              // BPF filter
  duration?: number,            // seconds (auto-stop)
  max_packets?: number,
  promiscuous?: boolean,
}
```

Executor starts tcpdump, streams packet count updates, on stop runs tshark to get summary stats, creates `captures` row.

### 3D: Nmap wrapper (`network/nmap.ts`)

Wraps `nmap -oX -` (XML output to stdout) for port/service scanning.

Config:
```typescript
{
  target: string,               // IP, hostname, CIDR, range
  ports?: string,               // '-p 80,443' or '-p-' for all
  scan_type?: 'syn' | 'connect' | 'udp' | 'version' | 'script',
  scripts?: string[],           // NSE scripts
  timing?: number,              // -T0 to -T5
}
```

Parses XML output, stores in job stats, creates a compact summary. Full XML kept in `{output_dir}/nmap.xml`.

## REST API (`server/routes/runtime.ts`)

```
GET    /api/runtime                             — list jobs (filter by status/type/project/finding)
POST   /api/runtime                             — start a job
GET    /api/runtime/:id                         — get job details + recent output
POST   /api/runtime/:id/stop                    — stop a running job
DELETE /api/runtime/:id                         — delete job + output dir
GET    /api/runtime/:id/output?tail=N           — stream/tail job output

# Fuzz-specific
GET    /api/runtime/:id/crashes                 — list crashes for a fuzz job
POST   /api/runtime/crashes/:id/link            — link crash to a finding
POST   /api/runtime/crashes/:id/triage          — run triage (dedupe+classify)
GET    /api/runtime/crashes/:id/input           — download the crashing input

# Capture-specific
GET    /api/runtime/:id/packets?limit=N&offset=N  — list packets (parsed from pcap)
GET    /api/runtime/:id/pcap                      — download raw pcap

# Harness gen
POST   /api/runtime/harness-gen                   — generate libFuzzer harness from function signature
                                                     body: { function_signature, language }
```

## MCP Tools (append to server/mcp/tools.ts)

1. `start_runtime_job` — generic job starter, takes type/tool/config
2. `list_runtime_jobs` — filter by status/type/project
3. `get_runtime_job` — full status + stats + recent output
4. `stop_runtime_job` — stop a running job
5. `start_fuzz_campaign` — shortcut for `type=fuzz tool=libfuzzer`
6. `list_crashes` — list crashes across all fuzz jobs or for specific job
7. `link_crash_to_finding` — associate a crash with a vulnerability
8. `start_packet_capture` — shortcut for tcpdump
9. `start_port_scan` — shortcut for nmap
10. `debug_with_breakpoint` — run gdb with a breakpoint and return hit status

## Frontend

New page: `src/pages/Runtime.tsx`
- Tabs: All Jobs | Fuzzing | Debugger | Network
- Each tab shows a filtered job list
- Click a job → detail view with live output, stats, actions

New components:
- `src/components/FuzzCampaignCard.tsx` — fuzz job summary (exec/s, coverage, crashes)
- `src/components/CaptureViewerCard.tsx` — capture summary + top talkers
- `src/components/DebugSessionCard.tsx` — gdb session status + actions

New keyboard shortcut: Ctrl+Shift+R → opens "New runtime job" modal.

`App.tsx` additions:
- `'runtime'` in Page union + VALID_PAGES
- Nav icon (terminal/spawn shape)
- Register route + page content

## Parallel Build Plan

**Main thread (foundation):**
1. Spec doc ✓
2. DB schema + CRUD helpers (runtime_jobs, fuzz_crashes, captures)
3. Shared types file `server/pipeline/runtime/types.ts`

**Subagent A — Job runner + REST API**
- `server/pipeline/runtime/job-runner.ts` — unified runner
- `server/routes/runtime.ts` — full REST API
- Register route in `server/index.ts`

**Subagent B — Tool wrappers**
- `server/pipeline/runtime/fuzzers/libfuzzer.ts`
- `server/pipeline/runtime/fuzzers/harness-gen.ts`
- `server/pipeline/runtime/fuzzers/crash-triage.ts`
- `server/pipeline/runtime/debuggers/gdb.ts`
- `server/pipeline/runtime/network/pcap.ts`
- `server/pipeline/runtime/network/nmap.ts`

**Subagent C — MCP tools**
- Append 10 runtime tools to `server/mcp/tools.ts`

**Subagent D — Frontend**
- `src/pages/Runtime.tsx`
- `src/components/FuzzCampaignCard.tsx`
- `src/components/CaptureViewerCard.tsx`
- `src/components/NewRuntimeJobModal.tsx`
- `src/lib/api.ts` additions
- `src/App.tsx` wiring

## Success Criteria

- Start a libFuzzer job with a pre-built harness → see live exec/s counter, coverage, crash count
- Produce a crash → see it listed in the crashes table with stack hash and signal
- Link a crash to an existing finding → appears in the finding's context
- Start a tcpdump capture → see packet count increasing → stop → download pcap
- Run an nmap scan → see parsed results (open ports, service versions) in the UI
- External Claude Code can `start_fuzz_campaign` via MCP and poll for crashes
- Restart backend, `runtime_jobs` with status='running' show as 'interrupted' and can be resumed

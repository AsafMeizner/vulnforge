/**
 * Runtime Analysis shared types (Theme 3)
 *
 * All runtime tools (fuzzers, debuggers, network capture) implement the
 * RuntimeJobExecutor interface and share a unified lifecycle.
 */

export type RuntimeJobType = 'fuzz' | 'debug' | 'capture' | 'portscan' | 'mitm';
export type RuntimeJobStatus = 'queued' | 'starting' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';

export interface RuntimeJobSpec {
  type: RuntimeJobType;
  tool: string;
  projectId?: number;
  findingId?: number;
  config: Record<string, any>;
}

export interface RuntimeJob extends RuntimeJobSpec {
  id: string;
  status: RuntimeJobStatus;
  outputDir: string;
  stats: Record<string, any>;
  error?: string;
  startedAt: string;
  completedAt?: string;
}

export interface JobEvent {
  type: 'start' | 'output' | 'stats' | 'crash' | 'complete' | 'error';
  data?: any;
  timestamp: string;
}

export interface JobContext {
  jobId: string;
  outputDir: string;
  config: Record<string, any>;
  projectId?: number;
  findingId?: number;

  /** Emit a progress event (stats, output, etc.) — broadcasted via WebSocket. */
  emit(ev: Omit<JobEvent, 'timestamp'>): void;

  /** Update persisted stats for this job (merged with existing stats). */
  updateStats(stats: Record<string, any>): void;

  /** Check if the job should stop (cancelled/paused). Call periodically in long loops. */
  shouldStop(): boolean;
}

export interface RuntimeJobExecutor {
  readonly type: RuntimeJobType;
  readonly tool: string;

  /** Validate config before starting. Throw with clear message on error. */
  validate(config: Record<string, any>): void;

  /** Run the job. Returns when complete; should respect ctx.shouldStop(). */
  execute(ctx: JobContext): Promise<void>;
}

// ── Fuzz-specific types ────────────────────────────────────────────────────

export interface FuzzConfig {
  harness_path: string;
  corpus_dir?: string;
  crash_dir?: string;
  max_len?: number;
  max_total_time?: number;
  runs?: number;
  dictionary?: string;
  args?: string[];
}

export interface FuzzStats {
  exec_count?: number;
  exec_per_sec?: number;
  coverage?: number;
  corpus_size?: number;
  crashes?: number;
  cycles?: number;
  max_depth?: number;
  paths_total?: number;
  rss_mb?: number;
}

export interface CrashInfo {
  stack_hash: string;
  input_path: string;
  input_size: number;
  signal?: string;
  stack_trace?: string;
  exploitability?: 'high' | 'medium' | 'low' | 'unknown';
}

// ── Debugger types ─────────────────────────────────────────────────────────

export interface DebugConfig {
  binary_path: string;
  args?: string[];
  breakpoint?: string;        // "file:line" or "function_name"
  check_expr?: string;        // expression to evaluate at breakpoint
  core_path?: string;
  timeout?: number;
}

export interface DebugResult {
  hit_breakpoint: boolean;
  signal?: string;
  exit_code?: number;
  stack_frames?: Array<{ function: string; file?: string; line?: number; address?: string }>;
  registers?: Record<string, string>;
  eval_result?: string;
  raw_output: string;
}

// ── Network types ──────────────────────────────────────────────────────────

export interface CaptureConfig {
  interface: string;
  filter?: string;            // BPF expression
  duration?: number;          // seconds
  max_packets?: number;
  promiscuous?: boolean;
}

export interface CaptureStats {
  packet_count: number;
  bytes: number;
  dropped?: number;
}

export interface PortScanConfig {
  target: string;
  ports?: string;             // '80,443', '-p-', etc.
  scan_type?: 'syn' | 'connect' | 'udp' | 'version' | 'script';
  scripts?: string[];
  timing?: number;
  timeout?: number;
}

export interface PortScanResult {
  hosts: Array<{
    address: string;
    hostname?: string;
    state: string;
    ports: Array<{
      port: number;
      protocol: string;
      state: string;
      service?: string;
      version?: string;
      extra?: Record<string, any>;
    }>;
  }>;
  summary: {
    total_hosts: number;
    up_hosts: number;
    total_ports: number;
    open_ports: number;
  };
}

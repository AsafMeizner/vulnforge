/**
 * Track J — AI Accuracy & Self-Consistency
 *
 * Shared types used across self-consistency voting, cross-finding dedup,
 * PoC-on-demand, and confidence calibration.
 */

import type { VerificationResult } from '../prompts/verify.js';

// ── Self-consistency ───────────────────────────────────────────────────────

/**
 * Configuration for N-vote self-consistency verification.
 *
 * `n` = number of independent votes to cast (recommended: 3).
 * `threshold` = minimum fraction of agreeing votes to return `verified=true`.
 *   Below `threshold` we fall back to `reason: 'inconsistent'`.
 */
export interface ConsistencyConfig {
  n: number;
  threshold: number;
}

/** Single AI vote — one of N runs in a self-consistency loop. */
export interface VerifyVote {
  /** Temperature used for this vote. */
  temperature: number;
  /** Parsed result, or null if the response could not be parsed. */
  result: VerificationResult | null;
  /** Raw response text — handy for logging / debugging. */
  raw?: string;
  /** Provider that answered this vote (if known). */
  provider?: string;
  /** Error message if this vote failed entirely. */
  error?: string;
}

/**
 * Aggregate result of an N-vote self-consistency run.
 *
 * - `verified` — true iff a majority (>= threshold) of parseable votes agreed
 *   `verified=true`. Tied or scattered votes yield `verified=false` with
 *   `reason='inconsistent'`.
 * - `confidence` — agreeing_votes / N (0..1). For ties this is <= 0.5.
 * - `votes` — the raw votes, preserved for audit / replay.
 * - `reason` — short human-readable explanation of the verdict.
 * - `result` — averaged VerificationResult across agreeing votes (majority
 *   CWE, average CVSS, mode severity). Null if no agreeing votes.
 */
export interface VerificationAggregate {
  verified: boolean;
  confidence: number;
  votes: VerifyVote[];
  reason: string;
  result: VerificationResult | null;
}

// ── Cross-finding dedup ────────────────────────────────────────────────────

/**
 * Group of findings that map to the same logical bug.
 * The `representative` is the finding we feed into verification; the verdict
 * propagates to all `duplicates`.
 */
export interface FindingGroup<T = any> {
  /** Stable group key: `${cwe}|${normalized_title}|${function_sig}`. */
  key: string;
  /** Canonical finding used for AI verification (highest-severity pick). */
  representative: T;
  /** Other findings that collapsed into this group. */
  duplicates: T[];
  /** Total count — always `1 + duplicates.length`. */
  count: number;
}

// ── PoC runner ─────────────────────────────────────────────────────────────

/**
 * Sandbox specification for running an AI-generated PoC.
 * We hook into the existing runtime runner via `type` + `tool` + `config`,
 * but we provide defaults so callers can just pass `{ language }`.
 */
export interface SandboxSpec {
  /** Language of the reproducer script: 'bash' | 'python' | 'javascript'. */
  language: 'bash' | 'python' | 'javascript';
  /** Max wall time for the run in milliseconds. Default: 30_000. */
  timeoutMs?: number;
  /** Optional runtime job type — defaults to 'sandbox'. */
  jobType?: string;
  /** Optional runtime tool — defaults to 'docker-sandbox'. */
  tool?: string;
  /** Optional extra config merged into the runtime job spec. */
  extraConfig?: Record<string, any>;
  /** Optional injected runner for testing; falls back to the real singleton. */
  runner?: {
    start: (spec: {
      type: string;
      tool: string;
      findingId?: number;
      config: Record<string, any>;
    }) => Promise<string>;
    getStatus: (jobId: string) => {
      status: string;
      stats?: string;
      error?: string;
    } | null;
    stop?: (jobId: string) => Promise<boolean>;
  };
}

/** Result of generating + running a PoC in a sandbox. */
export interface PoCResult {
  succeeded: boolean;
  evidence: string;
  duration_ms: number;
  script?: string;
  /** If succeeded, callers should elevate the finding's confidence. */
  elevated_confidence?: number;
}

// ── Calibration ────────────────────────────────────────────────────────────

/**
 * Running reliability stats for one (provider, task) pair.
 * Beta(1,1) priors ensure un-seen pairs start with confidence = 0.5.
 */
export interface CalibrationRow {
  provider: string;
  task: string;
  true_positive: number;   // AI said yes, human agreed
  false_positive: number;  // AI said yes, human disagreed
  true_negative: number;   // AI said no, human agreed
  false_negative: number;  // AI said no, human disagreed
  updated_at?: string;
}

/** Accepted human verdicts on an AI decision. */
export type HumanVerdict = 'confirmed' | 'rejected';

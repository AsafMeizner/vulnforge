/**
 * J2 — Self-consistency voting.
 *
 * Runs `routeAI` N times with varied temperatures, parses each with the
 * existing `parseVerifyResponse`, and returns a majority-vote verdict.
 *
 * Why: LLM verifications can be noisy. A single "yes" at T=0.3 is much less
 * reliable than 3-of-3 agreement across T=0.1/0.3/0.5. This module is meant
 * to be a drop-in replacement for the single-call in `ai-verify.ts` (the
 * integrator wires it up — we only expose the function here).
 */

import { routeAI } from '../router.js';
import {
  VERIFY_SYSTEM_PROMPT,
  buildVerifyPrompt,
  parseVerifyResponse,
  type VerificationResult,
} from '../prompts/verify.js';
import type {
  ConsistencyConfig,
  VerificationAggregate,
  VerifyVote,
} from './types.js';

/**
 * Default spread of temperatures for N=3. For other N values we interpolate
 * linearly between 0.1 and 0.7.
 */
const DEFAULT_TEMPERATURES: Record<number, number[]> = {
  1: [0.3],
  2: [0.1, 0.5],
  3: [0.1, 0.3, 0.5],
  4: [0.1, 0.25, 0.4, 0.6],
  5: [0.1, 0.2, 0.3, 0.45, 0.6],
};

function pickTemperatures(n: number): number[] {
  if (DEFAULT_TEMPERATURES[n]) return DEFAULT_TEMPERATURES[n];
  if (n <= 0) return [0.3];
  // Linear spread for uncommon N.
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    out.push(0.1 + (0.6 * i) / Math.max(1, n - 1));
  }
  return out;
}

// ── Aggregation helpers (exported for tests) ───────────────────────────────

/** Parse "7.5" or "CVSS:3.1/AV:N/…" and return the base-score number. */
export function parseCvssScore(raw: string | undefined): number | null {
  if (!raw) return null;
  const trimmed = String(raw).trim();
  // Try to match a leading number like "7.5" or inside a vector.
  const match = trimmed.match(/(\d+(?:\.\d+)?)/);
  if (!match) return null;
  const n = parseFloat(match[1]);
  if (Number.isNaN(n)) return null;
  // CVSS is 0–10. Clamp defensively.
  if (n < 0 || n > 10) return null;
  return n;
}

/** Pick the most common value in a list. Ties broken by the first to appear. */
export function mode<T>(values: T[]): T | null {
  if (values.length === 0) return null;
  const counts = new Map<T, number>();
  for (const v of values) counts.set(v, (counts.get(v) || 0) + 1);
  let best: T | null = null;
  let bestCount = 0;
  for (const [v, c] of counts) {
    if (c > bestCount) {
      best = v;
      bestCount = c;
    }
  }
  return best;
}

/**
 * Average two or more VerificationResult objects (the "agreeing votes" subset).
 * - verified: taken from the majority (guaranteed same across inputs by caller)
 * - cvss_score: mean of numeric scores, rounded to 1 decimal, or '' if none
 * - cwe: mode across votes; ties → first occurrence
 * - severity: mode (Critical > High > Medium > Low)
 * - all string fields: pick the longest non-empty value (most informative)
 * - booleans: majority vote
 */
export function averageResults(
  results: VerificationResult[],
): VerificationResult | null {
  if (results.length === 0) return null;
  if (results.length === 1) return results[0];

  const cvssNums = results
    .map(r => parseCvssScore(r.cvss_score))
    .filter((n): n is number => typeof n === 'number');
  const avgCvss =
    cvssNums.length > 0
      ? (cvssNums.reduce((a, b) => a + b, 0) / cvssNums.length).toFixed(1)
      : '';

  const pickLongest = (k: keyof VerificationResult): string => {
    let best = '';
    for (const r of results) {
      const v = String(r[k] ?? '');
      if (v.length > best.length) best = v;
    }
    return best;
  };

  const majBool = (k: keyof VerificationResult): boolean => {
    let yes = 0;
    for (const r of results) if (Boolean(r[k])) yes++;
    return yes > results.length / 2;
  };

  return {
    verified: majBool('verified'),
    confidence: mode(results.map(r => r.confidence)) || 'Medium',
    verification_reason: pickLongest('verification_reason'),
    exploitability: mode(results.map(r => r.exploitability)) || 'None',
    data_flow_reachable: majBool('data_flow_reachable'),
    error_handling_present: majBool('error_handling_present'),
    enriched_title: pickLongest('enriched_title'),
    enriched_description: pickLongest('enriched_description'),
    enriched_impact: pickLongest('enriched_impact'),
    enriched_fix: pickLongest('enriched_fix'),
    severity: mode(results.map(r => r.severity)) || 'Medium',
    cvss_score: avgCvss,
    cvss_vector: pickLongest('cvss_vector'),
    cwe: mode(results.map(r => r.cwe)) || '',
    tier: mode(results.map(r => r.tier)) || 'C',
  };
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Finding shape we accept. We use a structural subset that matches both the
 * DB `ScanFinding` row and the plain-object fixtures used in tests, so we
 * don't import the DB types here.
 */
export interface ConsistencyFinding {
  title: string;
  description?: string;
  severity?: string;
  cwe?: string;
  file?: string;
  line_start?: number;
  tool_name?: string;
  code_snippet?: string;
}

/**
 * Run self-consistency voting. Returns a `VerificationAggregate` with the
 * majority verdict, confidence (agreeing_votes / N), and averaged fields
 * from agreeing votes.
 *
 * Contract:
 * - `config.n >= 1`. We call `routeAI` exactly `config.n` times.
 * - Temperatures varied across 0.1/0.3/0.5 for N=3 (spec default).
 * - Tied votes → `verified=false`, `reason='inconsistent'`, confidence = tie_size / N.
 * - Failed parses count as abstentions — they do not vote either way.
 * - If ALL votes fail to parse, returns `verified=false, reason='no_parseable_votes'`.
 *
 * @param finding        The finding to verify.
 * @param config         { n, threshold } — see `ConsistencyConfig`.
 * @param projectName    Optional project name for the prompt (default 'project').
 * @param sourceContext  Optional ±50 lines of source around the finding.
 */
export async function verifyWithConsistency(
  finding: ConsistencyFinding,
  config: ConsistencyConfig,
  projectName = 'project',
  sourceContext = '',
): Promise<VerificationAggregate> {
  const n = Math.max(1, Math.floor(config.n));
  const threshold = Math.max(0, Math.min(1, config.threshold));
  const temps = pickTemperatures(n);

  const prompt = buildVerifyPrompt(finding as any, sourceContext, projectName);
  const votes: VerifyVote[] = [];

  // Fire votes sequentially to respect AI-provider rate limits.
  // The integrator can parallelize later if needed; integration is out of scope
  // for this track.
  for (let i = 0; i < n; i++) {
    const temperature = temps[i];
    try {
      const resp = await routeAI({
        messages: [{ role: 'user', content: prompt }],
        systemPrompt: VERIFY_SYSTEM_PROMPT,
        temperature,
        maxTokens: 2048,
        task: 'verify',
      });
      const parsed = parseVerifyResponse(resp.content);
      votes.push({
        temperature,
        result: parsed,
        raw: resp.content,
        provider: resp.provider,
      });
    } catch (err: any) {
      votes.push({
        temperature,
        result: null,
        error: err?.message || String(err),
      });
    }
  }

  return aggregateVotes(votes, threshold, n);
}

/**
 * Aggregate a list of votes into a VerificationAggregate. Separated from the
 * async call path so the tie-breaking logic can be unit-tested directly with
 * synthetic VerifyVote[] inputs.
 */
export function aggregateVotes(
  votes: VerifyVote[],
  threshold: number,
  n = votes.length,
): VerificationAggregate {
  const parseable = votes.filter(v => v.result !== null);
  if (parseable.length === 0) {
    return {
      verified: false,
      confidence: 0,
      votes,
      reason: 'no_parseable_votes',
      result: null,
    };
  }

  let yesCount = 0;
  let noCount = 0;
  for (const v of parseable) {
    if (v.result!.verified) yesCount++;
    else noCount++;
  }

  // Confidence always normalized over N, not just parseable votes — unparsed
  // votes drag the confidence down as they should.
  const majorityCount = Math.max(yesCount, noCount);
  const confidence = majorityCount / n;

  // Tie or too-close-to-call → inconsistent.
  if (yesCount === noCount) {
    return {
      verified: false,
      confidence,
      votes,
      reason: 'inconsistent',
      result: null,
    };
  }

  const majorityVerified = yesCount > noCount;
  const agreeingVotes = parseable.filter(
    v => v.result!.verified === majorityVerified,
  );

  // Apply threshold — if we don't have enough agreement, flag inconsistent.
  if (confidence < threshold) {
    return {
      verified: false,
      confidence,
      votes,
      reason: 'inconsistent',
      result: null,
    };
  }

  const averaged = averageResults(agreeingVotes.map(v => v.result!));
  if (averaged) averaged.verified = majorityVerified;

  return {
    verified: majorityVerified,
    confidence,
    votes,
    reason: majorityVerified ? 'majority_verified' : 'majority_rejected',
    result: averaged,
  };
}

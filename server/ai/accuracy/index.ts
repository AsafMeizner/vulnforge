/**
 * Track J — AI Accuracy & Self-Consistency — public entrypoint.
 *
 * One place for the integrator (ai-verify.ts) to import from. All symbols
 * here are stable, documented, and intended for external use.
 */

// Types
export type {
  ConsistencyConfig,
  VerifyVote,
  VerificationAggregate,
  FindingGroup,
  SandboxSpec,
  PoCResult,
  CalibrationRow,
  HumanVerdict,
} from './types.js';

// Self-consistency voting
export {
  verifyWithConsistency,
  aggregateVotes,
  averageResults,
  parseCvssScore,
  mode,
  type ConsistencyFinding,
} from './self-consistency.js';

// Cross-finding deduplication
export {
  dedupFindings,
  groupKey,
  normalizeTitle,
  extractFunctionSignature,
  propagateVerdict,
  type DedupFinding,
} from './cross-finding-dedup.js';

// Confidence calibration
export {
  recordReviewOutcome,
  getCalibratedConfidence,
  getCalibrationRow,
  listCalibrationRows,
  ensureCalibrationTable,
  classifyOutcome,
  computePrecisionAndNpv,
} from './calibration.js';

// PoC-on-demand lives in server/pipeline/poc-runner.ts per the track spec —
// re-export here so the integrator has one import path.
export {
  generateAndRunPoC,
  detectExploitationMarkers,
  cleanAIScript,
  buildSandboxCommand,
  resolveRunner,
  type PoCFinding,
} from '../../pipeline/poc-runner.js';

import type { Vulnerability } from '../db.js';

// ── False-positive path patterns ───────────────────────────────────────────

const FP_PATH_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /test[\/\\]|_test\.|\.test\.|tests[\/\\]|unittest|fuzztest/i, reason: 'Test file' },
  { pattern: /third_party[\/\\]|vendor[\/\\]|node_modules[\/\\]|external[\/\\]/i, reason: 'Third-party code' },
  { pattern: /examples?[\/\\]|tutorials?[\/\\]|samples?[\/\\]|demo[\/\\]/i, reason: 'Example code' },
  { pattern: /docs?[\/\\]|\.md$/i, reason: 'Documentation' },
  { pattern: /build[\/\\]|dist[\/\\]|\.o$|\.a$/i, reason: 'Build artifact' },
];

// ── False-positive title patterns (generic/uncertain) ──────────────────────

const FP_TITLE_PATTERNS: RegExp[] = [
  /missing\s+null\s+check/i,
  /potential\s+overflow/i,
  /possible\s+issue/i,
  /may\s+be\s+null/i,
  /could\s+be\s+unsafe/i,
];

// ── Confidence score for a raw finding ────────────────────────────────────

export type ConfidenceLevel = 'High' | 'Medium' | 'Low';

export function classifyConfidence(vuln: Partial<Vulnerability>): ConfidenceLevel {
  const numeric = typeof vuln.confidence === 'number' ? vuln.confidence : 0.5;
  if (numeric >= 0.7) return 'High';
  if (numeric >= 0.4) return 'Medium';
  return 'Low';
}

// ── Auto-filter function ───────────────────────────────────────────────────

export interface FilterResult {
  accepted: Partial<Vulnerability>[];
  rejected: Array<{ finding: Partial<Vulnerability>; reason: string }>;
}

export function autoFilterFindings(findings: Partial<Vulnerability>[]): FilterResult {
  const accepted: Partial<Vulnerability>[] = [];
  const rejected: Array<{ finding: Partial<Vulnerability>; reason: string }> = [];

  for (const finding of findings) {
    let rejectReason: string | null = null;

    // 1. Check path patterns
    const filePath = finding.file || '';
    if (filePath) {
      for (const { pattern, reason } of FP_PATH_PATTERNS) {
        if (pattern.test(filePath)) {
          rejectReason = reason;
          break;
        }
      }
    }

    // 2. If LOW confidence + generic title → auto-reject
    if (!rejectReason) {
      const confidence = typeof finding.confidence === 'number' ? finding.confidence : 0.5;
      if (confidence < 0.4) {
        const title = finding.title || '';
        for (const pat of FP_TITLE_PATTERNS) {
          if (pat.test(title)) {
            rejectReason = 'Low confidence generic finding';
            break;
          }
        }
      }
    }

    if (rejectReason) {
      rejected.push({ finding, reason: rejectReason });
    } else {
      accepted.push(finding);
    }
  }

  return { accepted, rejected };
}

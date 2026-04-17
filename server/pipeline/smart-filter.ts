import {
  getScanFindings,
  updateScanFinding,
  getAllAIProviders,
  type ScanFinding,
} from '../db.js';
import { routeAI } from '../ai/router.js';

/** Check if any AI provider is enabled. */
async function isAIAvailable(): Promise<boolean> {
  try {
    const providers = getAllAIProviders();
    return providers.some(p => p.enabled);
  } catch { return false; }
}

// ── Types ──────────────────────────────────────────────────────────────────

export interface SmartFilterResult {
  remaining: number;   // findings still pending after all filters
  rejected: number;    // total auto-rejected
  merged: number;      // duplicates merged
}

// ── Additional FP Patterns (extends scanner/filter.ts) ─────────────────────

const EXTRA_FP_PATHS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\.github[\/\\]/i, reason: 'GitHub config' },
  { pattern: /__pycache__[\/\\]/i, reason: 'Python cache' },
  { pattern: /migrations?[\/\\]/i, reason: 'Database migration' },
  { pattern: /generated[\/\\]|\.generated\./i, reason: 'Generated code' },
  { pattern: /mock[\/\\]|__mocks__[\/\\]/i, reason: 'Mock/test data' },
  { pattern: /fixtures?[\/\\]/i, reason: 'Test fixtures' },
  { pattern: /\.min\.js$/i, reason: 'Minified file' },
  { pattern: /changelog|license|readme|contributing/i, reason: 'Project metadata' },
  { pattern: /fuzz[\/\\]|fuzzing[\/\\]|oss-?fuzz/i, reason: 'Fuzzing harness' },
];

const EXTRA_FP_TITLES: RegExp[] = [
  /todo[:\s]/i,
  /fixme[:\s]/i,
  /deprecated/i,
  /\binfo(rmational)?\b.*\bonly\b/i,
  /style\s+(issue|violation|warning)/i,
  /cosmetic/i,
];

// ── Main Entry Point ───────────────────────────────────────────────────────

/**
 * Run 3-tier smart filtering on all pending findings for a pipeline.
 * Mutates scan_findings in DB (rejects become auto_rejected).
 */
export async function runSmartFilter(
  pipelineId: string,
  projectPath: string,
): Promise<SmartFilterResult> {
  let totalRejected = 0;
  let totalMerged = 0;

  // Load all pending findings for this pipeline
  const findings = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
  if (findings.length === 0) return { remaining: 0, rejected: 0, merged: 0 };

  // ── Stage 1: Enhanced Regex Filter ────────────────────────────────────
  const stage1Rejected = filterByPatterns(findings);
  totalRejected += stage1Rejected;

  // ── Stage 2: Cross-Tool Deduplication ─────────────────────────────────
  const remaining1 = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
  const mergeCount = deduplicateFindings(remaining1);
  totalMerged += mergeCount;

  // ── Stage 3: AI Batch FP Filter (skipped if no AI provider enabled) ──
  const remaining2 = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
  if (remaining2.length > 3 && await isAIAvailable()) {
    const aiRejected = await aiBatchFilter(remaining2);
    totalRejected += aiRejected;
  }

  const finalRemaining = getScanFindings({ pipeline_id: pipelineId, status: 'pending' }).length;
  return { remaining: finalRemaining, rejected: totalRejected, merged: totalMerged };
}

// ── Stage 1: Enhanced Regex Filter ─────────────────────────────────────────

function filterByPatterns(findings: ScanFinding[]): number {
  let rejected = 0;

  for (const f of findings) {
    const filePath = f.file || '';
    let rejectReason: string | null = null;

    // Path-based rejection
    for (const { pattern, reason } of EXTRA_FP_PATHS) {
      if (pattern.test(filePath)) {
        rejectReason = reason;
        break;
      }
    }

    // Title-based rejection for low-confidence findings
    if (!rejectReason && (f.confidence === 'Low' || f.confidence === 'Medium')) {
      const title = f.title || '';
      for (const pat of EXTRA_FP_TITLES) {
        if (pat.test(title)) {
          rejectReason = `Low-value finding: ${pat.source}`;
          break;
        }
      }
    }

    // Reject informational/low severity
    if (!rejectReason && f.severity) {
      const sev = f.severity.toLowerCase();
      if (sev === 'info' || sev === 'informational' || sev === 'low') {
        rejectReason = 'Below severity threshold (Low/Info)';
      }
    }

    if (rejectReason && f.id) {
      updateScanFinding(f.id, {
        status: 'auto_rejected',
        rejection_reason: rejectReason,
        ai_filter_reason: `Stage 1 regex: ${rejectReason}`,
      });
      rejected++;
    }
  }

  return rejected;
}

// ── Stage 2: Cross-Tool Deduplication ──────────────────────────────────────

function deduplicateFindings(findings: ScanFinding[]): number {
  // Group by (file, approximate line)
  const groups = new Map<string, ScanFinding[]>();

  for (const f of findings) {
    if (!f.file || !f.line_start) continue;
    // Bucket lines within ±5 of each other
    const lineBucket = Math.floor((f.line_start || 0) / 10) * 10;
    const key = `${f.file}:${lineBucket}`;

    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  let merged = 0;

  for (const [, group] of groups) {
    if (group.length <= 1) continue;

    // Find best finding (highest severity, most detail)
    const severityOrder: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 };
    group.sort((a, b) => {
      const sa = severityOrder[a.severity || 'Medium'] || 2;
      const sb = severityOrder[b.severity || 'Medium'] || 2;
      if (sb !== sa) return sb - sa;
      // Prefer finding with more description
      return (b.description?.length || 0) - (a.description?.length || 0);
    });

    const primary = group[0];
    const otherTools = group.slice(1).map(f => f.tool_name).filter(Boolean);
    const allTools = [primary.tool_name, ...otherTools].filter(Boolean).join(', ');

    // Update primary: boost confidence and record merged tools
    if (primary.id) {
      updateScanFinding(primary.id, {
        confidence: 'High',  // Cross-tool corroboration = high confidence
        merged_tools: allTools,
      });
    }

    // Mark duplicates as auto_rejected
    for (const dup of group.slice(1)) {
      if (dup.id) {
        updateScanFinding(dup.id, {
          status: 'auto_rejected',
          rejection_reason: `Duplicate of finding #${primary.id} (merged)`,
          ai_filter_reason: `Stage 2 dedup: merged into #${primary.id}`,
        });
        merged++;
      }
    }
  }

  return merged;
}

// ── Stage 3: AI Batch FP Filter ────────────────────────────────────────────

async function aiBatchFilter(findings: ScanFinding[]): Promise<number> {
  let totalRejected = 0;

  // Process in batches of 10
  const BATCH_SIZE = 10;
  for (let i = 0; i < findings.length; i += BATCH_SIZE) {
    const batch = findings.slice(i, i + BATCH_SIZE);

    const findingSummaries = batch.map((f, idx) => ({
      index: idx,
      id: f.id,
      title: f.title,
      severity: f.severity,
      file: f.file,
      line: f.line_start,
      tool: f.tool_name,
      snippet: (f.code_snippet || '').slice(0, 200),
      description: (f.description || '').slice(0, 300),
    }));

    const prompt = `You are a security vulnerability triage expert. For each finding below, determine if it is a GENUINE security vulnerability (KEEP) or a false positive / noise (REJECT).

Consider:
- Is the code path likely reachable from external input?
- Does the finding describe a real exploitable condition or just a code quality issue?
- Is this a known false-positive pattern for the tool that found it?
- Would a security engineer investigating this spend time on it or dismiss it?

Return a JSON array with one object per finding:
[{"index": 0, "decision": "KEEP" or "REJECT", "reason": "brief explanation"}]

FINDINGS:
${JSON.stringify(findingSummaries, null, 2)}`;

    try {
      const response = await routeAI({
        messages: [{ role: 'user', content: prompt }],
        task: 'batch-filter' as any,
        temperature: 0.1,
        maxTokens: 2048,
      });

      const content = response?.content || '';
      // Extract JSON array from response
      const jsonMatch = content.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        const decisions: Array<{ index: number; decision: string; reason: string }> = JSON.parse(jsonMatch[0]);

        for (const d of decisions) {
          const finding = batch[d.index];
          if (!finding?.id) continue;

          if (d.decision === 'REJECT') {
            updateScanFinding(finding.id, {
              status: 'auto_rejected',
              rejection_reason: d.reason,
              ai_filter_reason: `Stage 3 AI: ${d.reason}`,
            });
            totalRejected++;
          } else {
            // Record that AI reviewed and approved this finding
            updateScanFinding(finding.id, {
              ai_filter_reason: `Stage 3 AI: KEPT - ${d.reason}`,
            });
          }
        }
      }
    } catch (err: any) {
      console.warn('[SmartFilter] AI batch filter failed, skipping batch:', err.message);
      // On AI failure, keep all findings (conservative approach)
    }

    // Small delay between batches to not overwhelm AI
    if (i + BATCH_SIZE < findings.length) {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  return totalRejected;
}

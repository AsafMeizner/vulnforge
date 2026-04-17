/**
 * Root-cause clustering for findings.
 *
 * Port of Parasoft's "accelerate remediation by grouping violations according
 * to root cause analysis" idea. Goes beyond cross-finding-dedup (same CWE +
 * same title) by asking: which of these findings would a single fix
 * resolve?
 *
 * Two tiers of grouping:
 *   1. Structural (fast, no AI): same function + same CWE class -> cluster.
 *      E.g. 10 null-deref findings all inside parseRequest() -> 1 cluster.
 *   2. Semantic (AI-assisted, opt-in): ask the model to group findings
 *      across function boundaries by shared root cause (e.g. "all these
 *      trust req.headers.host unvalidated - missing a central host allowlist").
 *
 * The structural tier is cheap and runs on every pipeline. The semantic
 * tier is gated behind the `semantic: true` option so you pay the AI
 * budget only when the review UI actually requests it.
 */

import type { ScanFinding } from '../db.js';
import { routeAI } from './router.js';

// ──────────────────────────────────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────────────────────────────────

export interface RootCauseCluster {
  cluster_id: string;
  root_cause: string;
  confidence: number;
  finding_ids: number[];
  representative: ScanFinding;
  members: ScanFinding[];
  suggested_fix_strategy?: string;
  cwe_shared?: string;
  file_shared?: string;
  function_shared?: string;
  method: 'structural' | 'semantic';
}

// ──────────────────────────────────────────────────────────────────────────
//  Structural clustering
// ──────────────────────────────────────────────────────────────────────────

/**
 * Extract enclosing function name from code_snippet or description.
 * Best-effort regex - returns undefined if nothing recognizable.
 */
function extractFunction(f: ScanFinding): string | undefined {
  const text = [f.code_snippet, f.description, f.title].filter(Boolean).join('\n');
  if (!text) return undefined;
  const patterns = [
    /function\s+(\w+)\s*\(/,
    /def\s+(\w+)\s*\(/,
    /func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(/,
    /(?:public|private|protected|static)\s+[\w<>\[\]]+\s+(\w+)\s*\(/,
    /\bin\s+(\w+)\s*\(\)/,
    /\bin\s+function\s+`?(\w+)`?/,
  ];
  for (const re of patterns) {
    const m = text.match(re);
    if (m && m[1]) return m[1];
  }
  return undefined;
}

/**
 * Structural clustering: group findings that share {cwe family, same file,
 * same function}. Fast, deterministic, no AI cost.
 */
export function clusterStructural(findings: ScanFinding[]): RootCauseCluster[] {
  const groups = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const fn = extractFunction(f);
    const key = [
      (f.cwe || '').split(',')[0].trim(),
      (f.file || '').toLowerCase(),
      fn || '<no-fn>',
    ].join('|');
    const arr = groups.get(key);
    if (arr) arr.push(f);
    else groups.set(key, [f]);
  }

  const clusters: RootCauseCluster[] = [];
  let idx = 0;
  for (const [key, members] of groups) {
    if (members.length < 2) continue; // singleton, not a cluster
    const [cwe, file, fn] = key.split('|');
    const representative = members[0];
    clusters.push({
      cluster_id: `struct-${idx++}`,
      root_cause: fn !== '<no-fn>'
        ? `${members.length} findings of ${cwe || 'same class'} inside function ${fn}() in ${file}`
        : `${members.length} findings of ${cwe || 'same class'} in ${file}`,
      confidence: 0.7,
      finding_ids: members.map((m) => m.id!).filter(Boolean),
      representative,
      members,
      suggested_fix_strategy: fn !== '<no-fn>'
        ? `Fix ${fn}() to address the shared vulnerability class, then re-scan.`
        : `Review ${file} for the shared issue class and apply a single remediation.`,
      cwe_shared: cwe || undefined,
      file_shared: file || undefined,
      function_shared: fn !== '<no-fn>' ? fn : undefined,
      method: 'structural',
    });
  }
  return clusters;
}

// ──────────────────────────────────────────────────────────────────────────
//  Semantic clustering (AI-assisted)
// ──────────────────────────────────────────────────────────────────────────

const SEMANTIC_PROMPT_SYSTEM = `You are a senior security engineer grouping vulnerability findings by SHARED ROOT CAUSE.

Definition: two findings share a root cause if the same single code change would resolve both (or substantially both). They do NOT necessarily share CWE, file, or function. A missing central host-allowlist, a broken session-invalidation on role change, or a misconfigured CORS handler can surface as many different-looking findings that ultimately trace to one fix.

Output STRICT JSON:
{
  "clusters": [
    {
      "root_cause": "<one sentence>",
      "fix_strategy": "<one sentence, imperative>",
      "confidence": <0.0-1.0>,
      "member_indices": [<0-based indices into the input>]
    }
  ],
  "unclustered_indices": [<indices that belong to no cluster>]
}
Do not invent indices outside the input range. Every index appears exactly once across clusters + unclustered. Prefer fewer, larger clusters.`;

function buildSemanticPrompt(findings: ScanFinding[]): string {
  const compact = findings.map((f, i) => ({
    i,
    severity: f.severity,
    cwe: f.cwe,
    file: f.file,
    line: f.line_start,
    title: f.title,
    // Keep snippet short - this is about grouping, not deep analysis
    snippet: (f.code_snippet || '').slice(0, 200),
  }));
  return `Input findings:\n${JSON.stringify(compact, null, 2)}\n\nReturn the clusters JSON now:`;
}

interface SemanticLlmResponse {
  clusters: Array<{
    root_cause: string;
    fix_strategy: string;
    confidence: number;
    member_indices: number[];
  }>;
  unclustered_indices: number[];
}

function parseSemanticResponse(text: string): SemanticLlmResponse | null {
  const m = text.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try {
    const parsed = JSON.parse(m[0]);
    if (!Array.isArray(parsed.clusters)) return null;
    return parsed as SemanticLlmResponse;
  } catch {
    return null;
  }
}

/**
 * Semantic clustering via AI. Keeps input bounded (default 40 findings per
 * call) to stay within comfortable context budgets.
 */
export async function clusterSemantic(
  findings: ScanFinding[],
  opts: { maxPerCall?: number } = {}
): Promise<RootCauseCluster[]> {
  const maxPerCall = opts.maxPerCall ?? 40;
  if (findings.length === 0) return [];

  const clusters: RootCauseCluster[] = [];
  let globalIdx = 0;

  for (let offset = 0; offset < findings.length; offset += maxPerCall) {
    const batch = findings.slice(offset, offset + maxPerCall);
    const prompt = buildSemanticPrompt(batch);

    let parsed: SemanticLlmResponse | null = null;
    try {
      const resp = await routeAI({
        messages: [{ role: 'user', content: prompt }],
        systemPrompt: SEMANTIC_PROMPT_SYSTEM,
        temperature: 0.1,
        maxTokens: 2048,
        task: 'batch-filter' as any,
      });
      parsed = parseSemanticResponse(resp.content);
    } catch (err) {
      console.warn('[root-cause/semantic] AI call failed, skipping batch:', (err as Error).message);
      continue;
    }
    if (!parsed) continue;

    for (const c of parsed.clusters) {
      if (!Array.isArray(c.member_indices) || c.member_indices.length < 2) continue;
      const members = c.member_indices
        .map((i) => batch[i])
        .filter(Boolean);
      if (members.length < 2) continue;
      clusters.push({
        cluster_id: `sem-${globalIdx++}`,
        root_cause: c.root_cause || '(unspecified)',
        confidence: Math.max(0, Math.min(1, c.confidence ?? 0.5)),
        finding_ids: members.map((m) => m.id!).filter(Boolean),
        representative: members[0],
        members,
        suggested_fix_strategy: c.fix_strategy,
        cwe_shared: undefined,
        file_shared: undefined,
        function_shared: undefined,
        method: 'semantic',
      });
    }
  }
  return clusters;
}

// ──────────────────────────────────────────────────────────────────────────
//  Top-level entry
// ──────────────────────────────────────────────────────────────────────────

export interface ClusterOptions {
  /** Run AI-based semantic clustering in addition to structural. Costs tokens. */
  semantic?: boolean;
  /** Cap on findings passed to semantic clustering (AI budget guard). */
  maxSemanticInput?: number;
}

export async function clusterByRootCause(
  findings: ScanFinding[],
  opts: ClusterOptions = {}
): Promise<RootCauseCluster[]> {
  const structural = clusterStructural(findings);
  if (!opts.semantic) return structural;

  // Pass only findings NOT already in a structural cluster to semantic
  // layer, so we don't pay AI cost for cases the cheap tier already got.
  const already = new Set<number>();
  for (const c of structural) for (const f of c.members) if (f.id) already.add(f.id);
  const residual = findings.filter((f) => f.id && !already.has(f.id));
  const cap = opts.maxSemanticInput ?? 100;
  const capped = residual.slice(0, cap);

  const semantic = await clusterSemantic(capped);
  return [...structural, ...semantic];
}

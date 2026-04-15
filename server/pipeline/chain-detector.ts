import type { ScanFinding } from '../db.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface VulnChain {
  id: string;
  chain_type: string;
  description: string;
  finding_ids: number[];
  combined_severity: 'Critical' | 'High' | 'Medium';
  exploitation_path: string;
  cwe_chain: string[];
}

// ── Known Chain Patterns ───────────────────────────────────────────────────

interface ChainPattern {
  type: string;
  description: string;
  combined_severity: 'Critical' | 'High' | 'Medium';
  exploitation_path: string;
  // At least one finding must match condition A AND at least one must match condition B
  conditionA: FindingMatcher;
  conditionB: FindingMatcher;
  // Optional: findings must be related (same file, nearby, data flow connected)
  proximity?: 'same_file' | 'same_project' | 'nearby_lines';
}

interface FindingMatcher {
  cwes?: string[];             // Match any of these CWEs
  title_patterns?: RegExp[];   // Match any of these title patterns
  severity_min?: string;       // Minimum severity
}

const CHAIN_PATTERNS: ChainPattern[] = [
  {
    type: 'info_leak_to_rce',
    description: 'Information leak + memory corruption = potential remote code execution',
    combined_severity: 'Critical',
    exploitation_path: 'Info leak defeats ASLR → memory corruption achieves code execution',
    conditionA: {
      cwes: ['CWE-200', 'CWE-209', 'CWE-532'],
      title_patterns: [/info.*(leak|disclos)/i, /uninitialized.*memory/i, /stack.*read/i, /memory.*leak/i],
    },
    conditionB: {
      cwes: ['CWE-122', 'CWE-787', 'CWE-120', 'CWE-190', 'CWE-416', 'CWE-415'],
      title_patterns: [/buffer.*overflow/i, /heap.*overflow/i, /use.*after.*free/i, /integer.*overflow/i, /out.*of.*bounds.*write/i],
    },
    proximity: 'same_project',
  },
  {
    type: 'race_to_uaf',
    description: 'Race condition + use-after-free = memory corruption under timing pressure',
    combined_severity: 'Critical',
    exploitation_path: 'Race condition triggers premature free → UAF achieves arbitrary write',
    conditionA: {
      cwes: ['CWE-362', 'CWE-367', 'CWE-479'],
      title_patterns: [/race.*condition/i, /toctou/i, /signal.*handler/i, /concurrent/i],
    },
    conditionB: {
      cwes: ['CWE-416', 'CWE-415'],
      title_patterns: [/use.*after.*free/i, /double.*free/i, /dangling.*pointer/i],
    },
    proximity: 'same_file',
  },
  {
    type: 'auth_bypass_to_privesc',
    description: 'Authentication bypass + privilege escalation = full system compromise',
    combined_severity: 'Critical',
    exploitation_path: 'Bypass auth → access privileged functions → escalate to root/admin',
    conditionA: {
      cwes: ['CWE-287', 'CWE-306', 'CWE-862'],
      title_patterns: [/auth.*bypass/i, /missing.*auth/i, /broken.*auth/i, /credential/i],
    },
    conditionB: {
      cwes: ['CWE-269', 'CWE-250', 'CWE-732'],
      title_patterns: [/privilege.*escalat/i, /setuid/i, /root/i, /permission/i, /insecure.*default/i],
    },
    proximity: 'same_project',
  },
  {
    type: 'overflow_to_code_exec',
    description: 'Integer overflow + heap overflow = code execution via controlled allocation size',
    combined_severity: 'Critical',
    exploitation_path: 'Integer overflow produces undersized allocation → heap overflow achieves write-what-where',
    conditionA: {
      cwes: ['CWE-190', 'CWE-191'],
      title_patterns: [/integer.*overflow/i, /truncat/i, /narrowing/i],
    },
    conditionB: {
      cwes: ['CWE-122', 'CWE-787', 'CWE-120'],
      title_patterns: [/buffer.*overflow/i, /heap.*overflow/i, /out.*of.*bounds/i],
    },
    proximity: 'same_file',
  },
  {
    type: 'path_traversal_to_rce',
    description: 'Path traversal + file write = arbitrary code execution via uploaded webshell or cron',
    combined_severity: 'Critical',
    exploitation_path: 'Traverse to writable directory → write malicious file → execute via web/cron/startup',
    conditionA: {
      cwes: ['CWE-22', 'CWE-23'],
      title_patterns: [/path.*traversal/i, /directory.*traversal/i, /\.\..*slash/i],
    },
    conditionB: {
      cwes: ['CWE-434', 'CWE-94'],
      title_patterns: [/file.*write/i, /file.*upload/i, /code.*inject/i, /arbitrary.*file/i],
    },
    proximity: 'same_project',
  },
  {
    type: 'ssrf_to_cred_theft',
    description: 'SSRF + cloud metadata access = credential theft in cloud environments',
    combined_severity: 'High',
    exploitation_path: 'SSRF to 169.254.169.254 → fetch IAM credentials → pivot to cloud resources',
    conditionA: {
      cwes: ['CWE-918'],
      title_patterns: [/ssrf/i, /server.*side.*request/i, /url.*redirect/i],
    },
    conditionB: {
      cwes: ['CWE-200', 'CWE-522'],
      title_patterns: [/cloud.*metadata/i, /credential/i, /secret.*expos/i, /api.*key/i],
    },
    proximity: 'same_project',
  },
  {
    type: 'format_string_to_info_leak',
    description: 'Format string + stack read = information disclosure leading to further exploitation',
    combined_severity: 'High',
    exploitation_path: 'Format string reads stack values → discloses addresses and secrets → enables targeted exploits',
    conditionA: {
      cwes: ['CWE-134'],
      title_patterns: [/format.*string/i, /printf.*user/i],
    },
    conditionB: {
      cwes: ['CWE-200', 'CWE-125'],
      title_patterns: [/info.*(leak|disclos)/i, /out.*of.*bounds.*read/i, /stack.*read/i],
    },
    proximity: 'same_file',
  },
  {
    type: 'null_deref_in_signal_handler',
    description: 'NULL dereference + signal handler unsafe = denial of service escalation',
    combined_severity: 'High',
    exploitation_path: 'Trigger NULL deref in signal handler → crash in critical service (e.g., PID 1)',
    conditionA: {
      cwes: ['CWE-476'],
      title_patterns: [/null.*deref/i, /null.*pointer/i],
    },
    conditionB: {
      cwes: ['CWE-479'],
      title_patterns: [/signal.*handler/i, /async.*signal/i, /sighandler/i],
    },
    proximity: 'same_file',
  },
];

// ── Main Detection Function ────────────────────────────────────────────────

/**
 * Detect vulnerability chains in a set of findings.
 * Chains are combinations of findings that, together, create a more severe exploit path.
 */
export function detectChains(findings: ScanFinding[]): VulnChain[] {
  const chains: VulnChain[] = [];
  let chainCounter = 0;

  for (const pattern of CHAIN_PATTERNS) {
    const matchesA = findings.filter(f => matchesFinding(f, pattern.conditionA));
    const matchesB = findings.filter(f => matchesFinding(f, pattern.conditionB));

    if (matchesA.length === 0 || matchesB.length === 0) continue;

    // Check proximity constraints
    for (const a of matchesA) {
      for (const b of matchesB) {
        if (a.id === b.id) continue; // Can't chain with itself

        if (!checkProximity(a, b, pattern.proximity)) continue;

        chainCounter++;
        chains.push({
          id: `chain-${chainCounter}`,
          chain_type: pattern.type,
          description: pattern.description,
          finding_ids: [a.id!, b.id!],
          combined_severity: pattern.combined_severity,
          exploitation_path: pattern.exploitation_path,
          cwe_chain: [a.cwe || '', b.cwe || ''].filter(Boolean),
        });
      }
    }
  }

  // Deduplicate chains (same findings in different order)
  return deduplicateChains(chains);
}

/**
 * Elevate findings that participate in chains.
 * Returns the chain associations for each finding ID.
 */
export function getChainContext(findingId: number, chains: VulnChain[]): VulnChain[] {
  return chains.filter(c => c.finding_ids.includes(findingId));
}

// ── Helpers ────────────────────────────────────────────────────────────────

function matchesFinding(finding: ScanFinding, matcher: FindingMatcher): boolean {
  // CWE match
  if (matcher.cwes && finding.cwe) {
    if (matcher.cwes.includes(finding.cwe)) return true;
  }

  // Title pattern match
  if (matcher.title_patterns) {
    const title = finding.title || '';
    if (matcher.title_patterns.some(p => p.test(title))) return true;
  }

  return false;
}

function checkProximity(a: ScanFinding, b: ScanFinding, proximity?: string): boolean {
  if (!proximity || proximity === 'same_project') return true;

  if (proximity === 'same_file') {
    return Boolean(a.file && b.file && a.file === b.file);
  }

  if (proximity === 'nearby_lines') {
    if (!a.file || !b.file || a.file !== b.file) return false;
    const lineA = a.line_start || 0;
    const lineB = b.line_start || 0;
    return Math.abs(lineA - lineB) < 100;
  }

  return true;
}

function deduplicateChains(chains: VulnChain[]): VulnChain[] {
  const seen = new Set<string>();
  return chains.filter(c => {
    const key = [...c.finding_ids].sort().join(',') + ':' + c.chain_type;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

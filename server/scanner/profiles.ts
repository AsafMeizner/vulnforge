// ── Scan profiles ──────────────────────────────────────────────────────────
//
// A profile groups a curated set of tools under a friendly name. The 'full'
// profile intentionally has an empty tools array — the route handler expands
// it to every enabled tool at request time.

export interface ScanProfile {
  name: string;
  description: string;
  /** Tool names (without .py extension). Empty means "all enabled tools". */
  tools: string[];
}

export const PROFILES: Record<string, ScanProfile> = {
  quick: {
    name: 'Quick Scan',
    description: 'Fast checks: integer overflow + dangerous patterns + signal safety',
    tools: ['integer_overflow_scanner', 'dangerous_patterns', 'signal_safety_checker'],
  },

  memory: {
    name: 'Memory Safety',
    description: 'Full memory safety analysis',
    tools: [
      'cross_arch_truncation',
      'integer_overflow_scanner',
      'double_free_scanner',
      'realloc_dangling_scanner',
      'uaf_detector',
      'stack_clash_vla_scanner',
    ],
  },

  crypto: {
    name: 'Crypto & Auth',
    description: 'Cryptographic and authentication analysis',
    tools: ['timing_oracle_scanner', 'crypto_misuse_scanner', 'auth_bypass_finder'],
  },

  full: {
    name: 'Full Scan',
    description: 'All enabled tools (takes longer)',
    tools: [], // empty means all enabled tools — resolved at route level
  },

  protocol: {
    name: 'Protocol Analysis',
    description: 'HTTP/TLS/DNS protocol parsing bugs',
    tools: [
      'protocol_smuggling_scanner',
      'state_machine_scanner',
      'deserialization_trust_scanner',
    ],
  },

  concurrency: {
    name: 'Concurrency & Signals',
    description: 'Race conditions, signal handler safety, lock ordering',
    tools: ['signal_safety_checker', 'race_condition_scanner', 'callback_safety_scanner'],
  },

  supply_chain: {
    name: 'Supply Chain',
    description: 'XZ-pattern maintainer and build-system risk assessment',
    tools: ['supply_chain_scanner', 'dependency_tree_auditor'],
  },

  secrets: {
    name: 'Secrets & Injection',
    description: 'Hardcoded credentials, command injection, taint flows',
    tools: [
      'hardcoded_secrets_scanner',
      'command_injection_scanner',
      'taint_flow_analyzer',
      'input_validation_bypass_scanner',
    ],
  },
};

/** Return the profile for a given key, or null if not found. */
export function getProfile(key: string): ScanProfile | null {
  return PROFILES[key.toLowerCase()] ?? null;
}

/** Return all profile keys and their metadata (without the full tool list). */
export function listProfiles(): Array<{ key: string; name: string; description: string; toolCount: number }> {
  return Object.entries(PROFILES).map(([key, p]) => ({
    key,
    name: p.name,
    description: p.description,
    toolCount: p.tools.length,
  }));
}

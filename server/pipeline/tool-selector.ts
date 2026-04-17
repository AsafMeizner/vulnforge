import type { ProjectMeta } from './git.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ToolSelection {
  tools: string[];                // Python tool names from security-solver/tools/
  plugins: PluginRunConfig[];     // Plugin integrations to run
  reason: string;                 // Human-readable explanation of selections
}

export interface PluginRunConfig {
  pluginName: string;             // e.g. 'semgrep', 'trivy', 'bandit'
  options?: Record<string, any>;
}

// ── Tool Profiles by Language/Category ─────────────────────────────────────

/** Core memory safety tools for C/C++ */
const C_MEMORY_TOOLS = [
  'integer_overflow_scanner',
  'cross_arch_truncation',
  'uaf_detector',
  'double_free_scanner',
  'null_deref_hunter',
  'realloc_dangling_scanner',
  'uninitialized_memory_leak_scanner',
  'boundary_check_scanner',
  'stack_clash_vla_scanner',
];

/** C/C++ crypto and protocol tools */
const C_SECURITY_TOOLS = [
  'crypto_misuse_scanner',
  'timing_oracle_scanner',
  'signal_safety_checker',
  'preauth_tracer',
  'protocol_smuggling_scanner',
  'state_machine_scanner',
  'signed_unsigned_checker',
];

/** C/C++ code quality and logic tools */
const C_LOGIC_TOOLS = [
  'error_path_divergence',
  'cleanup_order_scanner',
  'callback_safety_scanner',
  'macro_safety_scanner',
  'variadic_misuse_scanner',
  'ub_compiler_trap_scanner',
];

/** Tools applicable to any language */
const UNIVERSAL_TOOLS = [
  'dangerous_patterns',
  'hardcoded_secrets_scanner',
  'taint_flow_analyzer',
  'auth_bypass_finder',
];

/** API and input validation tools */
const API_TOOLS = [
  'command_injection_scanner',
  'input_validation_bypass_scanner',
  'deserialization_trust_scanner',
  'api_misuse_scanner',
];

/** Concurrency tools */
const CONCURRENCY_TOOLS = [
  'race_condition_scanner',
  'filesystem_race_scanner',
  'privilege_transition_scanner',
];

/** Supply chain and dependency tools */
const SUPPLY_CHAIN_TOOLS = [
  'supply_chain_scanner',
  'dependency_tree_auditor',
];

// ── Selection Logic ────────────────────────────────────────────────────────

/**
 * Select the right tools and plugins based on the project's languages and characteristics.
 * The goal: pick tools that will find real bugs, not generate noise.
 */
export function selectToolsForProject(meta: ProjectMeta): ToolSelection {
  const tools = new Set<string>();
  const plugins: PluginRunConfig[] = [];
  const reasons: string[] = [];

  const langs = new Set(meta.languages.map(l => l.toLowerCase()));
  const hasC = langs.has('c') || langs.has('c++');
  const hasPython = langs.has('python');
  const hasGo = langs.has('go');
  const hasRust = langs.has('rust');
  const hasJS = langs.has('javascript') || langs.has('typescript');
  const hasJava = langs.has('java') || langs.has('kotlin') || langs.has('scala');

  // Always run universal tools
  for (const t of UNIVERSAL_TOOLS) tools.add(t);
  reasons.push('Universal security tools (secrets, auth, taint)');

  // C/C++ - highest tool coverage, these have the best hit rate
  if (hasC) {
    for (const t of C_MEMORY_TOOLS) tools.add(t);
    for (const t of C_SECURITY_TOOLS) tools.add(t);
    for (const t of C_LOGIC_TOOLS) tools.add(t);
    for (const t of CONCURRENCY_TOOLS) tools.add(t);
    // Parser complexity scorer helps rank which functions to focus on
    tools.add('parser_complexity_scorer');
    tools.add('type_confusion_scanner');
    tools.add('struct_padding_leak_scanner');
    reasons.push('Full C/C++ memory safety + crypto + protocol suite');
  }

  // Python
  if (hasPython) {
    plugins.push({ pluginName: 'bandit' });
    plugins.push({ pluginName: 'safety' });
    reasons.push('Bandit (Python security) + Safety (dependency audit)');
  }

  // Go
  if (hasGo) {
    for (const t of API_TOOLS) tools.add(t);
    tools.add('race_condition_scanner');
    reasons.push('Go API + concurrency tools');
  }

  // Rust - mostly safe by default, focus on unsafe blocks and logic
  if (hasRust) {
    tools.add('logic_bug_scanner');
    tools.add('error_path_divergence');
    reasons.push('Rust logic + error path analysis');
  }

  // JavaScript/TypeScript
  if (hasJS) {
    tools.add('unicode_encoding_auditor');
    for (const t of API_TOOLS) tools.add(t);
    reasons.push('JS/TS injection + encoding tools');
  }

  // Java/Kotlin
  if (hasJava) {
    for (const t of API_TOOLS) tools.add(t);
    tools.add('type_confusion_scanner');
    reasons.push('Java deserialization + injection tools');
  }

  // Always run Semgrep - it has auto-config and covers many languages
  plugins.push({ pluginName: 'semgrep' });
  reasons.push('Semgrep (universal static analysis)');

  // Always run Trivy for dependency scanning if we detected dep files
  if (meta.dependencyFiles.length > 0) {
    plugins.push({ pluginName: 'trivy' });
    reasons.push(`Trivy dependency scan (${meta.dependencyFiles.length} dep files found)`);
  }

  // Supply chain analysis
  for (const t of SUPPLY_CHAIN_TOOLS) tools.add(t);

  // Cap at reasonable number: if too many tools, prioritize by category
  // For large projects, skip the slower tools
  const toolList = [...tools];
  if (meta.estimatedSize === 'large' && toolList.length > 25) {
    // Keep only the top-priority tools for large projects
    const priority = new Set([
      ...UNIVERSAL_TOOLS,
      ...(hasC ? [...C_MEMORY_TOOLS, ...C_SECURITY_TOOLS] : []),
      'parser_complexity_scorer',
    ]);
    const filtered = toolList.filter(t => priority.has(t));
    return {
      tools: filtered,
      plugins,
      reason: reasons.join(' | ') + ' (large project: reduced to priority tools)',
    };
  }

  return {
    tools: toolList,
    plugins,
    reason: reasons.join(' | '),
  };
}

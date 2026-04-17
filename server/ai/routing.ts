export type TaskType = 'triage' | 'suggest-fix' | 'deep-analyze' | 'report' | 'chat' | 'simple' | 'verify' | 'batch-filter';

export interface RoutingRule {
  task: TaskType;
  provider: string; // provider name matching ai_providers.name in DB
  model: string;    // model id
  priority: number; // lower = higher priority
}

// ── All task types (used by presets and UI) ────────────────────────────────

export const ALL_TASK_TYPES: TaskType[] = [
  'triage', 'verify', 'suggest-fix', 'deep-analyze',
  'report', 'chat', 'batch-filter', 'simple',
];

export const TASK_DESCRIPTIONS: Record<TaskType, string> = {
  'triage': 'Classify severity and exploitability of findings',
  'verify': 'Deep code review to confirm or reject findings',
  'suggest-fix': 'Generate code patches for vulnerabilities',
  'deep-analyze': 'Thorough security analysis of a finding',
  'report': 'Write disclosure reports and advisories',
  'chat': 'Free-form conversation about findings',
  'batch-filter': 'Bulk false-positive assessment',
  'simple': 'Quick categorization and labeling',
};

export const TASK_COMPLEXITY: Record<TaskType, 'high' | 'medium' | 'low'> = {
  'verify': 'high',
  'deep-analyze': 'high',
  'suggest-fix': 'medium',
  'report': 'medium',
  'triage': 'medium',
  'chat': 'medium',
  'batch-filter': 'low',
  'simple': 'low',
};

// ── Default Rules ──────────────────────────────────────────────────────────

export const DEFAULT_RULES: RoutingRule[] = [
  { task: 'simple',       provider: 'ollama',     model: 'qwen3:8b',               priority: 1 },
  { task: 'simple',       provider: 'claude_cli', model: 'claude-code',             priority: 2 },
  { task: 'triage',       provider: 'claude_cli', model: 'claude-code',             priority: 1 },
  { task: 'triage',       provider: 'ollama',     model: 'deepseek-r1:8b',         priority: 2 },
  { task: 'suggest-fix',  provider: 'claude_cli', model: 'claude-code',             priority: 1 },
  { task: 'deep-analyze', provider: 'claude_cli', model: 'claude-code',             priority: 1 },
  { task: 'report',       provider: 'claude_cli', model: 'claude-code',             priority: 1 },
  { task: 'chat',         provider: 'claude_cli', model: 'claude-code',             priority: 1 },
  { task: 'chat',         provider: 'ollama',     model: 'qwen3:8b',               priority: 2 },
  { task: 'verify',       provider: 'claude_cli', model: 'claude-code',             priority: 1 },
  { task: 'verify',       provider: 'ollama',     model: 'deepseek-r1:8b',         priority: 2 },
  { task: 'batch-filter', provider: 'claude_cli', model: 'claude-code',             priority: 1 },
  { task: 'batch-filter', provider: 'ollama',     model: 'qwen3:8b',               priority: 2 },
];

// ── Routing Presets ────────────────────────────────────────────────────────

export interface RoutingPreset {
  name: string;
  label: string;
  description: string;
  rules: RoutingRule[];
}

export const ROUTING_PRESETS: Record<string, RoutingPreset> = {
  'smart-split': {
    name: 'smart-split',
    label: 'Smart Split',
    description: 'Strong models for complex tasks (verify, deep-analyze), fast models for simple ones. Best balance of quality and cost.',
    rules: [
      { task: 'verify',       provider: 'claude', model: 'claude-opus-4-6-20250619',   priority: 1 },
      { task: 'deep-analyze', provider: 'claude', model: 'claude-opus-4-6-20250619',   priority: 1 },
      { task: 'suggest-fix',  provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'report',       provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'triage',       provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'chat',         provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'batch-filter', provider: 'ollama', model: 'qwen3:8b',                   priority: 1 },
      { task: 'simple',       provider: 'ollama', model: 'qwen3:8b',                   priority: 1 },
    ],
  },
  'all-claude': {
    name: 'all-claude',
    label: 'All Claude',
    description: 'Use Claude API for everything. Highest quality but highest cost.',
    rules: [
      { task: 'verify',       provider: 'claude', model: 'claude-opus-4-6-20250619',   priority: 1 },
      { task: 'deep-analyze', provider: 'claude', model: 'claude-opus-4-6-20250619',   priority: 1 },
      { task: 'suggest-fix',  provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'report',       provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'triage',       provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'chat',         provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'batch-filter', provider: 'claude', model: 'claude-haiku-4-5-20251001',  priority: 1 },
      { task: 'simple',       provider: 'claude', model: 'claude-haiku-4-5-20251001',  priority: 1 },
    ],
  },
  'all-local': {
    name: 'all-local',
    label: 'All Local (Free)',
    description: 'Use only Ollama local models. Completely free but lower quality. Requires Ollama running.',
    rules: [
      { task: 'verify',       provider: 'ollama', model: 'deepseek-r1:8b',  priority: 1 },
      { task: 'deep-analyze', provider: 'ollama', model: 'deepseek-r1:8b',  priority: 1 },
      { task: 'suggest-fix',  provider: 'ollama', model: 'deepseek-r1:8b',  priority: 1 },
      { task: 'report',       provider: 'ollama', model: 'deepseek-r1:8b',  priority: 1 },
      { task: 'triage',       provider: 'ollama', model: 'qwen3:8b',        priority: 1 },
      { task: 'chat',         provider: 'ollama', model: 'qwen3:8b',        priority: 1 },
      { task: 'batch-filter', provider: 'ollama', model: 'qwen3:8b',        priority: 1 },
      { task: 'simple',       provider: 'ollama', model: 'qwen3:8b',        priority: 1 },
    ],
  },
  'budget': {
    name: 'budget',
    label: 'Budget Mode',
    description: 'Local models for most tasks, Claude Sonnet only for the hardest (verify, deep-analyze). Minimal API cost.',
    rules: [
      { task: 'verify',       provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'deep-analyze', provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 1 },
      { task: 'suggest-fix',  provider: 'ollama', model: 'deepseek-r1:8b',             priority: 1 },
      { task: 'report',       provider: 'ollama', model: 'deepseek-r1:8b',             priority: 1 },
      { task: 'triage',       provider: 'ollama', model: 'qwen3:8b',                   priority: 1 },
      { task: 'triage',       provider: 'claude', model: 'claude-sonnet-4-6-20250514', priority: 2 },
      { task: 'chat',         provider: 'ollama', model: 'qwen3:8b',                   priority: 1 },
      { task: 'batch-filter', provider: 'ollama', model: 'qwen3:8b',                   priority: 1 },
      { task: 'simple',       provider: 'ollama', model: 'qwen3:8b',                   priority: 1 },
    ],
  },
  'all-openai': {
    name: 'all-openai',
    label: 'All OpenAI',
    description: 'Use OpenAI API for everything. GPT-4o for complex, GPT-4o-mini for simple.',
    rules: [
      { task: 'verify',       provider: 'openai', model: 'gpt-4o',      priority: 1 },
      { task: 'deep-analyze', provider: 'openai', model: 'gpt-4o',      priority: 1 },
      { task: 'suggest-fix',  provider: 'openai', model: 'gpt-4o',      priority: 1 },
      { task: 'report',       provider: 'openai', model: 'gpt-4o',      priority: 1 },
      { task: 'triage',       provider: 'openai', model: 'gpt-4o-mini', priority: 1 },
      { task: 'chat',         provider: 'openai', model: 'gpt-4o',      priority: 1 },
      { task: 'batch-filter', provider: 'openai', model: 'gpt-4o-mini', priority: 1 },
      { task: 'simple',       provider: 'openai', model: 'gpt-4o-mini', priority: 1 },
    ],
  },
  'all-gemini': {
    name: 'all-gemini',
    label: 'All Gemini',
    description: 'Use Google Gemini API for everything. Pro for complex, Flash for simple. Huge context window.',
    rules: [
      { task: 'verify',       provider: 'gemini', model: 'gemini-2.5-pro',   priority: 1 },
      { task: 'deep-analyze', provider: 'gemini', model: 'gemini-2.5-pro',   priority: 1 },
      { task: 'suggest-fix',  provider: 'gemini', model: 'gemini-2.5-pro',   priority: 1 },
      { task: 'report',       provider: 'gemini', model: 'gemini-2.5-flash', priority: 1 },
      { task: 'triage',       provider: 'gemini', model: 'gemini-2.5-flash', priority: 1 },
      { task: 'chat',         provider: 'gemini', model: 'gemini-2.5-pro',   priority: 1 },
      { task: 'batch-filter', provider: 'gemini', model: 'gemini-2.5-flash', priority: 1 },
      { task: 'simple',       provider: 'gemini', model: 'gemini-2.5-flash', priority: 1 },
    ],
  },
  'claude-cli': {
    name: 'claude-cli',
    label: 'Claude CLI Only',
    description: 'Use Claude Code CLI for everything. No API key needed - uses your Claude Code subscription.',
    rules: ALL_TASK_TYPES.map(task => ({
      task, provider: 'claude_cli', model: 'claude-code', priority: 1,
    })),
  },
};

// ── In-Memory Rules Cache ──────────────────────────────────────────────────

let _rules: RoutingRule[] = [...DEFAULT_RULES];

export function getRoutingRules(): RoutingRule[] {
  return _rules;
}

export function setRoutingRules(rules: RoutingRule[]): void {
  _rules = rules;
}

export function resetRoutingRules(): void {
  _rules = [...DEFAULT_RULES];
}

/**
 * Initialize routing rules from database.
 * Called once at server startup after DB init.
 */
export async function initRoutingFromDb(): Promise<void> {
  try {
    const db = await import('../db.js');
    const count = db.countRoutingRules();
    if (count > 0) {
      const dbRules = db.getDbRoutingRules();
      _rules = dbRules
        .filter((r: any) => r.enabled)
        .map((r: any) => ({
          task: r.task as TaskType,
          provider: r.provider,
          model: r.model,
          priority: r.priority,
        }));
      console.log(`[Routing] Loaded ${_rules.length} rules from database`);
    } else {
      // Seed DB with defaults on first run
      db.setDbRoutingRules(DEFAULT_RULES.map(r => ({
        task: r.task, provider: r.provider, model: r.model, priority: r.priority, enabled: 1,
      })));
      console.log('[Routing] Seeded database with default rules');
    }
  } catch (err: any) {
    console.warn('[Routing] Failed to load from DB, using defaults:', err.message);
  }
}

/**
 * Save current rules to database and update in-memory cache.
 */
export async function persistRules(rules: RoutingRule[]): Promise<void> {
  _rules = rules;
  try {
    const db = await import('../db.js');
    db.setDbRoutingRules(rules.map(r => ({
      task: r.task, provider: r.provider, model: r.model, priority: r.priority, enabled: 1,
    })));
  } catch (err: any) {
    console.warn('[Routing] Failed to persist rules:', err.message);
  }
}

/**
 * Return the highest-priority rule for a given task whose provider is in the
 * set of enabled provider names.  Falls back to any rule for the task if none
 * of the preferred providers are enabled.
 */
export function resolveRule(
  task: TaskType,
  enabledProviders: string[]
): RoutingRule | null {
  const candidates = _rules
    .filter(r => r.task === task)
    .sort((a, b) => a.priority - b.priority);

  // First try to match an enabled provider
  for (const rule of candidates) {
    if (enabledProviders.includes(rule.provider.toLowerCase())) {
      return rule;
    }
  }

  // Fall back to first rule regardless of enabled status (caller will error)
  return candidates[0] ?? null;
}

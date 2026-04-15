export interface ModelInfo {
  id: string;
  name: string;
  tier: 'premium' | 'standard' | 'fast' | 'reasoning' | 'local' | 'cli';
  context: number;
  costPer1MInput?: number;   // USD per 1M input tokens (undefined = free/unknown)
  costPer1MOutput?: number;  // USD per 1M output tokens
}

export interface ProviderModels {
  models: ModelInfo[];
}

export const MODEL_REGISTRY: Record<string, ProviderModels> = {
  claude: {
    models: [
      { id: 'claude-opus-4-6-20250619',   name: 'Claude Opus 4.6',     tier: 'premium',   context: 200000, costPer1MInput: 15, costPer1MOutput: 75 },
      { id: 'claude-sonnet-4-6-20250514', name: 'Claude Sonnet 4.6',   tier: 'standard',  context: 200000, costPer1MInput: 3, costPer1MOutput: 15 },
      { id: 'claude-haiku-4-5-20251001',  name: 'Claude Haiku 4.5',    tier: 'fast',      context: 200000, costPer1MInput: 0.8, costPer1MOutput: 4 },
      // Legacy IDs (still work)
      { id: 'claude-opus-4-20250514',     name: 'Claude Opus 4',       tier: 'premium',   context: 200000, costPer1MInput: 15, costPer1MOutput: 75 },
      { id: 'claude-sonnet-4-20250514',   name: 'Claude Sonnet 4',     tier: 'standard',  context: 200000, costPer1MInput: 3, costPer1MOutput: 15 },
    ],
  },
  openai: {
    models: [
      { id: 'gpt-4o',      name: 'GPT-4o',      tier: 'premium',   context: 128000, costPer1MInput: 2.5, costPer1MOutput: 10 },
      { id: 'gpt-4o-mini', name: 'GPT-4o Mini', tier: 'fast',      context: 128000, costPer1MInput: 0.15, costPer1MOutput: 0.6 },
      { id: 'o3',          name: 'o3',           tier: 'reasoning', context: 200000, costPer1MInput: 10, costPer1MOutput: 40 },
      { id: 'o4-mini',     name: 'o4-mini',      tier: 'reasoning', context: 200000, costPer1MInput: 1.1, costPer1MOutput: 4.4 },
    ],
  },
  gemini: {
    models: [
      { id: 'gemini-2.5-pro',   name: 'Gemini 2.5 Pro',   tier: 'premium', context: 1000000, costPer1MInput: 1.25, costPer1MOutput: 10 },
      { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', tier: 'fast',    context: 1000000, costPer1MInput: 0.15, costPer1MOutput: 0.6 },
    ],
  },
  ollama: {
    models: [
      { id: 'deepseek-r1:8b',  name: 'DeepSeek R1 8B',  tier: 'local', context: 32000 },
      { id: 'qwen3:8b',        name: 'Qwen 3 8B',        tier: 'local', context: 32000 },
      { id: 'llama3.2',        name: 'Llama 3.2',        tier: 'local', context: 8000 },
      { id: 'codellama',       name: 'Code Llama',       tier: 'local', context: 16000 },
      { id: 'mistral',         name: 'Mistral 7B',       tier: 'local', context: 32000 },
    ],
  },
  claude_cli: {
    models: [
      { id: 'claude-code', name: 'Claude Code CLI', tier: 'cli', context: 200000 },
    ],
  },
};

/** Return the default (first) model id for a provider name, or undefined. */
export function getDefaultModel(providerName: string): string | undefined {
  const entry = MODEL_REGISTRY[providerName.toLowerCase()];
  return entry?.models[0]?.id;
}

/**
 * Merge live Ollama models into the registry.
 * Called when user refreshes from the Ollama instance.
 * Adds any models not already in the default list.
 */
export function mergeOllamaModels(liveModels: string[]): ModelInfo[] {
  const existing = new Set(MODEL_REGISTRY.ollama.models.map(m => m.id));
  const merged = [...MODEL_REGISTRY.ollama.models];

  for (const modelId of liveModels) {
    if (!existing.has(modelId)) {
      merged.push({
        id: modelId,
        name: modelId,
        tier: 'local',
        context: 32000,
      });
    }
  }

  return merged;
}

/** Look up cost for a specific provider+model combo. Returns null if free/unknown. */
export function getModelCost(providerName: string, modelId: string): { input: number; output: number } | null {
  const entry = MODEL_REGISTRY[providerName.toLowerCase()];
  if (!entry) return null;
  const model = entry.models.find(m => m.id === modelId);
  if (!model || model.costPer1MInput === undefined) return null;
  return { input: model.costPer1MInput, output: model.costPer1MOutput || 0 };
}

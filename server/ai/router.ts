import { getAllAIProviders, getEnabledAIProvider } from '../db.js';
import { ollamaChat, type OllamaMessage } from './providers/ollama.js';
import { claudeChat, type ClaudeMessage } from './providers/claude.js';
import { chatGemini } from './providers/gemini.js';
import { chatClaudeCLI } from './providers/claude-cli.js';
import { resolveRule, getRoutingRules, type TaskType, type RoutingRule } from './routing.js';

export interface AIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface AIRequest {
  messages: AIMessage[];
  systemPrompt?: string;
  temperature?: number;
  maxTokens?: number;
  task?: TaskType;
}

export interface AIResponse {
  content: string;
  model: string;
  provider: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
  };
}

// ── Internal: dispatch to a named provider ─────────────────────────────────

async function dispatchToProvider(
  providerName: string,
  model: string | undefined,
  request: AIRequest
): Promise<AIResponse> {
  const { messages, systemPrompt, temperature, maxTokens } = request;

  // Look up the provider record for api_key / base_url
  const allProviders = getAllAIProviders();
  const providerRecord = allProviders.find(
    p => p.name.toLowerCase() === providerName.toLowerCase()
  );

  switch (providerName.toLowerCase()) {
    case 'ollama': {
      const ollamaMessages: OllamaMessage[] = [];
      if (systemPrompt) ollamaMessages.push({ role: 'system', content: systemPrompt });
      for (const msg of messages) {
        ollamaMessages.push({ role: msg.role as OllamaMessage['role'], content: msg.content });
      }
      const resp = await ollamaChat(ollamaMessages, {
        baseUrl: providerRecord?.base_url || 'http://localhost:11434',
        model: model || providerRecord?.model || 'llama3.2',
        temperature: temperature ?? 0.3,
      });
      return { ...resp, provider: 'ollama' };
    }

    case 'claude': {
      const apiKey = providerRecord?.api_key;
      if (!apiKey) throw new Error('Claude API key not configured');

      const claudeMessages: ClaudeMessage[] = [];
      let systemContent = systemPrompt || '';
      for (const msg of messages) {
        if (msg.role === 'system') {
          systemContent = systemContent ? `${systemContent}\n${msg.content}` : msg.content;
        } else {
          claudeMessages.push({ role: msg.role as 'user' | 'assistant', content: msg.content });
        }
      }
      const resp = await claudeChat(claudeMessages, {
        apiKey,
        model: model || providerRecord?.model || 'claude-sonnet-4-20250514',
        maxTokens: maxTokens || 4096,
        temperature,
        systemPrompt: systemContent || undefined,
      });
      return { ...resp, provider: 'claude' };
    }

    case 'openai': {
      const apiKey = providerRecord?.api_key;
      if (!apiKey) throw new Error('OpenAI API key not configured');

      const { default: OpenAI } = await import('openai');
      const client = new OpenAI({ apiKey });
      const openaiMessages: any[] = [];
      if (systemPrompt) openaiMessages.push({ role: 'system', content: systemPrompt });
      for (const msg of messages) {
        openaiMessages.push({ role: msg.role, content: msg.content });
      }
      const completion = await client.chat.completions.create({
        model: model || providerRecord?.model || 'gpt-4o',
        messages: openaiMessages,
        max_tokens: maxTokens || 4096,
        temperature: temperature ?? 0.3,
      });
      const content = completion.choices[0]?.message?.content || '';
      return {
        content,
        model: completion.model,
        provider: 'openai',
        usage: {
          prompt_tokens: completion.usage?.prompt_tokens,
          completion_tokens: completion.usage?.completion_tokens,
        },
      };
    }

    case 'gemini': {
      const apiKey = providerRecord?.api_key;
      if (!apiKey) throw new Error('Gemini API key not configured');

      const allMessages: AIMessage[] = [];
      if (systemPrompt) allMessages.push({ role: 'system', content: systemPrompt });
      allMessages.push(...messages);

      const resp = await chatGemini(allMessages, {
        apiKey,
        model: model || providerRecord?.model || 'gemini-2.5-flash',
        temperature: temperature ?? 0.3,
        maxTokens: maxTokens || 4096,
      });
      return { ...resp, provider: 'gemini' };
    }

    case 'claude_cli': {
      // Flatten all messages into a single prompt string for the CLI
      const parts: string[] = [];
      if (systemPrompt) parts.push(`[System]: ${systemPrompt}`);
      for (const msg of messages) {
        const label = msg.role === 'user' ? 'User' : msg.role === 'assistant' ? 'Assistant' : 'System';
        parts.push(`[${label}]: ${msg.content}`);
      }
      const resp = await chatClaudeCLI(parts.join('\n\n'));
      return { ...resp, provider: 'claude_cli' };
    }

    default:
      throw new Error(`Unknown AI provider: ${providerName}`);
  }
}

// ── Public: route a request ────────────────────────────────────────────────

/** Patterns that indicate token/rate limit exhaustion (provider-specific). */
const EXHAUSTION_PATTERNS = [
  /rate.?limit/i, /429/i, /quota/i, /insufficient.?quota/i,
  /overloaded/i, /capacity/i, /too.?many.?requests/i,
  /billing/i, /credit/i, /token.?limit/i, /exceeded/i,
  /resource.?exhausted/i, /server.?error/i, /503/i, /529/i,
];

function isExhausted(err: any): boolean {
  const msg = String(err?.message || err || '');
  return EXHAUSTION_PATTERNS.some(p => p.test(msg));
}

export async function routeAI(request: AIRequest): Promise<AIResponse> {
  const task = request.task;
  const allProviders = getAllAIProviders();
  const enabledNames = allProviders
    .filter(p => p.enabled)
    .map(p => p.name.toLowerCase());

  if (enabledNames.length === 0) {
    throw new Error('No AI provider enabled. Configure an AI provider in settings.');
  }

  if (task) {
    // Task-aware routing with auto-fallback on exhaustion
    const candidates = _getRulesForTask(task, enabledNames);

    for (const rule of candidates) {
      try {
        return await dispatchToProvider(rule.provider, rule.model, request);
      } catch (err: any) {
        if (isExhausted(err) && candidates.length > 1) {
          console.warn(`[AI] Provider ${rule.provider} exhausted for task "${task}", trying next fallback...`);
          continue; // Try next priority
        }
        throw err; // Non-exhaustion error, propagate
      }
    }
    // All candidates exhausted - fall through to legacy
  }

  // Legacy / fallback: try each enabled provider in order
  for (const provName of enabledNames) {
    try {
      const provRecord = allProviders.find(p => p.name.toLowerCase() === provName);
      return await dispatchToProvider(provName, provRecord?.model || undefined, request);
    } catch (err: any) {
      if (isExhausted(err) && enabledNames.indexOf(provName) < enabledNames.length - 1) {
        console.warn(`[AI] Provider ${provName} exhausted, trying next...`);
        continue;
      }
      throw err;
    }
  }

  throw new Error('All AI providers exhausted or failed.');
}

/** Get all matching rules for a task, sorted by priority, filtered to enabled providers. */
function _getRulesForTask(task: TaskType, enabledProviders: string[]): RoutingRule[] {
  return getRoutingRules()
    .filter(r => r.task === task && enabledProviders.includes(r.provider.toLowerCase()))
    .sort((a, b) => a.priority - b.priority);
}

// ── Triage helper ──────────────────────────────────────────────────────────

export async function triageFinding(vuln: Record<string, any>): Promise<string> {
  const systemPrompt = `You are an expert security researcher and vulnerability analyst.
Your task is to triage security findings and provide concise, actionable analysis.
Focus on exploitability, real-world impact, and concrete remediation steps.
Use the CVSS framework to assess severity. Be precise and technical.`;

  const userMessage = `Triage this security finding:

Title: ${vuln.title}
Severity: ${vuln.severity || 'Unknown'}
CVSS: ${vuln.cvss || 'N/A'}
CWE: ${vuln.cwe || 'N/A'}
File: ${vuln.file || 'N/A'}
Method: ${vuln.method || 'N/A'}

Description:
${vuln.description || 'No description provided'}

Code Snippet:
${vuln.code_snippet ? '```\n' + vuln.code_snippet + '\n```' : 'None provided'}

Please provide:
1. Exploitability assessment (can this be reliably triggered?)
2. Real-world impact (what can an attacker actually achieve?)
3. Confidence level (High/Medium/Low) with reasoning
4. Suggested CVSS score and vector if not provided
5. Recommended immediate fix
6. Tier classification: A (private disclosure), B (open PR), or C (internal note)`;

  const response = await routeAI({
    messages: [{ role: 'user', content: userMessage }],
    systemPrompt,
    temperature: 0.2,
    maxTokens: 2048,
    task: 'triage',
  });

  return response.content;
}

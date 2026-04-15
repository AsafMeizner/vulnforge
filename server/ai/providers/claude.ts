import { createRequire } from 'module';

const require = createRequire(import.meta.url);

export interface ClaudeMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface ClaudeOptions {
  apiKey: string;
  model?: string;
  maxTokens?: number;
  temperature?: number;
  systemPrompt?: string;
}

export interface ChatResponse {
  content: string;
  model: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
  };
}

export async function claudeChat(
  messages: ClaudeMessage[],
  options: ClaudeOptions
): Promise<ChatResponse> {
  const Anthropic = require('@anthropic-ai/sdk');
  const client = new Anthropic.default({ apiKey: options.apiKey });

  const model = options.model || 'claude-sonnet-4-20250514';
  const maxTokens = options.maxTokens || 4096;

  const params: any = {
    model,
    max_tokens: maxTokens,
    messages,
  };

  if (options.systemPrompt) {
    params.system = options.systemPrompt;
  }

  if (options.temperature !== undefined) {
    params.temperature = options.temperature;
  }

  const response = await client.messages.create(params);

  const textBlock = response.content.find((b: any) => b.type === 'text');
  const content = textBlock?.text || '';

  return {
    content,
    model: response.model,
    usage: {
      prompt_tokens: response.usage?.input_tokens,
      completion_tokens: response.usage?.output_tokens,
    },
  };
}

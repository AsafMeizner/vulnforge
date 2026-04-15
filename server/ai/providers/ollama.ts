export interface OllamaMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface OllamaOptions {
  baseUrl?: string;
  model?: string;
  temperature?: number;
}

export interface ChatResponse {
  content: string;
  model: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
  };
}

export async function ollamaChat(
  messages: OllamaMessage[],
  options: OllamaOptions = {}
): Promise<ChatResponse> {
  const baseUrl = options.baseUrl || 'http://localhost:11434';
  const model = options.model || 'llama3.2';

  const response = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages,
      stream: false,
      options: {
        temperature: options.temperature ?? 0.3,
      },
    }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Ollama API error ${response.status}: ${text}`);
  }

  const data = await response.json() as any;

  return {
    content: data.message?.content || '',
    model: data.model || model,
    usage: {
      prompt_tokens: data.prompt_eval_count,
      completion_tokens: data.eval_count,
    },
  };
}

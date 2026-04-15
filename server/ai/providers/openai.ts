import OpenAI from 'openai';

export async function chatOpenAI(
  messages: { role: string; content: string }[],
  options?: {
    model?: string;
    temperature?: number;
    apiKey?: string;
    maxTokens?: number;
  }
): Promise<string> {
  const client = new OpenAI({
    apiKey: options?.apiKey || process.env.OPENAI_API_KEY,
  });

  const response = await client.chat.completions.create({
    model: options?.model || 'gpt-4o',
    messages: messages as OpenAI.Chat.ChatCompletionMessageParam[],
    temperature: options?.temperature ?? 0.7,
    max_tokens: options?.maxTokens ?? 4096,
  });

  return response.choices[0]?.message?.content || '';
}

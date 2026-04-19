import { assertSafeExternalUrl } from '../../lib/net.js';

const GEMINI_HOST = 'generativelanguage.googleapis.com';
const GEMINI_ALLOWED_HOSTS = [GEMINI_HOST];

export interface GeminiMessage {
  role: 'user' | 'model';
  parts: Array<{ text: string }>;
}

export interface GeminiOptions {
  apiKey: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
}

export interface ChatResponse {
  content: string;
  model: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
  };
}

export async function chatGemini(
  messages: Array<{ role: 'user' | 'assistant' | 'system'; content: string }>,
  options: GeminiOptions
): Promise<ChatResponse> {
  const model = options.model || 'gemini-2.5-flash';
  // API key goes in the header (x-goog-api-key), NOT the query string,
  // so it doesn't land in request-log lines / reverse-proxy access
  // logs / referer headers.
  const url = `https://${GEMINI_HOST}/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  await assertSafeExternalUrl(url, {
    field: 'gemini.api',
    allowedHosts: GEMINI_ALLOWED_HOSTS,
  });

  // Gemini uses 'user'/'model' roles; system messages are prepended to first user turn
  let systemText = '';
  const contents: GeminiMessage[] = [];

  for (const msg of messages) {
    if (msg.role === 'system') {
      systemText += (systemText ? '\n' : '') + msg.content;
    } else if (msg.role === 'user') {
      const text = systemText ? `${systemText}\n\n${msg.content}` : msg.content;
      systemText = ''; // consume once
      contents.push({ role: 'user', parts: [{ text }] });
    } else {
      contents.push({ role: 'model', parts: [{ text: msg.content }] });
    }
  }

  // If there were only system messages and no user message, add a synthetic one
  if (systemText && contents.length === 0) {
    contents.push({ role: 'user', parts: [{ text: systemText }] });
  }

  const body: Record<string, any> = { contents };

  if (options.temperature !== undefined || options.maxTokens !== undefined) {
    body.generationConfig = {};
    if (options.temperature !== undefined) {
      body.generationConfig.temperature = options.temperature;
    }
    if (options.maxTokens !== undefined) {
      body.generationConfig.maxOutputTokens = options.maxTokens;
    }
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': options.apiKey,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Gemini API error ${response.status}: ${text}`);
  }

  const data = await response.json() as any;

  const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  const usage = data.usageMetadata;

  return {
    content,
    model,
    usage: {
      prompt_tokens: usage?.promptTokenCount,
      completion_tokens: usage?.candidatesTokenCount,
    },
  };
}

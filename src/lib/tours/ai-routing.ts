/**
 * AI-routing tour — introduces the multi-provider routing table.
 */
import type { TourDefinition } from './index';

export const aiRoutingTour: TourDefinition = {
  id: 'ai-routing',
  title: 'Configure AI providers',
  description: 'Wire up Claude / OpenAI / Gemini / Ollama and pick which provider handles which task.',
  steps: [
    {
      target: '[data-tour-id="ai-providers-tab"]',
      title: 'Providers',
      body: 'Paste an API key, then click "Test" to confirm the provider responds.',
      placement: 'bottom',
    },
    {
      target: '[data-tour-id="ai-routing-tab"]',
      title: 'Task-based routing',
      body: 'Each task (triage, verify, deep-analyze, …) gets its own provider + fallback chain so cheap tasks stay cheap.',
      placement: 'bottom',
    },
    {
      target: '[data-tour-id="ai-routing-table"]',
      title: 'The routing table',
      body: 'Drag providers into priority order. Verify and deep-analyze default to your strongest model; triage defaults to the cheapest.',
      placement: 'top',
    },
    {
      target: '[data-tour-id="ai-chat-tab"]',
      title: 'Try it',
      body: 'Send a test message in the Chat tab — the response header tells you which provider actually answered.',
      placement: 'left',
    },
  ],
};

export default aiRoutingTour;

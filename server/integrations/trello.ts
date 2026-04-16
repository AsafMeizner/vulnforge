import type { ServiceIntegration, ServiceConfig, TicketResult, ConfigField } from './types.js';

export class TrelloIntegration implements ServiceIntegration {
  readonly name = 'trello';
  readonly type = 'ticketing' as const;
  readonly configFields: ConfigField[] = [
    { key: 'api_key', label: 'API Key', type: 'text', required: true, placeholder: 'Trello API key' },
    { key: 'token', label: 'Token', type: 'password', required: true, placeholder: 'Trello token' },
    { key: 'board_id', label: 'Board ID', type: 'text', required: true, placeholder: 'Board ID from URL' },
    { key: 'list_id', label: 'List ID', type: 'text', required: true, placeholder: 'List ID for new cards' },
  ];

  async testConnection(config: ServiceConfig): Promise<{ ok: boolean; error?: string }> {
    try {
      const res = await fetch(`https://api.trello.com/1/boards/${config.board_id}?key=${config.api_key}&token=${config.token}`);
      if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
      return { ok: true };
    } catch (err: any) { return { ok: false, error: err.message }; }
  }

  async createTicket(data: { title: string; description: string; severity?: string }, config: ServiceConfig): Promise<TicketResult> {
    const label = data.severity === 'Critical' ? 'red' : data.severity === 'High' ? 'orange' : 'yellow';
    const params = new URLSearchParams({
      key: config.api_key,
      token: config.token,
      idList: config.list_id,
      name: data.title,
      desc: data.description,
    });

    const res = await fetch(`https://api.trello.com/1/cards?${params}`, { method: 'POST' });
    if (!res.ok) throw new Error(`Trello create failed: ${await res.text()}`);
    const card = await res.json();
    return { ticket_id: card.id, url: card.url };
  }
}

import type { ServiceIntegration, ServiceConfig, TicketResult, ConfigField } from './types.js';
import { assertSafeExternalUrl } from '../lib/net.js';

const TRELLO_API_HOST = 'api.trello.com';

/**
 * Trello accepts the (key, token) pair either as `?key=...&token=...`
 * query params OR as an `Authorization: OAuth oauth_consumer_key=...,
 * oauth_token=...` header. The query-string form was previously in use
 * here, which leaked both secrets into every log line along the
 * request path (request-logging middleware, any reverse proxy, browser
 * history, referer headers). We now send them in the header only.
 */
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
      const url = `https://${TRELLO_API_HOST}/1/boards/${encodeURIComponent(config.board_id)}`;
      await assertSafeExternalUrl(url, {
        field: 'trello.api_host',
        allowedHosts: [TRELLO_API_HOST],
      });
      const res = await fetch(url, { headers: this.authHeaders(config) });
      if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
      return { ok: true };
    } catch (err: any) { return { ok: false, error: err.message }; }
  }

  async createTicket(data: { title: string; description: string; severity?: string }, config: ServiceConfig): Promise<TicketResult> {
    const url = `https://${TRELLO_API_HOST}/1/cards`;
    await assertSafeExternalUrl(url, {
      field: 'trello.api_host',
      allowedHosts: [TRELLO_API_HOST],
    });

    // Non-secret params go in the body. Secrets stay in the header.
    const body = new URLSearchParams({
      idList: config.list_id,
      name: data.title,
      desc: data.description,
    });

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        ...this.authHeaders(config),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });
    if (!res.ok) throw new Error(`Trello create failed: ${await res.text()}`);
    const card = await res.json();
    return { ticket_id: card.id, url: card.url };
  }

  /**
   * Trello's OAuth 1.0a-flavoured header. The `oauth_*` params are the
   * only ones Trello looks at in this header - everything else it
   * ignores, which is what we want (no signature or timestamp needed
   * for api-key + pre-issued-token auth).
   */
  private authHeaders(config: ServiceConfig): Record<string, string> {
    const key = String(config.api_key).replace(/"/g, '');
    const token = String(config.token).replace(/"/g, '');
    return {
      Authorization: `OAuth oauth_consumer_key="${key}", oauth_token="${token}"`,
      Accept: 'application/json',
    };
  }
}

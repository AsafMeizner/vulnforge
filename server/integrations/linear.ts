import type { ServiceIntegration, ServiceConfig, TicketResult, ConfigField } from './types.js';
import { assertSafeExternalUrl } from '../lib/net.js';

const LINEAR_ENDPOINT = 'https://api.linear.app/graphql';
const LINEAR_ALLOWED_HOSTS = ['api.linear.app'];

export class LinearIntegration implements ServiceIntegration {
  readonly name = 'linear';
  readonly type = 'ticketing' as const;
  readonly configFields: ConfigField[] = [
    { key: 'api_key', label: 'API Key', type: 'password', required: true, placeholder: 'lin_api_...' },
    { key: 'team_id', label: 'Team ID', type: 'text', required: true, placeholder: 'Team UUID' },
  ];

  async testConnection(config: ServiceConfig): Promise<{ ok: boolean; error?: string }> {
    try {
      await assertSafeExternalUrl(LINEAR_ENDPOINT, {
        field: 'linear.api',
        allowedHosts: LINEAR_ALLOWED_HOSTS,
      });
      const res = await fetch(LINEAR_ENDPOINT, {
        method: 'POST',
        headers: this.headers(config),
        body: JSON.stringify({ query: '{ viewer { id name } }' }),
      });
      if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
      const data = await res.json();
      if (data.errors) return { ok: false, error: data.errors[0]?.message };
      return { ok: true };
    } catch (err: any) { return { ok: false, error: err.message }; }
  }

  async createTicket(data: { title: string; description: string; severity?: string }, config: ServiceConfig): Promise<TicketResult> {
    const priorityMap: Record<string, number> = { Critical: 1, High: 2, Medium: 3, Low: 4 };
    const priority = data.severity ? priorityMap[data.severity] || 3 : 3;

    const query = `
      mutation IssueCreate($input: IssueCreateInput!) {
        issueCreate(input: $input) {
          success
          issue { id identifier url }
        }
      }
    `;

    await assertSafeExternalUrl(LINEAR_ENDPOINT, {
      field: 'linear.api',
      allowedHosts: LINEAR_ALLOWED_HOSTS,
    });
    const res = await fetch(LINEAR_ENDPOINT, {
      method: 'POST',
      headers: this.headers(config),
      body: JSON.stringify({
        query,
        variables: {
          input: {
            teamId: config.team_id,
            title: data.title,
            description: data.description,
            priority,
          },
        },
      }),
    });

    if (!res.ok) throw new Error(`Linear create failed: ${await res.text()}`);
    const result = await res.json();
    if (result.errors) throw new Error(result.errors[0]?.message);
    const issue = result.data.issueCreate.issue;
    return { ticket_id: issue.identifier, url: issue.url };
  }

  private headers(config: ServiceConfig): Record<string, string> {
    return {
      Authorization: config.api_key,
      'Content-Type': 'application/json',
    };
  }
}

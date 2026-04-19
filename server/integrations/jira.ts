/**
 * Jira Cloud / Server integration via REST API v3.
 */
import type { ServiceIntegration, ServiceConfig, TicketResult, ConfigField } from './types.js';
import { assertSafeExternalUrl } from '../lib/net.js';

const SEVERITY_TO_PRIORITY: Record<string, string> = {
  Critical: 'Highest',
  High: 'High',
  Medium: 'Medium',
  Low: 'Low',
};

export class JiraIntegration implements ServiceIntegration {
  readonly name = 'jira';
  readonly type = 'ticketing' as const;
  readonly configFields: ConfigField[] = [
    { key: 'base_url', label: 'Jira URL', type: 'url', required: true, placeholder: 'https://yourcompany.atlassian.net' },
    { key: 'email', label: 'Email', type: 'text', required: true, placeholder: 'user@company.com' },
    { key: 'api_token', label: 'API Token', type: 'password', required: true, placeholder: 'Jira API token' },
    { key: 'project_key', label: 'Project Key', type: 'text', required: true, placeholder: 'SEC' },
    { key: 'issue_type', label: 'Issue Type', type: 'text', required: false, placeholder: 'Bug' },
  ];

  async testConnection(config: ServiceConfig): Promise<{ ok: boolean; error?: string }> {
    try {
      const url = `${config.base_url}/rest/api/3/myself`;
      await assertSafeExternalUrl(url, { field: 'jira.base_url' });
      const res = await fetch(url, {
        headers: this.headers(config),
      });
      if (!res.ok) return { ok: false, error: `HTTP ${res.status}: ${await res.text()}` };
      return { ok: true };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  async createTicket(data: { title: string; description: string; severity?: string }, config: ServiceConfig): Promise<TicketResult> {
    const body = {
      fields: {
        project: { key: config.project_key },
        summary: data.title,
        description: {
          type: 'doc',
          version: 1,
          content: [{ type: 'paragraph', content: [{ type: 'text', text: data.description }] }],
        },
        issuetype: { name: config.issue_type || 'Bug' },
        priority: data.severity ? { name: SEVERITY_TO_PRIORITY[data.severity] || 'Medium' } : undefined,
      },
    };

    const url = `${config.base_url}/rest/api/3/issue`;
    await assertSafeExternalUrl(url, { field: 'jira.base_url' });
    const res = await fetch(url, {
      method: 'POST',
      headers: this.headers(config),
      body: JSON.stringify(body),
    });

    if (!res.ok) throw new Error(`Jira create failed: ${await res.text()}`);
    const result = await res.json();
    return {
      ticket_id: result.key,
      url: `${config.base_url}/browse/${result.key}`,
    };
  }

  async updateTicket(ticketId: string, updates: { status?: string; comment?: string }, config: ServiceConfig): Promise<void> {
    if (updates.comment) {
      const url = `${config.base_url}/rest/api/3/issue/${encodeURIComponent(ticketId)}/comment`;
      await assertSafeExternalUrl(url, { field: 'jira.base_url' });
      await fetch(url, {
        method: 'POST',
        headers: this.headers(config),
        body: JSON.stringify({
          body: {
            type: 'doc',
            version: 1,
            content: [{ type: 'paragraph', content: [{ type: 'text', text: updates.comment }] }],
          },
        }),
      });
    }
  }

  private headers(config: ServiceConfig): Record<string, string> {
    const auth = Buffer.from(`${config.email}:${config.api_token}`).toString('base64');
    return {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
  }
}

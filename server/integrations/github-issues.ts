import type { ServiceIntegration, ServiceConfig, TicketResult, ConfigField } from './types.js';
import { assertSafeExternalUrl } from '../lib/net.js';

const GH_API_HOST = 'api.github.com';
const GH_ALLOWED_HOSTS = [GH_API_HOST];

export class GitHubIssuesIntegration implements ServiceIntegration {
  readonly name = 'github';
  readonly type = 'ticketing' as const;
  readonly configFields: ConfigField[] = [
    { key: 'token', label: 'Personal Access Token', type: 'password', required: true, placeholder: 'ghp_...' },
    { key: 'owner', label: 'Repository Owner', type: 'text', required: true, placeholder: 'org-name' },
    { key: 'repo', label: 'Repository Name', type: 'text', required: true, placeholder: 'repo-name' },
    { key: 'labels', label: 'Labels (comma-separated)', type: 'text', required: false, placeholder: 'security,vulnerability' },
  ];

  async testConnection(config: ServiceConfig): Promise<{ ok: boolean; error?: string }> {
    try {
      const url = `https://${GH_API_HOST}/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}`;
      await assertSafeExternalUrl(url, { field: 'github.api', allowedHosts: GH_ALLOWED_HOSTS });
      const res = await fetch(url, { headers: this.headers(config) });
      if (!res.ok) return { ok: false, error: `HTTP ${res.status}: ${await res.text()}` };
      return { ok: true };
    } catch (err: any) { return { ok: false, error: err.message }; }
  }

  async createTicket(data: { title: string; description: string; severity?: string }, config: ServiceConfig): Promise<TicketResult> {
    const labels = config.labels ? config.labels.split(',').map((l: string) => l.trim()) : ['security'];
    if (data.severity) labels.push(data.severity.toLowerCase());

    const url = `https://${GH_API_HOST}/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}/issues`;
    await assertSafeExternalUrl(url, { field: 'github.api', allowedHosts: GH_ALLOWED_HOSTS });
    const res = await fetch(url, {
      method: 'POST',
      headers: this.headers(config),
      body: JSON.stringify({ title: data.title, body: data.description, labels }),
    });

    if (!res.ok) throw new Error(`GitHub issue creation failed: ${await res.text()}`);
    const issue = await res.json();
    return { ticket_id: String(issue.number), url: issue.html_url };
  }

  async updateTicket(ticketId: string, updates: { comment?: string }, config: ServiceConfig): Promise<void> {
    if (updates.comment) {
      const url = `https://${GH_API_HOST}/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(config.repo)}/issues/${encodeURIComponent(ticketId)}/comments`;
      await assertSafeExternalUrl(url, { field: 'github.api', allowedHosts: GH_ALLOWED_HOSTS });
      await fetch(url, {
        method: 'POST',
        headers: this.headers(config),
        body: JSON.stringify({ body: updates.comment }),
      });
    }
  }

  private headers(config: ServiceConfig): Record<string, string> {
    return {
      Authorization: `Bearer ${config.token}`,
      Accept: 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
    };
  }
}

import type { ServiceIntegration, ServiceConfig, TicketResult, ConfigField } from './types.js';

export class SlackIntegration implements ServiceIntegration {
  readonly name = 'slack';
  readonly type = 'messaging' as const;
  readonly configFields: ConfigField[] = [
    { key: 'webhook_url', label: 'Webhook URL', type: 'url', required: true, placeholder: 'https://hooks.slack.com/services/...' },
    { key: 'channel', label: 'Channel (optional)', type: 'text', required: false, placeholder: '#security' },
  ];

  async testConnection(config: ServiceConfig): Promise<{ ok: boolean; error?: string }> {
    try {
      const res = await fetch(config.webhook_url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'VulnForge integration test - connection successful!' }),
      });
      return { ok: res.ok, error: res.ok ? undefined : `HTTP ${res.status}` };
    } catch (err: any) { return { ok: false, error: err.message }; }
  }

  async createTicket(data: { title: string; description: string; severity?: string; url?: string }, config: ServiceConfig): Promise<TicketResult> {
    // Slack doesn't create tickets — send a formatted message instead
    await this.sendNotification(
      `*[${data.severity || 'Medium'}] New Finding*\n>${data.title}\n${data.description?.slice(0, 300) || ''}${data.url ? `\n<${data.url}|View in VulnForge>` : ''}`,
      config,
    );
    return { ticket_id: 'slack-msg', url: '' };
  }

  async sendNotification(message: string, config: ServiceConfig): Promise<void> {
    const res = await fetch(config.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: message,
        channel: config.channel || undefined,
      }),
    });
    if (!res.ok) throw new Error(`Slack notification failed: ${res.status}`);
  }
}

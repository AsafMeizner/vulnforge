/**
 * External Service Integration interface.
 * Each integration (Jira, Trello, Slack, GitHub, Linear) implements this.
 */

export interface ServiceConfig {
  [key: string]: any;
}

export interface TicketResult {
  ticket_id: string;
  url: string;
}

export interface ServiceIntegration {
  readonly name: string;
  readonly type: 'ticketing' | 'messaging';
  readonly configFields: ConfigField[];

  testConnection(config: ServiceConfig): Promise<{ ok: boolean; error?: string }>;
  createTicket(data: { title: string; description: string; severity?: string; url?: string }, config: ServiceConfig): Promise<TicketResult>;
  updateTicket?(ticketId: string, updates: { status?: string; comment?: string }, config: ServiceConfig): Promise<void>;
  sendNotification?(message: string, config: ServiceConfig): Promise<void>;
}

export interface ConfigField {
  key: string;
  label: string;
  type: 'text' | 'password' | 'url' | 'select';
  required: boolean;
  placeholder?: string;
  options?: string[];
}

/**
 * Integration registry — maps service names to their implementations.
 */
import type { ServiceIntegration } from './types.js';
import { JiraIntegration } from './jira.js';
import { TrelloIntegration } from './trello.js';
import { SlackIntegration } from './slack.js';
import { GitHubIssuesIntegration } from './github-issues.js';
import { LinearIntegration } from './linear.js';

const INTEGRATIONS: Record<string, ServiceIntegration> = {
  jira: new JiraIntegration(),
  trello: new TrelloIntegration(),
  slack: new SlackIntegration(),
  github: new GitHubIssuesIntegration(),
  linear: new LinearIntegration(),
};

export function getServiceIntegration(name: string): ServiceIntegration | null {
  return INTEGRATIONS[name.toLowerCase()] || null;
}

export function listAvailableIntegrations(): Array<{
  name: string;
  type: string;
  configFields: any[];
}> {
  return Object.values(INTEGRATIONS).map(i => ({
    name: i.name,
    type: i.type,
    configFields: i.configFields,
  }));
}

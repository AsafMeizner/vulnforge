/**
 * Dashboard tour — introduces the landing page to a new user.
 *
 * Targets rely on `data-tour-id="..."` attributes that the integrator wires
 * into existing pages. Until they are wired the overlay falls back to a
 * centered popover without a highlight.
 */
import type { TourDefinition } from './index';

export const dashboardTour: TourDefinition = {
  id: 'dashboard',
  title: 'Welcome to the dashboard',
  description: "A 60-second spin around the landing page.",
  steps: [
    {
      target: '[data-tour-id="nav-sidebar"]',
      title: 'Navigation',
      body: 'Every workflow in VulnForge lives in the left sidebar. Hunt is the quickest way to kick off research.',
      placement: 'right',
    },
    {
      target: '[data-tour-id="dashboard-scan-count"]',
      title: 'Scan counters',
      body: 'These cards surface the high-severity findings you should look at first.',
      placement: 'bottom',
    },
    {
      target: '[data-tour-id="dashboard-pipelines"]',
      title: 'Pipeline list',
      body: 'Running, queued and recently-finished pipelines live here — click one to jump into the Review queue.',
      placement: 'top',
    },
    {
      target: '[data-tour-id="dashboard-ai-status"]',
      title: 'AI status',
      body: 'Shows which AI provider is currently active and whether routing rules need attention.',
      placement: 'left',
    },
  ],
};

export default dashboardTour;

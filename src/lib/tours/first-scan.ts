/**
 * First-scan tour — walks the user from "what is this page?" to a running scan.
 */
import type { TourDefinition } from './index';

export const firstScanTour: TourDefinition = {
  id: 'first-scan',
  title: 'Run your first scan',
  description: 'Five steps from a blank Scanner page to a running pipeline.',
  steps: [
    {
      target: '[data-tour-id="scanner-page"]',
      title: 'The Scanner page',
      body: 'This is where you orchestrate static-analysis tools over a local project path or git URL.',
      placement: 'bottom',
    },
    {
      target: '[data-tour-id="scanner-project-input"]',
      title: 'Pick a project',
      body: 'Paste a path to a repo you already cloned, or a git URL — VulnForge will clone it for you.',
      placement: 'right',
    },
    {
      target: '[data-tour-id="scanner-tool-selection"]',
      title: 'Select tools',
      body: 'Pick one tool to get a feel for the output, or keep the default bundle for broad coverage.',
      placement: 'right',
    },
    {
      target: '[data-tour-id="scanner-start-button"]',
      title: 'Start the scan',
      body: 'Click Start — results stream in as each tool finishes. Nothing leaves your machine in solo mode.',
      placement: 'top',
    },
    {
      target: '[data-tour-id="scanner-progress"]',
      title: 'Watch it run',
      body: 'Per-tool progress shows here. When everything turns green, head to the Findings page to triage.',
      placement: 'left',
    },
  ],
};

export default firstScanTour;

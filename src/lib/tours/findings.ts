/**
 * Findings tour — explains the findings list and the review flow.
 */
import type { TourDefinition } from './index';

export const findingsTour: TourDefinition = {
  id: 'findings',
  title: 'Understanding findings',
  description: 'Learn how to triage, verify and export findings.',
  steps: [
    {
      target: '[data-tour-id="findings-list"]',
      title: 'The finding list',
      body: 'One row per vulnerability. Click a row to open the detail drawer with full dataflow + verification trace.',
      placement: 'bottom',
    },
    {
      target: '[data-tour-id="findings-severity-filter"]',
      title: 'Severity filter',
      body: 'Quickly scope to Critical/High or widen to Info — the counts update live.',
      placement: 'bottom',
    },
    {
      target: '[data-tour-id="findings-verify-button"]',
      title: 'Verify a finding',
      body: "Ask the AI to build a PoC. VulnForge runs it in a sandbox and records the result on the finding.",
      placement: 'left',
    },
    {
      target: '[data-tour-id="findings-export"]',
      title: 'Export',
      body: 'CSV, JSON, SARIF or a markdown disclosure draft — all generated from the current filter.',
      placement: 'bottom',
    },
  ],
};

export default findingsTour;

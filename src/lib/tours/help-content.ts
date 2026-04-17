/**
 * Keyed contextual help content. The `HelpButton` component renders the
 * tooltip from this registry and opens `docLink` on click.
 *
 * The doc paths are deep links into the bundled documentation site served
 * by the backend under `/docs/...`. They are absolute paths — consumers
 * should NOT prefix a protocol or host.
 */

export interface HelpEntry {
  /** Title shown at the top of the tooltip. */
  title: string;
  /** Short description (one or two sentences). */
  text: string;
  /** Deep link to the relevant docs page. */
  docLink: string;
}

export const HELP_CONTENT: Record<string, HelpEntry> = {
  'dashboard.stats': {
    title: 'Dashboard statistics',
    text: 'Aggregated counts from the current project filter. Click a card to jump to its filtered view.',
    docLink: '/docs/ui/dashboard#statistics',
  },
  'scanner.project-input': {
    title: 'Project path or URL',
    text: 'Accepts a local directory path or a git URL. Git URLs are cloned into ~/.vulnforge/clones.',
    docLink: '/docs/scanner/projects',
  },
  'scanner.tool-selection': {
    title: 'Tool selection',
    text: 'VulnForge ships 48 static analysers and 10 external plugins. Leave empty for the curated default bundle.',
    docLink: '/docs/scanner/tools',
  },
  'findings.severity': {
    title: 'Severity filter',
    text: 'Severities come from the CWE → CVSS mapping and the AI verifier — disputes are recorded in the finding detail.',
    docLink: '/docs/findings/severity',
  },
  'findings.verify': {
    title: 'AI verification',
    text: 'Runs an N-vote self-consistency pass and (optionally) a sandboxed PoC. Costs increase with N — see Settings → AI.',
    docLink: '/docs/ai/verify',
  },
  'ai.providers': {
    title: 'AI providers',
    text: 'Claude, OpenAI, Gemini, Ollama and the Claude CLI are supported. Keys live in your OS keychain.',
    docLink: '/docs/ai/providers',
  },
  'ai.routing': {
    title: 'Task-based routing',
    text: 'Map each task (triage, verify, …) to a provider and a fallback chain. Cheap providers handle cheap tasks.',
    docLink: '/docs/ai/routing',
  },
  'pipeline.stages': {
    title: 'Pipeline stages',
    text: 'Clone → Git analysis → Attack surface → Scan + CVE hunt → Filter → Chain detection → AI verify → Review.',
    docLink: '/docs/pipeline/overview',
  },
  'shortcuts.cheatsheet': {
    title: 'Keyboard shortcuts',
    text: 'Press ? at any time to see the full shortcut cheatsheet.',
    docLink: '/docs/ui/shortcuts',
  },
  'onboarding.resume': {
    title: 'Onboarding tours',
    text: 'Re-run any tour from Settings → Onboarding. Tours never repeat unless you explicitly restart them.',
    docLink: '/docs/ui/onboarding',
  },
};

/**
 * Safe lookup — returns a minimal fallback entry if the ID is unknown so
 * consumers never have to null-check.
 */
export function getHelp(id: string): HelpEntry {
  return (
    HELP_CONTENT[id] || {
      title: 'Help',
      text: 'No help content is registered for this element yet.',
      docLink: '/docs',
    }
  );
}

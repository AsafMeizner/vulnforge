/**
 * Plugin Integration Registry
 *
 * Each integration provides install(), run(), and parseOutput() for a specific
 * external security tool. The INTEGRATIONS map is keyed by catalog name so the
 * PluginManager can resolve the right integration at runtime.
 */

import { NettackerIntegration } from './nettacker.js';
import { GarakIntegration } from './garak.js';
import { NucleiIntegration } from './nuclei.js';
import { SemgrepIntegration } from './semgrep.js';
import { TrivyIntegration } from './trivy.js';
import { CodeQLIntegration } from './codeql.js';
import { BanditIntegration } from './bandit.js';
import { GrypeIntegration } from './grype.js';
import { OSVScannerIntegration } from './osv-scanner.js';
import { SafetyIntegration } from './safety.js';

// ── Shared type ───────────────────────────────────────────────────────────────

export interface PluginFinding {
  title: string;
  severity: string;
  description: string;
  file?: string;
  code_snippet?: string;
  raw?: any;
}

export interface PluginRunResult {
  output: string;
  findings: PluginFinding[];
}

/**
 * Common interface every integration must satisfy.
 * Optional methods (getAvailableModules etc.) are present only on integrations
 * that expose configurable sub-options.
 */
export interface PluginIntegration {
  /** Canonical catalog name - must match PLUGIN_CATALOG[].name (lowercased) */
  name: string;
  /** Installs the tool into installDir */
  install: (installDir: string) => Promise<void>;
  /** Runs the tool against target with options, returns raw output + parsed findings */
  run: (
    target: string,
    options?: Record<string, any>,
    installDir?: string
  ) => Promise<PluginRunResult>;
  /** Parses raw tool output into structured findings */
  parseOutput: (raw: string) => PluginFinding[];
  /** Available scan modules (Nettacker) */
  getAvailableModules?: () => string[];
  /** Available LLM probes (Garak) */
  getAvailableProbes?: () => string[];
  /** Available template categories (Nuclei) */
  getAvailableTemplates?: () => string[];
  /** Available Semgrep rule configs */
  getAvailableConfigs?: () => string[];
}

// ── Registry ──────────────────────────────────────────────────────────────────

export const INTEGRATIONS: Record<string, PluginIntegration> = {
  // Keyed by catalog name (case-insensitive match is done in getIntegration())
  'owasp nettacker': NettackerIntegration as unknown as PluginIntegration,
  'garak':           GarakIntegration as unknown as PluginIntegration,
  'nuclei':          NucleiIntegration as unknown as PluginIntegration,
  'semgrep':         SemgrepIntegration as unknown as PluginIntegration,
  'trivy':           TrivyIntegration as unknown as PluginIntegration,
  'codeql':          CodeQLIntegration as unknown as PluginIntegration,
  'bandit':          BanditIntegration as unknown as PluginIntegration,
  'grype':           GrypeIntegration as unknown as PluginIntegration,
  'osv-scanner':     OSVScannerIntegration as unknown as PluginIntegration,
  'safety':          SafetyIntegration as unknown as PluginIntegration,
};

/**
 * Look up an integration by catalog name (case-insensitive).
 * Returns null if no matching integration exists.
 */
export function getIntegration(pluginName: string): PluginIntegration | null {
  const key = pluginName.toLowerCase().trim();
  return INTEGRATIONS[key] ?? null;
}

/**
 * Return the list of available sub-options (modules/probes/templates/configs)
 * for a named plugin, or an empty array if the plugin has none.
 */
export function getPluginModules(pluginName: string): string[] {
  const integration = getIntegration(pluginName);
  if (!integration) return [];
  return (
    integration.getAvailableModules?.() ??
    integration.getAvailableProbes?.() ??
    integration.getAvailableTemplates?.() ??
    integration.getAvailableConfigs?.() ??
    []
  );
}

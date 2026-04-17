import path from 'path';
import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface NucleiOptions {
  templates?: string[];
  severity?: string[];
  rateLimit?: number;
  timeout?: number;
  outputFile?: string;
}

export interface PluginFinding {
  title: string;
  severity: string;
  description: string;
  file?: string;
  code_snippet?: string;
  raw?: any;
}

function normalizeNucleiSeverity(s: string | undefined): string {
  const m: Record<string, string> = {
    critical: 'Critical', high: 'High', medium: 'Medium',
    low: 'Low', info: 'Low', informational: 'Low', unknown: 'Low',
  };
  return m[(s ?? '').toLowerCase()] ?? 'Low';
}

export const NucleiIntegration = {
  name: 'nuclei',

  install: async (_installDir: string): Promise<void> => {
    console.log('[Nuclei] Installing via go install...');
    const goBin = process.platform === 'win32' ? 'C:\\Program Files\\Go\\bin\\go.exe' : 'go';
    const result = await execFileNoThrow(goBin, [
      'install', 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
    ], { timeout: 300_000 });
    if (!result.ok) throw new Error(`go install nuclei failed: ${result.stderr}`);

    console.log('[Nuclei] Updating templates...');
    await execFileNoThrow('nuclei', ['-update-templates'], {
      timeout: 120_000, useShell: true,
    });
    console.log('[Nuclei] Install complete.');
  },

  run: async (
    target: string,
    options: NucleiOptions = {},
    installDir?: string
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const outputFile = options.outputFile
      ?? path.join(installDir ?? '/tmp', `nuclei-out-${Date.now()}.json`);

    const args = ['-u', target, '-json', '-o', outputFile, '-silent'];
    if (options.severity && options.severity.length > 0) {
      args.push('-severity', options.severity.join(','));
    }
    if (options.templates && options.templates.length > 0) {
      args.push('-t', options.templates.join(','));
    }
    if (options.rateLimit) {
      args.push('-rate-limit', String(options.rateLimit));
    }

    console.log(`[Nuclei] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('nuclei', args, {
      timeout: (options.timeout ?? 300) * 1000,
      useShell: true,
    });

    const output = result.stdout + result.stderr;
    return { output, findings: NucleiIntegration.parseOutput(output) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    for (const line of raw.split('\n').filter(Boolean)) {
      try {
        const obj = JSON.parse(line) as any;
        if (!obj || typeof obj !== 'object') continue;
        const info = obj.info ?? {};
        const severity = normalizeNucleiSeverity(info.severity ?? obj.severity);
        const templateId: string = obj['template-id'] ?? obj.templateID ?? 'unknown';
        const matchedAt: string = obj['matched-at'] ?? obj.matchedAt ?? '';
        findings.push({
          title: info.name ?? templateId,
          severity,
          description: info.description
            ?? `Template "${templateId}" matched at ${matchedAt}`,
          file: matchedAt || undefined,
          code_snippet: obj.extracted_results
            ? JSON.stringify(obj.extracted_results) : undefined,
          raw: obj,
        });
      } catch { /* progress lines - skip */ }
    }
    return findings;
  },

  getAvailableTemplates: (): string[] => [
    'cves', 'exposures', 'misconfiguration', 'vulnerabilities',
    'default-logins', 'file', 'fuzzing', 'headless', 'iot',
    'network', 'ssl', 'takeovers', 'technologies',
  ],
};

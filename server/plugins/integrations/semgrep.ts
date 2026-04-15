import path from 'path';
import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface SemgrepOptions {
  config?: string;
  language?: string;
  severity?: string[];
  exclude?: string[];
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

function normalizeSemgrepSeverity(s: string | undefined): string {
  const m: Record<string, string> = {
    error: 'High', warning: 'Medium', info: 'Low', note: 'Low',
    critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
  };
  return m[(s ?? '').toLowerCase()] ?? 'Medium';
}

export const SemgrepIntegration = {
  name: 'semgrep',

  install: async (_installDir: string): Promise<void> => {
    console.log('[Semgrep] Installing via pip...');
    const result = await execFileNoThrow('pip', ['install', 'semgrep'], {
      timeout: 300_000, useShell: true,
    });
    if (!result.ok) throw new Error(`pip install semgrep failed: ${result.stderr}`);
    console.log('[Semgrep] Install complete.');
  },

  run: async (
    target: string,
    options: SemgrepOptions = {},
    installDir?: string
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const config = options.config ?? 'auto';
    const outputFile = options.outputFile
      ?? path.join(installDir ?? '/tmp', `semgrep-out-${Date.now()}.json`);

    const args = ['--config', config, target, '--json', '-o', outputFile, '--quiet'];
    if (options.language) args.push('--lang', options.language);
    if (options.severity && options.severity.length > 0) {
      for (const sev of options.severity) args.push('--severity', sev.toUpperCase());
    }
    if (options.exclude && options.exclude.length > 0) {
      for (const ex of options.exclude) args.push('--exclude', ex);
    }

    console.log(`[Semgrep] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('semgrep', args, {
      timeout: (options.timeout ?? 300) * 1000,
      useShell: true,
    });

    const output = result.stdout + result.stderr;
    return { output, findings: SemgrepIntegration.parseOutput(output) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    // Semgrep outputs a single JSON object (not JSONL)
    const jsonStart = raw.indexOf('{');
    if (jsonStart < 0) return findings;
    try {
      const obj = JSON.parse(raw.slice(jsonStart)) as any;
      const results: any[] = obj.results ?? [];
      for (const r of results) {
        const extra = r.extra ?? {};
        const severity = normalizeSemgrepSeverity(
          extra.severity ?? extra.metadata?.confidence ?? r.severity
        );
        findings.push({
          title: r.check_id ?? 'Semgrep Finding',
          severity,
          description: extra.message ?? r.message ?? r.check_id ?? '',
          file: r.path
            ? `${r.path}:${r.start?.line ?? ''}` : undefined,
          code_snippet: extra.lines ?? r.extra?.lines ?? undefined,
          raw: r,
        });
      }
    } catch { /* malformed JSON — ignore */ }
    return findings;
  },

  getAvailableConfigs: (): string[] => [
    'auto', 'p/security-audit', 'p/owasp-top-ten', 'p/ci',
    'p/secrets', 'p/supply-chain', 'p/r2c-security-audit',
    'p/cwe-top-25', 'p/default',
  ],
};

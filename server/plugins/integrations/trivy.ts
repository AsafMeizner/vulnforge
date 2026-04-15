import path from 'path';
import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface TrivyOptions {
  scanType?: 'fs' | 'repo' | 'image' | 'config';
  severity?: string[];
  ignoreUnfixed?: boolean;
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

function normalizeTrivySeverity(s: string | undefined): string {
  const m: Record<string, string> = {
    critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Low',
  };
  return m[(s ?? '').toLowerCase()] ?? 'Low';
}

export const TrivyIntegration = {
  name: 'trivy',

  install: async (_installDir: string): Promise<void> => {
    console.log('[Trivy] Installing via install script...');
    // Use PowerShell on Windows, curl on Unix
    const isWin = process.platform === 'win32';
    if (isWin) {
      const result = await execFileNoThrow('winget', [
        'install', '--id', 'AquaSecurity.Trivy', '-e',
      ], { timeout: 300_000, useShell: true });
      if (!result.ok) throw new Error(`winget install trivy failed: ${result.stderr}`);
    } else {
      const result = await execFileNoThrow('sh', [
        '-c',
        'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh',
      ], { timeout: 300_000 });
      if (!result.ok) throw new Error(`trivy install script failed: ${result.stderr}`);
    }
    console.log('[Trivy] Install complete.');
  },

  run: async (
    target: string,
    options: TrivyOptions = {},
    installDir?: string
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const scanType = options.scanType ?? 'fs';
    const outputFile = options.outputFile
      ?? path.join(installDir ?? '/tmp', `trivy-out-${Date.now()}.json`);

    const args = [scanType, target, '--format', 'json', '-o', outputFile, '--quiet'];
    if (options.severity && options.severity.length > 0) {
      args.push('--severity', options.severity.join(',').toUpperCase());
    }
    if (options.ignoreUnfixed) args.push('--ignore-unfixed');

    console.log(`[Trivy] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('trivy', args, {
      timeout: (options.timeout ?? 300) * 1000,
      useShell: true,
    });

    const output = result.stdout + result.stderr;
    return { output, findings: TrivyIntegration.parseOutput(output) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    const jsonStart = raw.indexOf('{');
    if (jsonStart < 0) return findings;
    try {
      const obj = JSON.parse(raw.slice(jsonStart)) as any;
      const scanResults: any[] = obj.Results ?? [];
      for (const scanResult of scanResults) {
        const vulns: any[] = scanResult.Vulnerabilities ?? [];
        for (const v of vulns) {
          findings.push({
            title: `${v.VulnerabilityID}: ${v.Title ?? v.PkgName}`,
            severity: normalizeTrivySeverity(v.Severity),
            description: v.Description ?? v.Title ?? v.VulnerabilityID,
            file: scanResult.Target ?? undefined,
            code_snippet: v.FixedVersion
              ? `Fixed in: ${v.FixedVersion}` : undefined,
            raw: v,
          });
        }
      }
    } catch { /* malformed JSON */ }
    return findings;
  },

  getAvailableModules: () => [
    'fs_scan', 'repo_scan', 'image_scan', 'config_scan',
    'os_packages', 'language_packages', 'misconfigurations',
    'secrets_detection', 'license_check', 'sbom_generation',
    'kubernetes_scan', 'aws_scan', 'dockerfile_scan',
  ],
};

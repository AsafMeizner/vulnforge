import path from 'path';
import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface SafetyOptions {
  requirementsFile?: string;
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

export const SafetyIntegration = {
  name: 'safety',

  install: async (_installDir: string): Promise<void> => {
    console.log('[Safety] Installing via pip...');
    const result = await execFileNoThrow('pip', ['install', 'safety'], {
      timeout: 120_000, useShell: true,
    });
    if (!result.ok) throw new Error(`pip install safety failed: ${result.stderr}`);
    console.log('[Safety] Install complete.');
  },

  run: async (
    target: string,
    options: SafetyOptions = {},
    installDir?: string
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const reqFile = options.requirementsFile
      ?? path.join(target, 'requirements.txt');
    const outputFile = options.outputFile
      ?? path.join(installDir ?? '/tmp', `safety-out-${Date.now()}.json`);

    const args = ['check', '-r', reqFile, '--json', '-o', outputFile];

    console.log(`[Safety] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('safety', args, {
      timeout: (options.timeout ?? 120) * 1000,
      useShell: true,
    });

    // Safety exits non-zero when vulns found - use stdout regardless
    const output = result.stdout + result.stderr;
    return { output, findings: SafetyIntegration.parseOutput(result.stdout || result.stderr) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    const jsonStart = raw.indexOf('[');
    if (jsonStart < 0) return findings;
    try {
      // Safety JSON is an array of [package, spec, version, advisory, vuln_id]
      const results = JSON.parse(raw.slice(jsonStart)) as any[];
      if (!Array.isArray(results)) return findings;
      for (const item of results) {
        // New Safety format (v3+): object with vulnerability key
        if (typeof item === 'object' && !Array.isArray(item)) {
          const v = item.vulnerability ?? item;
          findings.push({
            title: `${v.package_name ?? item.package_name ?? 'unknown'}: ${v.vulnerability_id ?? item.vulnerability_id ?? 'unknown'}`,
            severity: 'Medium',
            description: v.advisory ?? v.more_info_url ?? JSON.stringify(v),
            file: 'requirements.txt',
            raw: v,
          });
        } else if (Array.isArray(item) && item.length >= 4) {
          // Legacy format: [package, specs, version, advisory, id]
          findings.push({
            title: `${item[0]}: ${item[4] ?? 'unknown'}`,
            severity: 'Medium',
            description: item[3] ?? '',
            file: 'requirements.txt',
            code_snippet: `Installed: ${item[2]}, Vulnerable: ${item[1]}`,
            raw: item,
          });
        }
      }
    } catch { /* malformed JSON */ }
    return findings;
  },

  getAvailableModules: () => [
    'requirements_scan', 'pipfile_scan', 'poetry_scan',
    'virtualenv_scan', 'stdin_scan',
  ],
};

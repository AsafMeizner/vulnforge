import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface GarakOptions {
  modelType?: string;
  modelName?: string;
  probes?: string[];
  detectors?: string[];
  timeout?: number;
}

export interface PluginFinding {
  title: string;
  severity: string;
  description: string;
  file?: string;
  code_snippet?: string;
  raw?: any;
}

function garakSeverity(failRate: number): string {
  if (failRate >= 0.8) return 'High';
  if (failRate >= 0.5) return 'Medium';
  return 'Low';
}

export const GarakIntegration = {
  name: 'garak',

  install: async (_installDir: string): Promise<void> => {
    console.log('[Garak] Installing via pip...');
    const result = await execFileNoThrow('pip', ['install', 'garak'], {
      timeout: 300_000, useShell: true,
    });
    if (!result.ok) throw new Error(`pip install garak failed: ${result.stderr}`);
    console.log('[Garak] Install complete.');
  },

  run: async (
    target: string,
    options: GarakOptions = {}
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const modelType = options.modelType ?? 'huggingface';
    const modelName = options.modelName ?? target;
    const probes = options.probes?.join(',') ?? 'all';

    const args = [
      '--model_type', modelType,
      '--model_name', modelName,
      '--probes', probes,
      '--report_prefix', '/tmp/garak_out',
    ];
    if (options.detectors && options.detectors.length > 0) {
      args.push('--detectors', options.detectors.join(','));
    }

    console.log(`[Garak] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('garak', args, {
      timeout: (options.timeout ?? 600) * 1000,
      useShell: true,
    });

    const output = result.stdout + result.stderr;
    return { output, findings: GarakIntegration.parseOutput(output) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    for (const line of raw.split('\n').filter(Boolean)) {
      try {
        const obj = JSON.parse(line) as any;
        if (!obj || typeof obj !== 'object') continue;
        const probeName: string = obj.probe ?? obj.probe_name ?? 'unknown';
        const passedRate: number = Number(obj.passed_rate ?? obj.pass_rate ?? 1);
        if (passedRate < 1) {
          findings.push({
            title: `LLM vulnerability: ${probeName}`,
            severity: garakSeverity(1 - passedRate),
            description: obj.description
              ?? `Probe "${probeName}" detected potential vulnerability. Pass rate: ${(passedRate * 100).toFixed(0)}%`,
            file: obj.detector ?? undefined,
            raw: obj,
          });
        }
      } catch {
        const lower = line.toLowerCase();
        if (lower.includes('fail') || lower.includes('vulnerable') || lower.includes('unsafe')) {
          findings.push({ title: 'Garak probe failure', severity: 'Medium', description: line.trim() });
        }
      }
    }
    return findings;
  },

  getAvailableProbes: (): string[] => [
    'encoding', 'glitch', 'goodside', 'knownbadsignatures', 'leakreplay',
    'lmrc', 'misleading', 'packagehallucination', 'promptinject',
    'realtoxicity', 'snowball', 'xss',
  ],
};

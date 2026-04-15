import path from 'path';
import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface NettackerOptions {
  modules?: string[];
  intensity?: 'low' | 'medium' | 'high';
  ports?: string;
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

function normalizeNettackerSeverity(s: string | undefined): string {
  const m: Record<string, string> = {
    critical: 'Critical', high: 'High', medium: 'Medium',
    low: 'Low', info: 'Low', information: 'Low',
  };
  return m[(s ?? '').toLowerCase()] ?? 'Low';
}

export const NettackerIntegration = {
  name: 'owasp-nettacker',

  install: async (installDir: string): Promise<void> => {
    const fs = await import('fs');

    // Clone repo (or pull if already exists)
    console.log(`[Nettacker] Setting up ${installDir}...`);
    if (fs.existsSync(path.join(installDir, '.git'))) {
      console.log('[Nettacker] Directory exists, pulling latest...');
      await execFileNoThrow('git', ['pull'], { cwd: installDir });
    } else {
      if (fs.existsSync(installDir)) {
        console.log('[Nettacker] Removing incomplete directory...');
        fs.rmSync(installDir, { recursive: true, force: true });
      }
      const clone = await execFileNoThrow('git', [
        'clone', '--depth', '1', 'https://github.com/OWASP/Nettacker', installDir,
      ]);
      if (!clone.ok) throw new Error(`git clone failed: ${clone.stderr}`);
    }

    // Find requirements file (might be in root or subdirectory)
    const reqPath = path.join(installDir, 'requirements.txt');
    const altReqPath = path.join(installDir, 'requirements', 'requirements.txt');
    const setupPy = path.join(installDir, 'setup.py');
    const pyproject = path.join(installDir, 'pyproject.toml');

    if (fs.existsSync(reqPath)) {
      console.log('[Nettacker] Installing from requirements.txt...');
      const pip = await execFileNoThrow('pip', ['install', '-r', reqPath], { timeout: 300_000 });
      if (!pip.ok) console.warn(`[Nettacker] pip install warning: ${pip.stderr}`);
    } else if (fs.existsSync(altReqPath)) {
      console.log('[Nettacker] Installing from requirements/requirements.txt...');
      const pip = await execFileNoThrow('pip', ['install', '-r', altReqPath], { timeout: 300_000 });
      if (!pip.ok) console.warn(`[Nettacker] pip install warning: ${pip.stderr}`);
    } else if (fs.existsSync(setupPy)) {
      console.log('[Nettacker] Installing via setup.py...');
      const pip = await execFileNoThrow('pip', ['install', '-e', installDir], { timeout: 300_000 });
      if (!pip.ok) console.warn(`[Nettacker] pip install warning: ${pip.stderr}`);
    } else if (fs.existsSync(pyproject)) {
      console.log('[Nettacker] Installing via pyproject.toml...');
      const pip = await execFileNoThrow('pip', ['install', '-e', installDir], { timeout: 300_000 });
      if (!pip.ok) console.warn(`[Nettacker] pip install warning: ${pip.stderr}`);
    } else {
      console.log('[Nettacker] No requirements file found, trying pip install on directory...');
      const pip = await execFileNoThrow('pip', ['install', installDir], { timeout: 300_000 });
      if (!pip.ok) console.warn(`[Nettacker] pip install warning: ${pip.stderr}`);
    }
    console.log('[Nettacker] Install complete.');
  },

  run: async (
    target: string,
    options: NettackerOptions = {},
    installDir: string
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const modules = options.modules?.join(',') ?? 'port_scan';
    const outputFile = options.outputFile
      ?? path.join(installDir, `nettacker-out-${Date.now()}.json`);

    const args = [
      'nettacker.py', '-i', target, '-m', modules,
      '--graph-output', 'json', '-o', outputFile,
    ];
    if (options.ports) { args.push('--ports', options.ports); }

    console.log(`[Nettacker] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('python3', args, {
      cwd: installDir,
      timeout: (options.timeout ?? 300) * 1000,
      useShell: true,
    });

    const output = result.stdout + result.stderr;
    const findings = NettackerIntegration.parseOutput(output);
    return { output, findings };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    for (const line of raw.split('\n').filter(Boolean)) {
      try {
        const obj = JSON.parse(line) as any;
        const events: any[] = Array.isArray(obj)
          ? obj : obj.results ?? obj.events ?? [obj];
        for (const ev of events) {
          if (!ev || typeof ev !== 'object') continue;
          findings.push({
            title: ev.module_name ?? ev.name ?? 'Nettacker Finding',
            severity: normalizeNettackerSeverity(ev.severity ?? ev.risk),
            description: ev.description ?? ev.output ?? JSON.stringify(ev),
            file: ev.target ?? ev.host ?? undefined,
            raw: ev,
          });
        }
      } catch {
        const lower = line.toLowerCase();
        if (lower.includes('vulnerable') || lower.includes('found')) {
          findings.push({ title: 'Nettacker Detection', severity: 'Low', description: line.trim() });
        }
      }
    }
    return findings;
  },

  getAvailableModules: (): string[] => [
    'http_form_brute', 'xss_scan', 'sqli_scan', 'ssl_scan', 'port_scan',
    'dir_scan', 'subdomain_scan', 'wp_xmlrpc_brute', 'clickjacking_scan',
    'http_options_scan', 'content_security_policy_scan', 'cors_scan',
  ],
};

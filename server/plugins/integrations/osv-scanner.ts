import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface OSVScannerOptions {
  recursive?: boolean;
  lockfile?: string;
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

function normalizeOSVSeverity(s: string | undefined): string {
  const m: Record<string, string> = {
    critical: 'Critical', high: 'High', moderate: 'Medium',
    medium: 'Medium', low: 'Low',
  };
  return m[(s ?? '').toLowerCase()] ?? 'Medium';
}

export const OSVScannerIntegration = {
  name: 'osv-scanner',

  install: async (_installDir: string): Promise<void> => {
    console.log('[OSV-Scanner] Installing via go install...');
    const goBin = process.platform === 'win32' ? 'C:\\Program Files\\Go\\bin\\go.exe' : 'go';
    const result = await execFileNoThrow(goBin, [
      'install', 'github.com/google/osv-scanner/cmd/osv-scanner@latest',
    ], { timeout: 300_000 });
    if (!result.ok) throw new Error(`go install osv-scanner failed: ${result.stderr}`);
    console.log('[OSV-Scanner] Install complete.');
  },

  run: async (
    target: string,
    options: OSVScannerOptions = {}
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const args = ['--json'];
    if (options.recursive !== false) args.push('-r');
    if (options.lockfile) {
      args.push('--lockfile', options.lockfile);
    } else {
      args.push(target);
    }

    console.log(`[OSV-Scanner] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('osv-scanner', args, {
      timeout: (options.timeout ?? 300) * 1000,
      useShell: true,
    });

    // osv-scanner exits non-zero when it finds vulns — use stdout regardless
    const output = result.stdout + result.stderr;
    return { output, findings: OSVScannerIntegration.parseOutput(result.stdout) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    const jsonStart = raw.indexOf('{');
    if (jsonStart < 0) return findings;
    try {
      const obj = JSON.parse(raw.slice(jsonStart)) as any;
      const results: any[] = obj.results ?? [];
      for (const pkgResult of results) {
        const packages: any[] = pkgResult.packages ?? [];
        for (const pkg of packages) {
          const vulns: any[] = pkg.vulnerabilities ?? [];
          for (const v of vulns) {
            const severity = normalizeOSVSeverity(
              v.database_specific?.severity ?? v.severity?.[0]?.score
            );
            const aliases: string[] = v.aliases ?? [];
            findings.push({
              title: `${v.id}: ${pkg.package?.name ?? 'unknown'} ${pkg.package?.version ?? ''}`.trim(),
              severity,
              description: v.summary ?? v.details ?? v.id ?? '',
              file: pkgResult.source?.path ?? undefined,
              code_snippet: aliases.length > 0
                ? `Aliases: ${aliases.join(', ')}` : undefined,
              raw: v,
            });
          }
        }
      }
    } catch { /* malformed JSON */ }
    return findings;
  },

  getAvailableModules: () => [
    'npm_lockfile_scan',
    'pip_requirements_scan',
    'go_mod_scan',
    'cargo_lock_scan',
    'maven_pom_scan',
    'composer_lock_scan',
    'gemfile_lock_scan',
    'pubspec_lock_scan',
    'pnpm_lock_scan',
    'yarn_lock_scan',
    'recursive_directory_scan',
    'sbom_scan',
  ],
};

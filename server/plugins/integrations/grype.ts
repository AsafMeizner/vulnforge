import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface GrypeOptions {
  scope?: 'squashed' | 'all-layers';
  onlyFixed?: boolean;
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

function normalizeGrypeSeverity(s: string | undefined): string {
  const m: Record<string, string> = {
    critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
    negligible: 'Low', unknown: 'Low',
  };
  return m[(s ?? '').toLowerCase()] ?? 'Low';
}

export const GrypeIntegration = {
  name: 'grype',

  install: async (_installDir: string): Promise<void> => {
    console.log('[Grype] Installing...');
    const isWin = process.platform === 'win32';
    if (isWin) {
      const result = await execFileNoThrow('winget', [
        'install', '--id', 'Anchore.Grype', '-e',
      ], { timeout: 300_000, useShell: true });
      if (!result.ok) throw new Error(`winget install grype failed: ${result.stderr}`);
    } else {
      const result = await execFileNoThrow('sh', [
        '-c',
        'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh',
      ], { timeout: 300_000 });
      if (!result.ok) throw new Error(`grype install script failed: ${result.stderr}`);
    }
    console.log('[Grype] Install complete.');
  },

  run: async (
    target: string,
    options: GrypeOptions = {}
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    // Grype supports dir:, image:, file: prefixes — default to dir: for paths
    const scanTarget = target.includes(':') ? target : `dir:${target}`;
    const args = [scanTarget, '-o', 'json'];
    if (options.scope) args.push('--scope', options.scope);
    if (options.onlyFixed) args.push('--only-fixed');

    console.log(`[Grype] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('grype', args, {
      timeout: (options.timeout ?? 300) * 1000,
      useShell: true,
    });

    const output = result.stdout + result.stderr;
    return { output, findings: GrypeIntegration.parseOutput(result.stdout) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    const jsonStart = raw.indexOf('{');
    if (jsonStart < 0) return findings;
    try {
      const obj = JSON.parse(raw.slice(jsonStart)) as any;
      const matches: any[] = obj.matches ?? [];
      for (const match of matches) {
        const vuln = match.vulnerability ?? {};
        const art = match.artifact ?? {};
        const severity = normalizeGrypeSeverity(vuln.severity);
        const fixVersions: string[] = match.vulnerability?.fix?.versions ?? [];
        findings.push({
          title: `${vuln.id ?? 'CVE-unknown'}: ${art.name ?? 'unknown'} ${art.version ?? ''}`.trim(),
          severity,
          description: vuln.description ?? vuln.id ?? '',
          file: art.locations?.[0]?.path ?? art.name ?? undefined,
          code_snippet: fixVersions.length > 0
            ? `Fix available: ${fixVersions.join(', ')}` : undefined,
          raw: match,
        });
      }
    } catch { /* malformed JSON */ }
    return findings;
  },

  getAvailableModules: () => [
    'directory_scan', 'docker_image_scan', 'oci_image_scan',
    'sbom_scan', 'archive_scan', 'registry_scan',
    'nvd_database', 'github_advisories', 'os_advisories',
  ],
};

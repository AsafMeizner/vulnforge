import path from 'path';
import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface BanditOptions {
  severity?: string[];
  confidence?: string[];
  tests?: string[];
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

function normalizeBanditSeverity(s: string | undefined): string {
  const m: Record<string, string> = {
    high: 'High', medium: 'Medium', low: 'Low',
    critical: 'Critical', undefined: 'Low',
  };
  return m[(s ?? '').toLowerCase()] ?? 'Low';
}

export const BanditIntegration = {
  name: 'bandit',

  install: async (_installDir: string): Promise<void> => {
    console.log('[Bandit] Installing via pip...');
    const result = await execFileNoThrow('pip', ['install', 'bandit'], {
      timeout: 120_000, useShell: true,
    });
    if (!result.ok) throw new Error(`pip install bandit failed: ${result.stderr}`);
    console.log('[Bandit] Install complete.');
  },

  run: async (
    target: string,
    options: BanditOptions = {},
    installDir?: string
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const outputFile = options.outputFile
      ?? path.join(installDir ?? '/tmp', `bandit-out-${Date.now()}.json`);

    const args = ['-r', target, '-f', 'json', '-o', outputFile];
    if (options.severity && options.severity.length > 0) {
      // Bandit uses -l (LOW), -ll (MEDIUM+), -lll (HIGH) — map from array
      const sevSet = new Set(options.severity.map(s => s.toUpperCase()));
      if (sevSet.has('HIGH')) args.push('-lll');
      else if (sevSet.has('MEDIUM')) args.push('-ll');
      else args.push('-l');
    }
    if (options.confidence && options.confidence.length > 0) {
      const conSet = new Set(options.confidence.map(c => c.toUpperCase()));
      if (conSet.has('HIGH')) args.push('-iii');
      else if (conSet.has('MEDIUM')) args.push('-ii');
      else args.push('-i');
    }
    if (options.tests && options.tests.length > 0) {
      args.push('-t', options.tests.join(','));
    }
    if (options.exclude && options.exclude.length > 0) {
      args.push('--exclude', options.exclude.join(','));
    }

    console.log(`[Bandit] Running with args: ${args.join(' ')}`);
    const result = await execFileNoThrow('bandit', args, {
      timeout: (options.timeout ?? 300) * 1000,
      useShell: true,
    });

    const output = result.stdout + result.stderr;
    return { output, findings: BanditIntegration.parseOutput(output) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    const jsonStart = raw.indexOf('{');
    if (jsonStart < 0) return findings;
    try {
      const obj = JSON.parse(raw.slice(jsonStart)) as any;
      const results: any[] = obj.results ?? [];
      for (const r of results) {
        findings.push({
          title: `${r.test_id ?? 'B000'}: ${r.test_name ?? 'Bandit Finding'}`,
          severity: normalizeBanditSeverity(r.issue_severity),
          description: r.issue_text ?? r.test_name ?? '',
          file: r.filename
            ? `${r.filename}:${r.line_number ?? ''}` : undefined,
          code_snippet: r.code ?? undefined,
          raw: r,
        });
      }
    } catch { /* malformed JSON */ }
    return findings;
  },

  getAvailableModules: () => [
    'B101_assert_used', 'B102_exec_used', 'B103_set_bad_file_permissions',
    'B104_hardcoded_bind_all', 'B105_hardcoded_password_string',
    'B106_hardcoded_password_funcarg', 'B107_hardcoded_password_default',
    'B110_try_except_pass', 'B201_flask_debug_true',
    'B301_unsafe_deserialization', 'B303_md5', 'B304_ciphers',
    'B307_eval', 'B308_mark_safe', 'B310_urllib_urlopen',
    'B311_random', 'B323_unverified_context', 'B324_hashlib_insecure',
    'B501_request_no_cert_validation', 'B502_ssl_bad_version',
    'B506_yaml_load', 'B602_subprocess_popen_shell',
    'B608_hardcoded_sql', 'B701_jinja2_autoescape_false',
  ],
};

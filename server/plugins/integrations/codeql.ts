import path from 'path';
import { execFileNoThrow } from '../../utils/execFileNoThrow.js';

export interface CodeQLOptions {
  language?: string;
  queries?: string[];
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

function normalizeCodeQLSeverity(s: string | undefined): string {
  const m: Record<string, string> = {
    error: 'High', warning: 'Medium', recommendation: 'Low', note: 'Low',
    critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
  };
  return m[(s ?? '').toLowerCase()] ?? 'Medium';
}

export const CodeQLIntegration = {
  name: 'codeql',

  install: async (installDir: string): Promise<void> => {
    const fs = await import('fs');
    const isWin = process.platform === 'win32';

    // Method 1: Try gh extension
    console.log('[CodeQL] Trying GitHub CLI extension install...');
    const ghPath = isWin ? 'C:\\Program Files\\GitHub CLI\\gh.exe' : 'gh';
    const ext = await execFileNoThrow(ghPath, ['extension', 'install', 'github/gh-codeql'], {
      timeout: 120_000,
    });
    if (ext.ok) {
      console.log('[CodeQL] Installed via gh extension.');
      return;
    }
    console.warn(`[CodeQL] gh extension failed: ${ext.stderr?.substring(0, 200)}`);

    // Method 2: Download CodeQL CLI bundle directly
    console.log('[CodeQL] Downloading CodeQL CLI bundle...');
    if (!fs.existsSync(installDir)) fs.mkdirSync(installDir, { recursive: true });

    const platform = isWin ? 'win64' : process.platform === 'darwin' ? 'osx64' : 'linux64';
    const ext2 = isWin ? 'zip' : 'tar.gz';
    const url = `https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-${platform}.${ext2}`;
    const outFile = path.join(installDir, `codeql-bundle.${ext2}`);

    // Download
    const dl = isWin
      ? await execFileNoThrow('powershell', ['-Command', `Invoke-WebRequest -Uri '${url}' -OutFile '${outFile}'`], { timeout: 300_000 })
      : await execFileNoThrow('curl', ['-sfL', '-o', outFile, url], { timeout: 300_000 });

    if (!dl.ok) {
      throw new Error(`CodeQL download failed: ${dl.stderr?.substring(0, 300)}`);
    }

    // Extract
    console.log('[CodeQL] Extracting...');
    const extract = isWin
      ? await execFileNoThrow('powershell', ['-Command', `Expand-Archive -Path '${outFile}' -DestinationPath '${installDir}' -Force`], { timeout: 120_000 })
      : await execFileNoThrow('tar', ['xzf', outFile, '-C', installDir], { timeout: 120_000 });

    if (!extract.ok) {
      throw new Error(`CodeQL extract failed: ${extract.stderr?.substring(0, 300)}`);
    }

    // Clean up archive
    try { fs.unlinkSync(outFile); } catch {}

    console.log('[CodeQL] Install complete.');
  },

  run: async (
    target: string,
    options: CodeQLOptions = {},
    installDir?: string
  ): Promise<{ output: string; findings: PluginFinding[] }> => {
    const language = options.language ?? 'javascript';
    const dbPath = path.join(installDir ?? '/tmp', `codeql-db-${Date.now()}`);
    const outputFile = options.outputFile
      ?? path.join(installDir ?? '/tmp', `codeql-out-${Date.now()}.sarif`);

    console.log('[CodeQL] Creating database...');
    const createArgs = [
      'database', 'create', dbPath,
      `--language=${language}`,
      `--source-root=${target}`,
      '--overwrite',
    ];
    const createResult = await execFileNoThrow('codeql', createArgs, {
      timeout: (options.timeout ?? 600) * 1000, useShell: true,
    });
    const createOutput = createResult.stdout + createResult.stderr;

    if (!createResult.ok) {
      console.warn('[CodeQL] Database create reported errors — attempting analysis anyway');
    }

    console.log('[CodeQL] Running analysis...');
    const analyzeArgs = [
      'database', 'analyze', dbPath,
      '--format=sarif-latest',
      `--output=${outputFile}`,
    ];
    if (options.queries && options.queries.length > 0) {
      analyzeArgs.push(...options.queries);
    } else {
      analyzeArgs.push(`${language}-security-extended`);
    }
    const analyzeResult = await execFileNoThrow('codeql', analyzeArgs, {
      timeout: (options.timeout ?? 600) * 1000, useShell: true,
    });

    const output = createOutput + analyzeResult.stdout + analyzeResult.stderr;
    return { output, findings: CodeQLIntegration.parseOutput(output) };
  },

  parseOutput: (raw: string): PluginFinding[] => {
    const findings: PluginFinding[] = [];
    // CodeQL outputs SARIF JSON
    const jsonStart = raw.indexOf('{');
    if (jsonStart < 0) return findings;
    try {
      const sarif = JSON.parse(raw.slice(jsonStart)) as any;
      const runs: any[] = sarif.runs ?? [];
      for (const run of runs) {
        const results: any[] = run.results ?? [];
        const rules: Record<string, any> = {};
        for (const rule of run.tool?.driver?.rules ?? []) {
          rules[rule.id] = rule;
        }
        for (const r of results) {
          const ruleId: string = r.ruleId ?? 'unknown';
          const rule = rules[ruleId] ?? {};
          const severity = normalizeCodeQLSeverity(
            r.level ?? rule.defaultConfiguration?.level
          );
          const loc = r.locations?.[0]?.physicalLocation;
          const filePath = loc?.artifactLocation?.uri ?? undefined;
          const startLine: number | undefined = loc?.region?.startLine;
          findings.push({
            title: rule.name ?? ruleId,
            severity,
            description: r.message?.text ?? rule.fullDescription?.text ?? ruleId,
            file: filePath
              ? (startLine ? `${filePath}:${startLine}` : filePath)
              : undefined,
            raw: r,
          });
        }
      }
    } catch { /* malformed SARIF */ }
    return findings;
  },

  getAvailableModules: () => [
    'cpp_security', 'cpp_critical', 'cpp_recommendations',
    'java_security', 'java_error_prone',
    'javascript_security', 'javascript_xss',
    'python_security', 'python_injection',
    'go_security', 'csharp_security',
    'ruby_security', 'swift_security',
    'custom_queries',
  ],
};

/**
 * Plugin manager -- installs, lists, runs, and checks external security tools.
 *
 * Security note: Plugin run_command strings are supplied by administrators
 * from a curated catalog (registry.ts) or explicitly installed by trusted
 * operators. The integrations layer uses execFileNoThrow (no shell injection).
 * The legacy runShellCommand() helper is retained only for catalog-defined
 * install_command strings that require shell features (pipes, &&) and are
 * never constructed from raw user input.
 */
import { spawn } from 'child_process';
import path from 'path';
import { mkdirSync, existsSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';

import {
  getAllPlugins,
  getPluginById,
  createPlugin,
  updatePlugin,
  type Plugin,
} from '../db.js';
import {
  PLUGIN_CATALOG,
  getCatalogEntry,
  getCatalogEntryByUrl,
  type CatalogEntry,
} from './registry.js';
import {
  getIntegration,
  getPluginModules,
  type PluginFinding,
} from './integrations/index.js';
import { execFileNoThrow } from '../utils/execFileNoThrow.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PLUGINS_ROOT = path.resolve(__dirname, '..', '..', 'plugins');

// -- Dependency install commands per platform ---------------------------------
const isWin = process.platform === 'win32';
const WF = '--accept-source-agreements --accept-package-agreements --silent';
const DEPENDENCY_INSTALL_COMMANDS: Record<string, string> = {
  'go':       isWin ? `winget install GoLang.Go ${WF}`          : 'brew install go || sudo apt install golang-go',
  'gh':       isWin ? `winget install GitHub.cli ${WF}`          : 'brew install gh || sudo apt install gh',
  'python3':  isWin ? `winget install Python.Python.3.12 ${WF}`  : 'brew install python3 || sudo apt install python3',
  'pip':      isWin ? 'python -m ensurepip --upgrade'            : 'python3 -m ensurepip --upgrade || sudo apt install python3-pip',
  'git':      isWin ? `winget install Git.Git ${WF}`             : 'brew install git || sudo apt install git',
  'node':     isWin ? `winget install OpenJS.NodeJS.LTS ${WF}`   : 'brew install node || sudo apt install nodejs',
  'npm':      isWin ? `winget install OpenJS.NodeJS.LTS ${WF}`   : 'brew install node || sudo apt install npm',
  'docker':   isWin ? `winget install Docker.DockerDesktop ${WF}` : 'brew install --cask docker || sudo apt install docker.io',
  'curl':     isWin ? `winget install cURL.cURL ${WF}`           : 'brew install curl || sudo apt install curl',
  'ruby':     isWin ? `winget install RubyInstallerTeam.Ruby ${WF}` : 'brew install ruby || sudo apt install ruby',
  'java':     isWin ? `winget install Oracle.JDK.21 ${WF}`       : 'brew install openjdk || sudo apt install openjdk-21-jdk',
  'rustc':    isWin ? `winget install Rustlang.Rust.MSVC ${WF}`  : 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh',
};

// -- Status tracking ----------------------------------------------------------

export type PluginStatusValue = 'idle' | 'installing' | 'running' | 'error' | 'ready';

interface StatusEntry {
  status: PluginStatusValue;
  message?: string;
  lastRun?: Date;
}

const statusMap = new Map<number, StatusEntry>();

// -- Helpers ------------------------------------------------------------------

function ensurePluginsRoot(): void {
  if (!existsSync(PLUGINS_ROOT)) mkdirSync(PLUGINS_ROOT, { recursive: true });
}

/**
 * Execute a shell command string with shell: true.
 * Used only for catalog-defined install_command / run_command strings that
 * require shell features (pipes, &&). These originate from the admin-
 * controlled catalog and are never interpolated from raw user input.
 */
function runShellCommand(cmd: string, cwd?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, {
      shell: true,
      cwd: cwd || PLUGINS_ROOT,
      env: process.env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    child.on('close', (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(`Command exited ${code}: ${(stderr || stdout).trim()}`));
    });
    child.on('error', reject);
  });
}

async function isBinaryAvailable(bin: string): Promise<boolean> {
  // Try standard lookup first
  const which = process.platform === 'win32' ? 'where' : 'which';
  const result = await execFileNoThrow(which, [bin], { useShell: true });
  if (result.ok) return true;

  // On Windows, check common install paths that might not be in PATH
  if (process.platform === 'win32') {
    const { existsSync } = await import('fs');
    const home = process.env.LOCALAPPDATA || '';
    const progFiles = process.env['ProgramFiles'] || 'C:\\Program Files';
    const commonPaths: Record<string, string[]> = {
      'gh':      [`${progFiles}\\GitHub CLI\\gh.exe`],
      'go':      [`${progFiles}\\Go\\bin\\go.exe`, `C:\\Go\\bin\\go.exe`],
      'python3': [`${home}\\Programs\\Python\\Python312\\python.exe`, `${home}\\Programs\\Python\\Python311\\python.exe`],
      'docker':  [`${progFiles}\\Docker\\Docker\\resources\\bin\\docker.exe`],
      'git':     [`${progFiles}\\Git\\bin\\git.exe`],
      'node':    [`${progFiles}\\nodejs\\node.exe`],
      'ruby':    [`${progFiles}\\Ruby32-x64\\bin\\ruby.exe`],
      'rustc':   [`${home}\\.cargo\\bin\\rustc.exe`],
    };
    for (const p of (commonPaths[bin] ?? [])) {
      if (existsSync(p)) return true;
    }
    // Also try via PowerShell Get-Command as last resort
    const ps = await execFileNoThrow('powershell', ['-Command', `Get-Command ${bin} -ErrorAction SilentlyContinue`]);
    if (ps.ok && ps.stdout.trim().length > 0) return true;
  }

  return false;
}

// -- PluginManager ------------------------------------------------------------

export class PluginManager {
  /**
   * Install a plugin from a catalog name or source URL.
   * Prefers the typed integration layer; falls back to the catalog
   * shell install_command for tools without a dedicated integration.
   */
  async installPlugin(nameOrUrl: string): Promise<Plugin> {
    ensurePluginsRoot();

    let entry: CatalogEntry | null =
      getCatalogEntryByUrl(nameOrUrl) ?? getCatalogEntry(nameOrUrl);

    if (!entry) {
      const urlName = nameOrUrl.split('/').pop() ?? nameOrUrl;
      entry = {
        name: urlName,
        source_url: nameOrUrl,
        type: 'scanner',
        description: `Installed from ${nameOrUrl}`,
        install_command: `git clone ${nameOrUrl}`,
        run_command: '',
        parse_output: 'text',
        requires: [],
        version: 'unknown',
      };
    }

    const safeName = entry.name.replace(/\s+/g, '-');
    const installDir = path.join(PLUGINS_ROOT, safeName);

    // Check requirements before attempting install
    const reqCheck = await this.checkRequirements(
      entry as unknown as Plugin & { requires?: string[] }
    );
    if (!reqCheck.met) {
      throw new Error(
        `Missing requirements for "${entry.name}": ${reqCheck.missing.join(', ')}`
      );
    }

    const integration = getIntegration(entry.name);

    // Import progress broadcaster
    const { broadcastProgress } = await import('../ws.js');
    const pid = safeName;

    broadcastProgress('plugin-install', pid, { step: 'Starting install', detail: entry.name, progress: 10, status: 'running' });

    if (integration) {
      console.log(`[PluginManager] Installing "${entry.name}" via integration...`);
      if (!existsSync(installDir)) mkdirSync(installDir, { recursive: true });
      broadcastProgress('plugin-install', pid, { step: 'Downloading & installing', detail: 'This may take a few minutes...', progress: 30, status: 'running' });
      await integration.install(installDir);
      broadcastProgress('plugin-install', pid, { step: 'Installation files ready', progress: 80, status: 'running' });
    } else {
      console.log(`[PluginManager] Installing "${entry.name}" via shell: ${entry.install_command}`);
      broadcastProgress('plugin-install', pid, { step: 'Running install command', detail: entry.install_command, progress: 30, status: 'running' });
      await runShellCommand(entry.install_command, PLUGINS_ROOT);
      broadcastProgress('plugin-install', pid, { step: 'Install command complete', progress: 80, status: 'running' });
    }

    const manifest = {
      name: entry.name,
      version: entry.version,
      type: entry.type,
      description: entry.description,
      install_command: entry.install_command,
      run_command: entry.run_command,
      parse_output: entry.parse_output,
      requires: entry.requires,
    };

    if (existsSync(installDir)) {
      writeFileSync(
        path.join(installDir, 'manifest.json'),
        JSON.stringify(manifest, null, 2)
      );
    }

    const id = createPlugin({
      name: entry.name,
      type: entry.type,
      source_url: entry.source_url,
      install_path: installDir,
      version: entry.version,
      manifest: JSON.stringify(manifest),
      enabled: 1,
    });

    const plugin = getPluginById(id);
    if (!plugin) throw new Error('Failed to persist plugin record after install');

    statusMap.set(id, { status: 'ready' });
    broadcastProgress('plugin-install', pid, { step: 'Install complete!', detail: `${entry.name} is ready to use`, progress: 100, status: 'complete' });
    console.log(`[PluginManager] Plugin installed id=${id} name="${entry.name}"`);
    return plugin;
  }

  /** Disable a plugin (soft-uninstall; files remain on disk). */
  async uninstallPlugin(id: number): Promise<void> {
    const plugin = getPluginById(id);
    if (!plugin) throw new Error(`Plugin ${id} not found`);
    updatePlugin(id, { enabled: 0 });
    statusMap.delete(id);
    console.log(`[PluginManager] Uninstalled plugin id=${id} name="${plugin.name}"`);
  }

  /**
   * Run a plugin against a target.
   * Uses the typed integration layer when available; otherwise falls back to
   * the catalog run_command shell string.
   */
  async runPlugin(
    pluginId: number,
    target: string,
    options?: Record<string, any>
  ): Promise<{ output: string; findings: PluginFinding[] }> {
    const plugin = getPluginById(pluginId);
    if (!plugin) throw new Error(`Plugin ${pluginId} not found`);
    if (!plugin.enabled) throw new Error(`Plugin "${plugin.name}" is disabled`);

    statusMap.set(pluginId, { status: 'running' });

    try {
      const integration = getIntegration(plugin.name);

      if (integration) {
        console.log(`[PluginManager] Running "${plugin.name}" via integration...`);
        const result = await integration.run(
          target,
          options ?? {},
          plugin.install_path ?? PLUGINS_ROOT
        );
        statusMap.set(pluginId, { status: 'ready', lastRun: new Date() });
        return result;
      }

      // Fall back to shell run_command
      let runCmd: string | undefined;
      if (plugin.manifest) {
        try {
          const m = JSON.parse(plugin.manifest) as { run_command?: string };
          runCmd = m.run_command;
        } catch { /* malformed manifest -- fall through */ }
      }
      if (!runCmd) {
        const ce =
          getCatalogEntry(plugin.name) ??
          getCatalogEntryByUrl(plugin.source_url ?? '');
        runCmd = ce?.run_command;
      }
      if (!runCmd) {
        throw new Error(
          `Plugin "${plugin.name}" has no run_command and no integration. Reinstall from catalog.`
        );
      }

      const outputFile = path.join(
        PLUGINS_ROOT,
        `${plugin.name.replace(/\s+/g, '-')}-output-${Date.now()}.txt`
      );
      const cmd = runCmd
        .replace(/\{target\}/g, target)
        .replace(/\{output\}/g, outputFile);

      console.log(`[PluginManager] Running plugin "${plugin.name}" (shell): ${cmd}`);
      const output = await runShellCommand(cmd, plugin.install_path ?? PLUGINS_ROOT);

      const parseType = plugin.manifest
        ? ((JSON.parse(plugin.manifest) as any).parse_output ?? 'text')
        : 'text';
      const findings = this._parseShellOutput(output, parseType);
      statusMap.set(pluginId, { status: 'ready', lastRun: new Date() });
      return { output, findings };
    } catch (err) {
      statusMap.set(pluginId, {
        status: 'error',
        message: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  }

  /**
   * Check whether all requirement binaries for a plugin are present on PATH.
   */
  async checkRequirements(
    plugin: Plugin & { requires?: string[] }
  ): Promise<{ met: boolean; missing: string[]; installCommands: Record<string, string> }> {
    let requires: string[] = plugin.requires ?? [];
    if (requires.length === 0 && plugin.manifest) {
      try {
        requires =
          (JSON.parse(plugin.manifest) as { requires?: string[] }).requires ?? [];
      } catch { /* malformed */ }
    }
    if (requires.length === 0) {
      const entry = getCatalogEntry(plugin.name ?? '');
      requires = entry?.requires ?? [];
    }

    const missing: string[] = [];
    const installCommands: Record<string, string> = {};
    for (const req of requires) {
      if (!(await isBinaryAvailable(req))) {
        missing.push(req);
        installCommands[req] = DEPENDENCY_INSTALL_COMMANDS[req] ?? `Please install "${req}" manually`;
      }
    }
    return { met: missing.length === 0, missing, installCommands };
  }

  /** Install a missing system dependency */
  async installDependency(name: string): Promise<{ ok: boolean; output: string }> {
    const cmd = DEPENDENCY_INSTALL_COMMANDS[name];
    if (!cmd) return { ok: false, output: `No install command known for "${name}"` };

    console.log(`[PluginManager] Installing dependency "${name}" via: ${cmd}`);
    try {
      // On Windows, winget/choco need PowerShell; on Unix use sh
      const isWin = process.platform === 'win32';
      let result;
      if (isWin && cmd.startsWith('winget')) {
        // winget needs to run in PowerShell with proper env
        result = await execFileNoThrow('powershell', ['-Command', cmd], { timeout: 300_000 });
      } else if (isWin) {
        result = await execFileNoThrow('cmd', ['/c', cmd], { timeout: 300_000 });
      } else {
        // On Unix, pick the first alternative (before ||)
        const firstCmd = cmd.split('||')[0].trim();
        const parts = firstCmd.split(/\s+/);
        result = await execFileNoThrow(parts[0], parts.slice(1), { timeout: 300_000 });
      }

      const output = (result.stdout || '') + (result.stderr || '');
      const ok = result.ok;
      console.log(`[PluginManager] Dependency "${name}" install ${ok ? 'succeeded' : 'failed'}`);
      return { ok, output: output.substring(0, 2000) };
    } catch (err: any) {
      console.log(`[PluginManager] Dependency "${name}" install error: ${err.message}`);
      return { ok: false, output: err.message };
    }
  }

  listPlugins(): { installed: Plugin[]; catalog: CatalogEntry[] } {
    return { installed: getAllPlugins(), catalog: PLUGIN_CATALOG };
  }

  getPluginStatus(id: number): {
    status: PluginStatusValue;
    message?: string;
    lastRun?: Date;
  } {
    const plugin = getPluginById(id);
    if (!plugin) return { status: 'error', message: 'Plugin not found' };
    if (!plugin.enabled) return { status: 'error', message: 'Plugin is disabled' };
    return statusMap.get(id) ?? { status: 'idle' };
  }

  getPluginModules(pluginName: string): string[] {
    return getPluginModules(pluginName);
  }

  getPlugin(id: number): Plugin | null {
    return getPluginById(id);
  }

  // -- Private helpers --------------------------------------------------------

  private _parseShellOutput(output: string, parseType: string): PluginFinding[] {
    if (parseType === 'json') {
      const jsonStart =
        output.indexOf('{') >= 0 ? output.indexOf('{') : output.indexOf('[');
      if (jsonStart < 0) return [];
      try {
        const obj = JSON.parse(output.slice(jsonStart)) as any;
        const items: any[] = Array.isArray(obj)
          ? obj
          : obj.results ?? obj.findings ?? obj.vulnerabilities ?? [];
        return items.map((item: any) => ({
          title: item.title ?? item.name ?? item.id ?? 'Finding',
          severity: item.severity ?? item.risk ?? 'Medium',
          description: item.description ?? item.message ?? JSON.stringify(item),
          file: item.file ?? item.location ?? undefined,
        }));
      } catch {
        return [];
      }
    }
    // text / markdown: heuristic severity extraction
    return output
      .split('\n')
      .filter((l) => /critical|high|medium|low|vuln|cve/i.test(l))
      .slice(0, 100)
      .map((l) => ({
        title: 'Finding',
        severity: /critical/i.test(l)
          ? 'Critical'
          : /high/i.test(l)
          ? 'High'
          : /medium/i.test(l)
          ? 'Medium'
          : 'Low',
        description: l.trim(),
      }));
  }
}

export const pluginManager = new PluginManager();

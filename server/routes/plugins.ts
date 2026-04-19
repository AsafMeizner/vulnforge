import { Router, Request, Response, NextFunction } from 'express';
import { pluginManager } from '../plugins/manager.js';
import { PLUGIN_CATALOG } from '../plugins/registry.js';
import { createVulnerability } from '../db.js';

const router = Router();

// -- GET /api/plugins ---------------------------------------------------------
// Returns installed plugins merged with the static catalog.

router.get('/', (_req: Request, res: Response, next: NextFunction) => {
  try {
    const { installed, catalog } = pluginManager.listPlugins();
    const installedNames = new Set(
      installed.map((p) => p.name.toLowerCase()).filter(Boolean)
    );
    const catalogWithStatus = catalog.map((entry) => ({
      ...entry,
      installed: installedNames.has(entry.name.toLowerCase()),
    }));
    res.json({
      data: { installed, catalog: catalogWithStatus },
      total_installed: installed.length,
      total_catalog: catalog.length,
    });
  } catch (err: any) {
    console.error('[GET /plugins] error:', err);
    next(err);
  }
});

// -- GET /api/plugins/catalog/all ---------------------------------------------

router.get('/catalog/all', (_req: Request, res: Response, next: NextFunction) => {
  res.json({ data: PLUGIN_CATALOG, total: PLUGIN_CATALOG.length });
});

// -- GET /api/plugins/:id -----------------------------------------------------

router.get('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid plugin ID' }); return; }
    const plugin = pluginManager.getPlugin(id);
    if (!plugin) { res.status(404).json({ error: `Plugin ${id} not found` }); return; }
    res.json(plugin);
  } catch (err: any) {
    next(err);
  }
});

// -- GET /api/plugins/:id/status ----------------------------------------------
// Returns live status (idle/installing/running/error/ready) + requirements check.

router.get('/:id/status', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid plugin ID' }); return; }
    const plugin = pluginManager.getPlugin(id);
    if (!plugin) { res.status(404).json({ error: `Plugin ${id} not found` }); return; }

    const [runtimeStatus, reqCheck] = await Promise.all([
      pluginManager.getPluginStatus(id),
      pluginManager.checkRequirements(plugin),
    ]);

    res.json({
      ...runtimeStatus,
      requirements: reqCheck,
      plugin: { id: plugin.id, name: plugin.name, version: plugin.version },
    });
  } catch (err: any) {
    next(err);
  }
});

// -- GET /api/plugins/:id/modules ---------------------------------------------
// Returns available modules/probes/templates for the plugin.

router.get('/:id/modules', (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid plugin ID' }); return; }
    const plugin = pluginManager.getPlugin(id);
    if (!plugin) { res.status(404).json({ error: `Plugin ${id} not found` }); return; }

    const modules = pluginManager.getPluginModules(plugin.name);
    res.json({ plugin: plugin.name, modules, total: modules.length });
  } catch (err: any) {
    next(err);
  }
});

// -- POST /api/plugins/install ------------------------------------------------
// Body: { name?: string; source_url?: string; catalog_name?: string }

router.post('/install', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name, source_url, catalog_name } = req.body as {
      name?: string;
      source_url?: string;
      catalog_name?: string;
    };

    const identifier = name ?? source_url ?? catalog_name;
    if (!identifier) {
      res.status(400).json({ error: 'name, source_url, or catalog_name is required' });
      return;
    }

    const plugin = await pluginManager.installPlugin(identifier);
    res.status(201).json(plugin);
  } catch (err: any) {
    console.error('[POST /plugins/install] error:', err);
    // Check if it's a missing requirements error and include install commands
    const missingMatch = err.message?.match(/Missing requirements for "(.+?)": (.+)/);
    if (missingMatch) {
      const missing = missingMatch[2].split(', ').map((s: string) => s.trim());
      const isWin = process.platform === 'win32';
      const installCommands: Record<string, string> = {};
      const CMDS: Record<string, string> = {
        'go':      isWin ? 'winget install GoLang.Go' : 'brew install go || sudo apt install golang-go',
        'gh':      isWin ? 'winget install GitHub.cli' : 'brew install gh || sudo apt install gh',
        'python3': isWin ? 'winget install Python.Python.3.12' : 'brew install python3',
        'pip':     isWin ? 'python -m ensurepip --upgrade' : 'python3 -m ensurepip --upgrade',
        'git':     isWin ? 'winget install Git.Git' : 'brew install git',
        'docker':  isWin ? 'winget install Docker.DockerDesktop' : 'brew install --cask docker',
      };
      for (const m of missing) installCommands[m] = CMDS[m] ?? `Install "${m}" manually`;
      res.status(422).json({
        error: err.message,
        missingDeps: missing,
        installCommands,
      });
    } else {
      next(err);
    }
  }
});

// -- POST /api/plugins/install-from-url ---------------------------------------
// Register an external plugin from a user-supplied git URL.
//
// Request: { url: string; name?: string; description?: string; type?: string }
//
// Validation:
//   - URL must start with https:// or git@
//   - Forbid path traversal characters in URL
//
// Note: this endpoint records the plugin in the catalog + installed lists
// with a "pending" flag. A follow-up "enable" click triggers the actual
// clone + any install steps the manifest specifies. Keeping the two
// phases apart means a malformed URL fails fast without any filesystem
// state change.

router.post('/install-from-url', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { url, name, description, type } = req.body as {
      url?: string;
      name?: string;
      description?: string;
      type?: string;
    };
    if (!url || typeof url !== 'string') {
      res.status(400).json({ error: 'url is required' });
      return;
    }
    const safe = /^(https?:\/\/|git@)[^\s]+$/.test(url) && !/\.\./.test(url);
    if (!safe) {
      res.status(400).json({ error: 'url must be http(s):// or git@ and must not contain ".."' });
      return;
    }
    // Derive a name from the URL if the user didn't supply one
    const derivedName =
      name ||
      url.replace(/\.git$/, '').replace(/\/$/, '').split('/').slice(-1)[0] ||
      'custom-plugin';
    const { createPlugin } = await import('../db.js');
    const id = createPlugin({
      name: derivedName,
      type: (type as any) || 'scanner',
      source_url: url,
      version: 'latest',
      manifest: JSON.stringify({
        name: derivedName,
        source_url: url,
        description: description || `Custom plugin from ${url}`,
        install_command: `git clone ${url}`,
        run_command: '',
        parse_output: 'text',
        requires: ['git'],
        type: (type as any) || 'scanner',
        category: 'Custom',
        stars: '—',
        long_description: description || `User-added plugin from ${url}.`,
        version: 'latest',
        website_url: url,
      }),
      enabled: 0,
    } as any);
    res.status(201).json({
      success: true,
      id,
      name: derivedName,
      message: 'Plugin registered. Click Install to clone and enable.',
    });
  } catch (err: any) {
    console.error('[POST /plugins/install-from-url] error:', err);
    next(err);
  }
});

// -- POST /api/plugins/install-dep --------------------------------------------
// Install a missing system dependency (go, gh, etc.)

router.post('/install-dep', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { dependency } = req.body as { dependency?: string };
    if (!dependency) { res.status(400).json({ error: 'dependency name is required' }); return; }
    const result = await pluginManager.installDependency(dependency);
    res.json(result);
  } catch (err: any) {
    next(err);
  }
});

// -- PUT /api/plugins/:id -----------------------------------------------------
// Patch a plugin row. Primarily used by the Enable/Disable toggle.
// Accepts any subset of { enabled, name, manifest }.
router.put('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid plugin ID' }); return; }
    const existing = pluginManager.getPlugin(id);
    if (!existing) { res.status(404).json({ error: `Plugin ${id} not found` }); return; }

    const body = (req.body || {}) as Partial<{
      enabled: boolean | number;
      name: string;
      manifest: string | Record<string, unknown>;
    }>;
    const updates: Record<string, unknown> = {};
    if ('enabled' in body) {
      // Store as 0/1 since SQLite INTEGER columns prefer numbers to booleans.
      updates.enabled = body.enabled ? 1 : 0;
    }
    if (typeof body.name === 'string' && body.name.trim()) updates.name = body.name.trim();
    if (body.manifest !== undefined) {
      updates.manifest = typeof body.manifest === 'string' ? body.manifest : JSON.stringify(body.manifest);
    }
    if (Object.keys(updates).length === 0) {
      res.status(400).json({ error: 'No updatable fields provided' }); return;
    }
    const { updatePlugin } = await import('../db.js');
    updatePlugin(id, updates as any);
    res.json(pluginManager.getPlugin(id));
  } catch (err: any) {
    console.error('PUT /plugins/:id error:', err);
    next(err);
  }
});

// -- DELETE /api/plugins/:id --------------------------------------------------

router.delete('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid plugin ID' }); return; }
    if (!pluginManager.getPlugin(id)) {
      res.status(404).json({ error: `Plugin ${id} not found` });
      return;
    }
    await pluginManager.uninstallPlugin(id);
    res.status(204).send();
  } catch (err: any) {
    next(err);
  }
});

// -- POST /api/plugins/:id/run ------------------------------------------------
// Body: { target: string; options?: Record<string, any>; project_id?: number }
//
// Runs the plugin and persists each finding as a vulnerability record.

router.post('/:id/run', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid plugin ID' }); return; }

    const { target, options, project_id } = req.body as {
      target?: string;
      options?: Record<string, any>;
      project_id?: number;
    };
    if (!target) { res.status(400).json({ error: 'target is required' }); return; }

    const plugin = pluginManager.getPlugin(id);
    if (!plugin) { res.status(404).json({ error: `Plugin ${id} not found` }); return; }

    // Acknowledge immediately; run asynchronously
    res.status(202).json({
      message: `Plugin "${plugin.name}" started against "${target}"`,
      pluginId: id,
      target,
    });

    setImmediate(async () => {
      try {
        const { output, findings } = await pluginManager.runPlugin(id, target, options);
        console.log(
          `[PluginRun] id=${id} completed. output=${output.length}b findings=${findings.length}`
        );

        // Persist findings as vulnerability records
        for (const finding of findings) {
          try {
            createVulnerability({
              project_id: project_id ?? undefined,
              title: finding.title,
              severity: finding.severity,
              description: finding.description,
              file: finding.file ?? undefined,
              code_snippet: finding.code_snippet ?? undefined,
              tool_name: plugin.name,
              method: 'plugin',
              status: 'Open',
            });
          } catch (insertErr) {
            console.error('[PluginRun] Failed to insert finding:', insertErr);
          }
        }
      } catch (runErr: any) {
        console.error(`[PluginRun] id=${id} failed:`, runErr.message);
      }
    });
  } catch (err: any) {
    console.error(`[POST /plugins/${req.params.id}/run] error:`, err);
    next(err);
  }
});

export default router;

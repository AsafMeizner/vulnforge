import {
  getAllVulnerabilities,
  getVulnerabilityById,
  createVulnerability,
  updateVulnerability,
  getAllProjects,
  createProject,
  updateProject,
  getScanById,
  getAllChecklists,
  getChecklistById,
  getChecklistItems,
  getScanFindings,
  getScanFindingById,
  updateScanFinding,
  countScanFindings,
  getPipelineRun,
  getActivePipelineRuns,
  getPipelineRuns,
  getStats,
} from '../db.js';
import { streamTool } from '../scanner/runner.js';
import { triageFinding } from '../ai/router.js';
import { pluginManager } from '../plugins/manager.js';
import { PLUGIN_CATALOG } from '../plugins/registry.js';
import { verifyFullChecklist } from '../checklists/verifier.js';

// ── Tool definitions for MCP server ───────────────────────────────────────

export interface MCPToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
  handler: (args: any) => Promise<any>;
}

export const mcpTools: MCPToolDef[] = [
  // ── list_vulnerabilities ────────────────────────────────────────────────
  {
    name: 'list_vulnerabilities',
    description: 'List vulnerabilities with optional filters by severity, status, project, or search term',
    inputSchema: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['Critical', 'High', 'Medium', 'Low'], description: 'Filter by severity' },
        status: { type: 'string', description: 'Filter by status (Open, Submitted, Fixed, etc.)' },
        project_id: { type: 'number', description: 'Filter by project ID' },
        search: { type: 'string', description: 'Search in title, description, file' },
        limit: { type: 'number', description: 'Max results (default 50)' },
        offset: { type: 'number', description: 'Pagination offset' },
      },
    },
    handler: async (args: any) => {
      const vulns = getAllVulnerabilities({
        severity: args.severity,
        status: args.status,
        project_id: args.project_id,
        search: args.search,
        limit: args.limit || 50,
        offset: args.offset || 0,
      });
      return { vulnerabilities: vulns, total: vulns.length };
    },
  },

  // ── get_vulnerability ───────────────────────────────────────────────────
  {
    name: 'get_vulnerability',
    description: 'Get full details of a specific vulnerability by ID',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Vulnerability ID' },
      },
      required: ['id'],
    },
    handler: async (args: any) => {
      const vuln = getVulnerabilityById(Number(args.id));
      if (!vuln) throw new Error(`Vulnerability ${args.id} not found`);
      return vuln;
    },
  },

  // ── create_vulnerability ────────────────────────────────────────────────
  {
    name: 'create_vulnerability',
    description: 'Create a new vulnerability record',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string', description: 'Vulnerability title' },
        project_id: { type: 'number', description: 'Associated project ID' },
        severity: { type: 'string', enum: ['Critical', 'High', 'Medium', 'Low'] },
        status: { type: 'string', description: 'Status (Open, Submitted, Fixed, etc.)' },
        cvss: { type: 'string', description: 'CVSS score' },
        cvss_vector: { type: 'string', description: 'CVSS vector string' },
        cwe: { type: 'string', description: 'CWE identifier' },
        file: { type: 'string', description: 'Affected file path' },
        description: { type: 'string', description: 'Vulnerability description' },
        method: { type: 'string', description: 'Discovery method' },
      },
      required: ['title'],
    },
    handler: async (args: any) => {
      const id = createVulnerability(args);
      return getVulnerabilityById(id);
    },
  },

  // ── update_vulnerability ────────────────────────────────────────────────
  {
    name: 'update_vulnerability',
    description: 'Update fields on an existing vulnerability',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Vulnerability ID to update' },
        title: { type: 'string' },
        severity: { type: 'string' },
        status: { type: 'string' },
        cvss: { type: 'string' },
        description: { type: 'string' },
        suggested_fix: { type: 'string' },
        ai_triage: { type: 'string' },
        ai_summary: { type: 'string' },
        verified: { type: 'number', enum: [0, 1] },
        false_positive: { type: 'number', enum: [0, 1] },
        response: { type: 'string' },
        rejection_reason: { type: 'string' },
      },
      required: ['id'],
    },
    handler: async (args: any) => {
      const { id, ...fields } = args;
      const existing = getVulnerabilityById(Number(id));
      if (!existing) throw new Error(`Vulnerability ${id} not found`);
      updateVulnerability(Number(id), fields);
      return getVulnerabilityById(Number(id));
    },
  },

  // ── list_projects ───────────────────────────────────────────────────────
  {
    name: 'list_projects',
    description: 'List all imported projects',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    handler: async () => {
      const projects = getAllProjects();
      return { projects, total: projects.length };
    },
  },

  // ── import_project ──────────────────────────────────────────────────────
  {
    name: 'import_project',
    description: 'Import a project by filesystem path',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the project directory' },
        name: { type: 'string', description: 'Optional project name (auto-detected from path if omitted)' },
        repo_url: { type: 'string', description: 'Optional repository URL' },
        language: { type: 'string', description: 'Primary language (auto-detected if omitted)' },
      },
      required: ['path'],
    },
    handler: async (args: any) => {
      const { default: pathLib } = await import('path');
      const name = args.name || pathLib.basename(args.path);
      const id = createProject({
        name,
        path: args.path,
        repo_url: args.repo_url || null,
        language: args.language || null,
      });
      return { id, name, path: args.path };
    },
  },

  // ── run_tool ────────────────────────────────────────────────────────────
  {
    name: 'run_tool',
    description: 'Execute a security analysis tool on a project and return findings',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: { type: 'string', description: 'Tool name (without .py extension)' },
        project_id: { type: 'number', description: 'Project ID to scan' },
        target_path: { type: 'string', description: 'Override target path (uses project path if omitted)' },
        language: { type: 'string', description: 'Language hint for the tool' },
      },
      required: ['tool_name', 'project_id'],
    },
    handler: async (args: any) => {
      const { getAllProjects: getProjs } = await import('../db.js');
      const projects = getProjs();
      const project = projects.find(p => p.id === Number(args.project_id));
      if (!project) throw new Error(`Project ${args.project_id} not found`);

      const targetPath = args.target_path || project.path;
      if (!targetPath) throw new Error('No target path available');

      return new Promise((resolve, reject) => {
        const outputLines: string[] = [];
        const runner = streamTool(args.tool_name, targetPath, {
          language: args.language,
        });

        runner.on('output', (line: string) => outputLines.push(line));

        runner.on('complete', (output: string, exitCode: number) => {
          resolve({
            output: output || outputLines.join('\n'),
            exitCode,
            toolName: args.tool_name,
            targetPath,
          });
        });

        runner.on('error', (err: Error) => reject(err));
      });
    },
  },

  // ── get_scan_status ─────────────────────────────────────────────────────
  {
    name: 'get_scan_status',
    description: 'Get the current status and output of a scan by ID',
    inputSchema: {
      type: 'object',
      properties: {
        scan_id: { type: 'number', description: 'Scan ID' },
      },
      required: ['scan_id'],
    },
    handler: async (args: any) => {
      const scan = getScanById(Number(args.scan_id));
      if (!scan) throw new Error(`Scan ${args.scan_id} not found`);
      return scan;
    },
  },

  // ── triage_finding ──────────────────────────────────────────────────────
  {
    name: 'triage_finding',
    description: 'Send a vulnerability to the AI for triage analysis and severity assessment',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Vulnerability ID to triage' },
        save_result: { type: 'boolean', description: 'Save the triage result to the vulnerability record (default: true)' },
      },
      required: ['id'],
    },
    handler: async (args: any) => {
      const vuln = getVulnerabilityById(Number(args.id));
      if (!vuln) throw new Error(`Vulnerability ${args.id} not found`);

      const triageResult = await triageFinding(vuln as Record<string, any>);

      const saveResult = args.save_result !== false;
      if (saveResult) {
        updateVulnerability(Number(args.id), { ai_triage: triageResult });
      }

      return { id: args.id, triage: triageResult, saved: saveResult };
    },
  },

  // -- install_plugin ----------------------------------------------------------
  {
    name: 'install_plugin',
    description: 'Install an external security tool plugin from the catalog (by name) or from a Git URL',
    inputSchema: {
      type: 'object',
      properties: {
        source: {
          type: 'string',
          description: 'Catalog name (e.g. "Nuclei") or Git URL (e.g. "https://github.com/projectdiscovery/nuclei")',
        },
      },
      required: ['source'],
    },
    handler: async (args: any) => {
      const plugin = await pluginManager.installPlugin(String(args.source));
      return plugin;
    },
  },

  // -- list_plugins ------------------------------------------------------------
  {
    name: 'list_plugins',
    description: 'List all installed plugins and the full plugin catalog with installation status',
    inputSchema: {
      type: 'object',
      properties: {
        installed_only: {
          type: 'boolean',
          description: 'If true, return only installed plugins (default: false)',
        },
      },
    },
    handler: async (args: any) => {
      const { installed, catalog } = pluginManager.listPlugins();
      if (args.installed_only) {
        return { plugins: installed, total: installed.length };
      }
      const installedNames = new Set(installed.map((p: any) => p.name?.toLowerCase()).filter(Boolean));
      const catalogWithStatus = catalog.map(entry => ({
        ...entry,
        installed: installedNames.has(entry.name.toLowerCase()),
      }));
      return {
        installed,
        catalog: catalogWithStatus,
        total_installed: installed.length,
        total_catalog: catalog.length,
      };
    },
  },

  // -- run_plugin --------------------------------------------------------------
  {
    name: 'run_plugin',
    description: 'Execute an installed plugin against a target path or URL and return parsed findings',
    inputSchema: {
      type: 'object',
      properties: {
        plugin_id: { type: 'number', description: 'ID of the installed plugin' },
        plugin_name: {
          type: 'string',
          description: 'Plugin name to look up by name (alternative to plugin_id)',
        },
        target: {
          type: 'string',
          description: 'Target to scan -- filesystem path, URL, or hostname',
        },
        options: {
          type: 'object',
          description: 'Plugin-specific options (modules, severity, templates, etc.)',
        },
      },
      required: ['target'],
    },
    handler: async (args: any) => {
      let pluginId: number | undefined = args.plugin_id ? Number(args.plugin_id) : undefined;

      // Resolve by name if id not provided
      if (!pluginId && args.plugin_name) {
        const { installed } = pluginManager.listPlugins();
        const match = installed.find(
          (p: any) => p.name?.toLowerCase() === String(args.plugin_name).toLowerCase()
        );
        if (!match || !match.id) throw new Error(`Plugin "${args.plugin_name}" is not installed`);
        pluginId = match.id as number;
      }

      if (!pluginId) throw new Error('plugin_id or plugin_name is required');

      const { output, findings } = await pluginManager.runPlugin(
        pluginId,
        String(args.target),
        args.options
      );
      return {
        plugin_id: pluginId,
        target: args.target,
        findings_count: findings.length,
        findings: findings.slice(0, 50), // cap to keep MCP response manageable
        output_preview: output.substring(0, 2000),
      };
    },
  },

  // -- list_plugin_modules -----------------------------------------------------
  {
    name: 'list_plugin_modules',
    description: 'Return the available scan modules, probes, or templates for a plugin',
    inputSchema: {
      type: 'object',
      properties: {
        plugin_name: {
          type: 'string',
          description: 'Plugin catalog name (e.g. "Nuclei", "Semgrep", "OWASP Nettacker")',
        },
      },
      required: ['plugin_name'],
    },
    handler: async (args: any) => {
      const modules = pluginManager.getPluginModules(String(args.plugin_name));
      return {
        plugin: args.plugin_name,
        modules,
        total: modules.length,
      };
    },
  },

  // -- check_plugin_requirements -----------------------------------------------
  {
    name: 'check_plugin_requirements',
    description: 'Check whether the system dependencies for a plugin (python3, go, etc.) are installed',
    inputSchema: {
      type: 'object',
      properties: {
        plugin_name: {
          type: 'string',
          description: 'Plugin catalog name',
        },
      },
      required: ['plugin_name'],
    },
    handler: async (args: any) => {
      const { installed } = pluginManager.listPlugins();
      const match = installed.find(
        (p: any) => p.name?.toLowerCase() === String(args.plugin_name).toLowerCase()
      );
      if (!match) {
        // Use catalog entry to check even before install
        const { PLUGIN_CATALOG: cat } = await import('../plugins/registry.js');
        const catalogEntry = cat.find(
          (e) => e.name.toLowerCase() === String(args.plugin_name).toLowerCase()
        );
        if (!catalogEntry) throw new Error(`Plugin "${args.plugin_name}" not found in catalog`);
        return pluginManager.checkRequirements(
          catalogEntry as any
        );
      }
      return pluginManager.checkRequirements(match);
    },
  },

  // ── get_checklist ───────────────────────────────────────────────────────
  {
    name: 'get_checklist',
    description: 'Get a checklist with all its items and verification status',
    inputSchema: {
      type: 'object',
      properties: {
        checklist_id: { type: 'number', description: 'Checklist ID' },
        name: { type: 'string', description: 'Checklist name to search for (alternative to ID)' },
      },
    },
    handler: async (args: any) => {
      let checklist: any = null;

      if (args.checklist_id) {
        checklist = getChecklistById(Number(args.checklist_id));
        if (!checklist) throw new Error(`Checklist ${args.checklist_id} not found`);
      } else if (args.name) {
        const all = getAllChecklists();
        checklist = all.find(c =>
          c.name.toLowerCase().includes(String(args.name).toLowerCase())
        );
        if (!checklist) throw new Error(`No checklist found matching name "${args.name}"`);
      } else {
        // Return summary of all checklists
        const all = getAllChecklists();
        return {
          checklists: all.map(c => ({
            ...c,
            items_count: getChecklistItems(c.id!).length,
          })),
          total: all.length,
        };
      }

      const items = getChecklistItems(checklist.id!);
      const verifiedCount = items.filter((i: any) => i.verified).length;
      return {
        ...checklist,
        total_items: items.length,
        verified_count: verifiedCount,
        progress_pct: items.length > 0
          ? Math.round((verifiedCount / items.length) * 100)
          : 0,
        items,
      };
    },
  },

  // ── verify_checklist ────────────────────────────────────────────────────
  {
    name: 'verify_checklist',
    description: 'Run automated verification of a checklist against a project\'s vulnerability findings',
    inputSchema: {
      type: 'object',
      properties: {
        checklist_id: { type: 'number', description: 'Checklist ID to verify' },
        project_id: { type: 'number', description: 'Project ID to check findings against' },
      },
      required: ['checklist_id', 'project_id'],
    },
    handler: async (args: any) => {
      const result = await verifyFullChecklist(
        Number(args.checklist_id),
        Number(args.project_id)
      );
      return result;
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // PIPELINE TOOLS — autonomous scan pipeline operations
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'start_pipeline',
    description: 'Start an autonomous vulnerability research pipeline. Accepts a Git URL, local path, or existing project ID. The pipeline clones (if URL), selects tools based on language, runs scans, filters false positives, AI-verifies findings, and stages results for review.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Git repository URL to clone and scan' },
        path: { type: 'string', description: 'Local directory path to scan' },
        project_id: { type: 'number', description: 'Existing project ID to scan' },
        branch: { type: 'string', description: 'Git branch to clone (default: main)' },
        depth: { type: 'number', description: 'Git clone depth (default: 1 for shallow)' },
      },
    },
    handler: async (args: any) => {
      const { runPipeline } = await import('../pipeline/orchestrator.js');
      const pipelineId = await runPipeline({
        url: args.url,
        path: args.path,
        project_id: args.project_id ? Number(args.project_id) : undefined,
        branch: args.branch,
        depth: args.depth ? Number(args.depth) : undefined,
      });
      const pipeline = getPipelineRun(pipelineId);
      return { pipelineId, projectId: pipeline?.project_id, status: pipeline?.status };
    },
  },

  {
    name: 'get_pipeline_status',
    description: 'Get the current status and progress of a pipeline run, including stage, findings counts, and completion state',
    inputSchema: {
      type: 'object',
      properties: {
        pipeline_id: { type: 'string', description: 'Pipeline run ID' },
      },
      required: ['pipeline_id'],
    },
    handler: async (args: any) => {
      const pipeline = getPipelineRun(String(args.pipeline_id));
      if (!pipeline) throw new Error(`Pipeline ${args.pipeline_id} not found`);
      return pipeline;
    },
  },

  {
    name: 'list_pipelines',
    description: 'List pipeline runs. By default returns recent pipelines; set active_only=true to see only running ones.',
    inputSchema: {
      type: 'object',
      properties: {
        active_only: { type: 'boolean', description: 'Only return non-completed pipelines' },
      },
    },
    handler: async (args: any) => {
      const pipelines = args.active_only ? getActivePipelineRuns() : getPipelineRuns();
      return { pipelines, total: pipelines.length };
    },
  },

  {
    name: 'cancel_pipeline',
    description: 'Cancel a running pipeline',
    inputSchema: {
      type: 'object',
      properties: {
        pipeline_id: { type: 'string', description: 'Pipeline run ID to cancel' },
      },
      required: ['pipeline_id'],
    },
    handler: async (args: any) => {
      const { cancelPipeline } = await import('../pipeline/orchestrator.js');
      const success = cancelPipeline(String(args.pipeline_id));
      return { cancelled: success, pipeline_id: args.pipeline_id };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // SCAN FINDINGS TOOLS — manage staged findings before acceptance
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'list_scan_findings',
    description: 'List scan findings (staged results from tool scans). Filter by pipeline, scan, project, or status (pending/accepted/rejected/auto_rejected).',
    inputSchema: {
      type: 'object',
      properties: {
        pipeline_id: { type: 'string', description: 'Filter by pipeline run ID' },
        scan_id: { type: 'number', description: 'Filter by scan ID' },
        project_id: { type: 'number', description: 'Filter by project ID' },
        status: { type: 'string', enum: ['pending', 'accepted', 'rejected', 'auto_rejected'], description: 'Filter by status' },
      },
    },
    handler: async (args: any) => {
      const filters: any = {};
      if (args.pipeline_id) filters.pipeline_id = String(args.pipeline_id);
      if (args.scan_id) filters.scan_id = Number(args.scan_id);
      if (args.project_id) filters.project_id = Number(args.project_id);
      if (args.status) filters.status = args.status;
      const findings = getScanFindings(filters);
      const counts = countScanFindings(filters);
      return { findings: findings.slice(0, 100), counts, total: findings.length };
    },
  },

  {
    name: 'accept_scan_finding',
    description: 'Accept a staged scan finding, promoting it to the permanent vulnerabilities table',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Scan finding ID to accept' },
      },
      required: ['id'],
    },
    handler: async (args: any) => {
      const sf = getScanFindingById(Number(args.id));
      if (!sf) throw new Error(`Scan finding ${args.id} not found`);
      if (sf.status === 'accepted') return { already_accepted: true, id: args.id };

      const vulnId = createVulnerability({
        project_id: sf.project_id ?? undefined,
        title: sf.title,
        severity: sf.severity || 'Medium',
        status: 'Open',
        cvss: sf.cvss || undefined,
        cwe: sf.cwe || undefined,
        file: sf.file || undefined,
        line_start: sf.line_start ?? undefined,
        line_end: sf.line_end ?? undefined,
        code_snippet: sf.code_snippet || undefined,
        description: sf.description || undefined,
        impact: (sf as any).impact || undefined,
        suggested_fix: (sf as any).suggested_fix || undefined,
        tool_name: sf.tool_name || undefined,
        confidence: sf.confidence === 'High' ? 0.9 : sf.confidence === 'Medium' ? 0.6 : 0.3,
        verified: 0,
        false_positive: 0,
      });
      updateScanFinding(Number(args.id), { status: 'accepted' });
      return { accepted: true, vuln_id: vulnId, finding_id: args.id };
    },
  },

  {
    name: 'reject_scan_finding',
    description: 'Reject a staged scan finding with an optional reason',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Scan finding ID to reject' },
        reason: { type: 'string', description: 'Rejection reason' },
      },
      required: ['id'],
    },
    handler: async (args: any) => {
      const sf = getScanFindingById(Number(args.id));
      if (!sf) throw new Error(`Scan finding ${args.id} not found`);
      updateScanFinding(Number(args.id), {
        status: 'rejected',
        rejection_reason: args.reason || 'Rejected via MCP',
      });
      return { rejected: true, finding_id: args.id };
    },
  },

  {
    name: 'bulk_accept_findings',
    description: 'Accept multiple scan findings at once by their IDs',
    inputSchema: {
      type: 'object',
      properties: {
        ids: {
          type: 'array',
          items: { type: 'number' },
          description: 'Array of scan finding IDs to accept',
        },
      },
      required: ['ids'],
    },
    handler: async (args: any) => {
      const ids: number[] = args.ids || [];
      const results: { id: number; vuln_id?: number; error?: string }[] = [];
      for (const id of ids) {
        try {
          const sf = getScanFindingById(id);
          if (!sf) { results.push({ id, error: 'Not found' }); continue; }
          if (sf.status === 'accepted') { results.push({ id, error: 'Already accepted' }); continue; }
          const vulnId = createVulnerability({
            project_id: sf.project_id ?? undefined,
            title: sf.title,
            severity: sf.severity || 'Medium',
            status: 'Open',
            cvss: sf.cvss || undefined,
            cwe: sf.cwe || undefined,
            file: sf.file || undefined,
            description: sf.description || undefined,
            tool_name: sf.tool_name || undefined,
            confidence: sf.confidence === 'High' ? 0.9 : 0.6,
            verified: 0,
            false_positive: 0,
          });
          updateScanFinding(id, { status: 'accepted' });
          results.push({ id, vuln_id: vulnId });
        } catch (err: any) {
          results.push({ id, error: err.message });
        }
      }
      return { accepted: results.filter(r => r.vuln_id).length, results };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // PROJECT + AI ROUTING TOOLS
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'import_project_url',
    description: 'Clone a Git repository and import it as a project. Returns immediately with the project ID — cloning happens asynchronously.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Git repository URL (GitHub, GitLab, Bitbucket, etc.)' },
        branch: { type: 'string', description: 'Branch to clone (default: main)' },
        depth: { type: 'number', description: 'Clone depth (default: 1 for shallow)' },
      },
      required: ['url'],
    },
    handler: async (args: any) => {
      const {
        validateRepoUrl, repoNameFromUrl, cloneRepo, detectProjectMeta, extractDependencies,
      } = await import('../pipeline/git.js');

      const url = String(args.url);
      if (!validateRepoUrl(url)) throw new Error('Invalid git repository URL');

      const name = repoNameFromUrl(url);
      const projectId = createProject({
        name, repo_url: url, branch: args.branch || null, language: 'detecting...',
      } as any);
      updateProject(projectId, { clone_status: 'cloning' } as any);

      // Async clone — don't await in handler
      cloneRepo(url, { branch: args.branch, depth: args.depth || 1 }).then(async (result: any) => {
        const meta = detectProjectMeta(result.localPath);
        const deps = extractDependencies(result.localPath);
        updateProject(projectId, {
          path: result.localPath, branch: result.branch, language: meta.primaryLanguage,
          clone_status: 'ready', commit_hash: result.commitHash,
          build_system: JSON.stringify(meta.buildSystems),
          dependencies: JSON.stringify(deps),
          languages: JSON.stringify(meta.languages),
        } as any);
      }).catch((err: any) => {
        updateProject(projectId, { clone_status: 'failed', clone_error: err.message } as any);
      });

      return { id: projectId, name, status: 'cloning', url };
    },
  },

  {
    name: 'get_ai_routing',
    description: 'Get the current AI task routing rules. Shows which provider/model handles each task type.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    handler: async () => {
      const { getRoutingRules, ROUTING_PRESETS, TASK_DESCRIPTIONS } = await import('../ai/routing.js');
      return {
        rules: getRoutingRules(),
        available_presets: Object.keys(ROUTING_PRESETS),
        task_descriptions: TASK_DESCRIPTIONS,
      };
    },
  },

  {
    name: 'set_ai_routing',
    description: 'Update AI task routing rules. Provide either a preset name or a full rules array. Available presets: smart-split, all-claude, all-openai, all-gemini, all-local, budget, claude-cli',
    inputSchema: {
      type: 'object',
      properties: {
        preset: {
          type: 'string',
          description: 'Apply a named preset (smart-split, all-claude, all-openai, all-gemini, all-local, budget, claude-cli)',
        },
        rules: {
          type: 'array',
          description: 'Custom rules array. Each rule: { task, provider, model, priority }',
          items: {
            type: 'object',
            properties: {
              task: { type: 'string' },
              provider: { type: 'string' },
              model: { type: 'string' },
              priority: { type: 'number' },
            },
            required: ['task', 'provider', 'model'],
          },
        },
      },
    },
    handler: async (args: any) => {
      const { persistRules, ROUTING_PRESETS } = await import('../ai/routing.js');

      if (args.preset) {
        const preset = ROUTING_PRESETS[args.preset];
        if (!preset) throw new Error(`Unknown preset "${args.preset}". Available: ${Object.keys(ROUTING_PRESETS).join(', ')}`);
        persistRules(preset.rules);
        return { applied_preset: args.preset, rule_count: preset.rules.length };
      }

      if (args.rules && Array.isArray(args.rules)) {
        const rules = args.rules.map((r: any) => ({
          task: r.task, provider: r.provider, model: r.model, priority: r.priority || 1,
        }));
        persistRules(rules);
        return { custom_rules: true, rule_count: rules.length };
      }

      throw new Error('Provide either "preset" name or "rules" array');
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // REPORTS + STATS TOOLS
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'generate_report',
    description: 'Generate a vulnerability disclosure report. Types: email (vendor notification), advisory (public advisory), summary (brief overview)',
    inputSchema: {
      type: 'object',
      properties: {
        vuln_id: { type: 'number', description: 'Vulnerability ID to report on' },
        type: { type: 'string', enum: ['email', 'advisory', 'summary'], description: 'Report type' },
      },
      required: ['vuln_id', 'type'],
    },
    handler: async (args: any) => {
      const { createReport } = await import('../db.js');
      const vuln = getVulnerabilityById(Number(args.vuln_id));
      if (!vuln) throw new Error(`Vulnerability ${args.vuln_id} not found`);

      // Use AI to generate the report
      const { routeAI } = await import('../ai/router.js');
      const prompt = `Generate a ${args.type} report for this vulnerability:\n\nTitle: ${vuln.title}\nSeverity: ${vuln.severity}\nCVSS: ${vuln.cvss}\nCWE: ${vuln.cwe}\nFile: ${vuln.file}\nDescription: ${vuln.description}\nImpact: ${vuln.impact || 'N/A'}\nSuggested Fix: ${vuln.suggested_fix || 'N/A'}\n\n${args.type === 'email' ? 'Write a professional vendor notification email.' : args.type === 'advisory' ? 'Write a public security advisory.' : 'Write a brief summary.'}`;

      const response = await routeAI({
        messages: [{ role: 'user', content: prompt }],
        task: 'report' as any,
        temperature: 0.3,
        maxTokens: 2048,
      });

      const reportId = createReport({
        vuln_id: Number(args.vuln_id),
        type: args.type,
        format: 'text',
        content: response?.content || '',
        generated_by: 'mcp',
      });

      return { report_id: reportId, type: args.type, vuln_id: args.vuln_id, content: response?.content || '' };
    },
  },

  {
    name: 'get_dashboard_stats',
    description: 'Get dashboard statistics: total findings, severity breakdown, project count, recent scans, and more',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    handler: async () => {
      return getStats();
    },
  },
];

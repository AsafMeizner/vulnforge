import {
  getAllVulnerabilities,
  getVulnerabilityById,
  createVulnerability,
  updateVulnerability,
  getAllProjects,
  createProject,
  updateProject,
  getProjectById,
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
  getNotes,
  getNoteById,
  createNote,
  updateNote,
  getSessionState,
  setSessionState,
  getRuntimeJobs,
  getRuntimeJobById,
  getFuzzCrashes,
  getFuzzCrashById,
  updateFuzzCrash,
  getCveIntel,
  getCveIntelById,
  getCveProjectMatches,
  getBisectResults,
  getExploits,
  getExploitById,
  createExploit,
  updateExploit,
  getProofLadder,
  setProofTier,
} from '../db.js';
import { streamTool } from '../scanner/runner.js';
import { triageFinding } from '../ai/router.js';
import { pluginManager } from '../plugins/manager.js';
import { PLUGIN_CATALOG } from '../plugins/registry.js';
import { verifyFullChecklist } from '../checklists/verifier.js';
import { getProvider, getDefaultProvider } from '../pipeline/notes/index.js';
import type { NoteMeta } from '../pipeline/notes/index.js';

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

  // ═══════════════════════════════════════════════════════════════════════
  // NOTES / RESEARCH WORKSPACE TOOLS
  // ═══════════════════════════════════════════════════════════════════════

  // ── create_note ─────────────────────────────────────────────────────────
  {
    name: 'create_note',
    description: 'Create a note, hypothesis, or observation. Links to a project and/or findings.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string', description: 'Note title' },
        content: { type: 'string', description: 'Markdown body of the note' },
        type: {
          type: 'string',
          enum: ['note', 'hypothesis', 'observation', 'exploit-idea', 'todo'],
          description: 'Note type (default: note)',
        },
        status: {
          type: 'string',
          enum: ['open', 'investigating', 'confirmed', 'disproved', 'obsolete'],
          description: 'Status — primarily for hypotheses',
        },
        project_id: { type: 'number', description: 'Associated project ID' },
        finding_ids: {
          type: 'array',
          items: { type: 'number' },
          description: 'Linked vulnerability/finding IDs',
        },
        tags: {
          type: 'array',
          items: { type: 'string' },
          description: 'Free-form tags',
        },
        confidence: { type: 'number', description: 'Confidence score between 0 and 1' },
        provider: { type: 'string', description: 'Notes provider name (defaults to the configured default)' },
      },
      required: ['title', 'content'],
    },
    handler: async (args: any) => {
      if (!args.title) throw new Error('title is required');
      if (args.content === undefined || args.content === null) {
        throw new Error('content is required');
      }

      const provider = args.provider
        ? await getProvider(String(args.provider))
        : await getDefaultProvider();

      const now = new Date().toISOString();
      const meta: NoteMeta = {
        title: String(args.title),
        type: args.type || 'note',
        status: args.status,
        projectId: args.project_id !== undefined ? Number(args.project_id) : undefined,
        findingIds: Array.isArray(args.finding_ids)
          ? args.finding_ids.map((n: any) => Number(n)).filter((n: number) => !isNaN(n))
          : undefined,
        tags: Array.isArray(args.tags) ? args.tags.map((t: any) => String(t)) : undefined,
        confidence: args.confidence !== undefined ? Number(args.confidence) : undefined,
        createdAt: now,
        updatedAt: now,
      };

      const { externalId } = await provider.createNote(meta, String(args.content));

      const id = createNote({
        provider: provider.name,
        external_id: externalId,
        title: meta.title,
        type: meta.type || 'note',
        status: meta.status || undefined,
        tags: JSON.stringify(meta.tags || []),
        project_id: meta.projectId,
        finding_ids: JSON.stringify(meta.findingIds || []),
        file_refs: JSON.stringify([]),
        confidence: meta.confidence,
      });

      return {
        id,
        title: meta.title,
        type: meta.type || 'note',
        provider: provider.name,
        externalId,
      };
    },
  },

  // ── list_notes ──────────────────────────────────────────────────────────
  {
    name: 'list_notes',
    description: 'List notes with optional filters by project, type, status, tag, or linked finding.',
    inputSchema: {
      type: 'object',
      properties: {
        project_id: { type: 'number', description: 'Filter by project ID' },
        type: { type: 'string', description: 'Filter by note type' },
        status: { type: 'string', description: 'Filter by note status' },
        tag: { type: 'string', description: 'Filter by tag (exact match)' },
        finding_id: { type: 'number', description: 'Filter by linked finding ID' },
        limit: { type: 'number', description: 'Max results (default 50)' },
      },
    },
    handler: async (args: any) => {
      const limit = args.limit ? Math.min(Number(args.limit), 50) : 50;
      const notes = getNotes({
        project_id: args.project_id !== undefined ? Number(args.project_id) : undefined,
        type: args.type ? String(args.type) : undefined,
        status: args.status ? String(args.status) : undefined,
        tag: args.tag ? String(args.tag) : undefined,
        finding_id: args.finding_id !== undefined ? Number(args.finding_id) : undefined,
        limit,
      });
      return { notes, total: notes.length };
    },
  },

  // ── read_note ───────────────────────────────────────────────────────────
  {
    name: 'read_note',
    description: 'Read the full content of a note including its markdown body.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Note ID' },
      },
      required: ['id'],
    },
    handler: async (args: any) => {
      const note = getNoteById(Number(args.id));
      if (!note) throw new Error(`Note ${args.id} not found`);

      const provider = await getProvider(note.provider);
      const result = await provider.readNote(note.external_id);

      return {
        ...note,
        content: result.markdown,
      };
    },
  },

  // ── update_note ─────────────────────────────────────────────────────────
  {
    name: 'update_note',
    description: 'Update a note\'s content, status, tags, or other metadata.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Note ID to update' },
        title: { type: 'string', description: 'New title' },
        content: { type: 'string', description: 'New markdown body' },
        status: { type: 'string', description: 'New status' },
        tags: {
          type: 'array',
          items: { type: 'string' },
          description: 'Replacement tags list',
        },
        confidence: { type: 'number', description: 'Updated confidence 0-1' },
      },
      required: ['id'],
    },
    handler: async (args: any) => {
      const id = Number(args.id);
      const note = getNoteById(id);
      if (!note) throw new Error(`Note ${id} not found`);

      const provider = await getProvider(note.provider);

      // If content (or title) provided, update the underlying note file.
      if (args.content !== undefined || args.title !== undefined) {
        const existing = await provider.readNote(note.external_id);
        const nextMarkdown = args.content !== undefined ? String(args.content) : existing.markdown;
        const metaUpdate: Partial<NoteMeta> = {};
        if (args.title !== undefined) metaUpdate.title = String(args.title);
        if (args.status !== undefined) metaUpdate.status = String(args.status);
        if (Array.isArray(args.tags)) metaUpdate.tags = args.tags.map((t: any) => String(t));
        if (args.confidence !== undefined) metaUpdate.confidence = Number(args.confidence);
        await provider.updateNote(note.external_id, nextMarkdown, metaUpdate);
      }

      // Update the DB row metadata.
      const dbUpdates: Partial<typeof note> = {};
      if (args.title !== undefined) dbUpdates.title = String(args.title);
      if (args.status !== undefined) dbUpdates.status = String(args.status);
      if (Array.isArray(args.tags)) dbUpdates.tags = JSON.stringify(args.tags.map((t: any) => String(t)));
      if (args.confidence !== undefined) dbUpdates.confidence = Number(args.confidence);

      if (Object.keys(dbUpdates).length > 0) {
        updateNote(id, dbUpdates);
      }

      return getNoteById(id);
    },
  },

  // ── search_notes ────────────────────────────────────────────────────────
  {
    name: 'search_notes',
    description: 'Search notes by text query (matches title and content, case-insensitive).',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search text' },
        project_id: { type: 'number', description: 'Restrict search to a project' },
      },
      required: ['query'],
    },
    handler: async (args: any) => {
      const needle = String(args.query || '').toLowerCase();
      if (!needle) throw new Error('query is required');

      const notes = getNotes({
        project_id: args.project_id !== undefined ? Number(args.project_id) : undefined,
        limit: 200,
      });

      const matches: any[] = [];
      for (const note of notes) {
        if (matches.length >= 50) break;

        // Fast path: title match
        const titleHit = (note.title || '').toLowerCase().includes(needle);

        let contentHit = false;
        let snippet: string | undefined;
        try {
          const provider = await getProvider(note.provider);
          const { markdown } = await provider.readNote(note.external_id);
          if ((markdown || '').toLowerCase().includes(needle)) {
            contentHit = true;
            const idx = markdown.toLowerCase().indexOf(needle);
            const start = Math.max(0, idx - 60);
            const end = Math.min(markdown.length, idx + needle.length + 60);
            snippet = markdown.substring(start, end).replace(/\s+/g, ' ').trim();
          }
        } catch {
          // provider read failed — fall back to title-only match
        }

        if (titleHit || contentHit) {
          matches.push({ ...note, snippet });
        }
      }

      return { notes: matches, total: matches.length, query: args.query };
    },
  },

  // ── link_note_to_finding ────────────────────────────────────────────────
  {
    name: 'link_note_to_finding',
    description: 'Link a note to a specific vulnerability finding for cross-reference.',
    inputSchema: {
      type: 'object',
      properties: {
        note_id: { type: 'number', description: 'Note ID' },
        finding_id: { type: 'number', description: 'Vulnerability/finding ID to link' },
      },
      required: ['note_id', 'finding_id'],
    },
    handler: async (args: any) => {
      const noteId = Number(args.note_id);
      const findingId = Number(args.finding_id);

      const note = getNoteById(noteId);
      if (!note) throw new Error(`Note ${noteId} not found`);

      let findingIds: number[] = [];
      try {
        const parsed = JSON.parse(note.finding_ids || '[]');
        if (Array.isArray(parsed)) {
          findingIds = parsed.map((n: any) => Number(n)).filter((n: number) => !isNaN(n));
        }
      } catch {
        findingIds = [];
      }

      if (!findingIds.includes(findingId)) {
        findingIds.push(findingId);
        updateNote(noteId, { finding_ids: JSON.stringify(findingIds) });
      }

      return getNoteById(noteId);
    },
  },

  // ── list_hypotheses ─────────────────────────────────────────────────────
  {
    name: 'list_hypotheses',
    description: 'List research hypotheses. Hypotheses are notes with type="hypothesis" and track investigation status.',
    inputSchema: {
      type: 'object',
      properties: {
        project_id: { type: 'number', description: 'Filter by project ID' },
        status: {
          type: 'string',
          enum: ['open', 'investigating', 'confirmed', 'disproved', 'obsolete'],
          description: 'Filter by hypothesis status',
        },
      },
    },
    handler: async (args: any) => {
      const hypotheses = getNotes({
        project_id: args.project_id !== undefined ? Number(args.project_id) : undefined,
        type: 'hypothesis',
        status: args.status ? String(args.status) : undefined,
        limit: 50,
      });

      const statusCounts: Record<string, number> = {
        open: 0, investigating: 0, confirmed: 0, disproved: 0, obsolete: 0,
      };
      for (const h of hypotheses) {
        const s = h.status || 'open';
        statusCounts[s] = (statusCounts[s] || 0) + 1;
      }

      return {
        hypotheses,
        total: hypotheses.length,
        status_counts: statusCounts,
      };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // SESSION STATE TOOLS
  // ═══════════════════════════════════════════════════════════════════════

  // ── get_session_state ───────────────────────────────────────────────────
  {
    name: 'get_session_state',
    description: 'Get saved session state — the user\'s last investigation context, filters, active items, etc.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: {
          type: 'string',
          enum: ['global', 'project', 'finding'],
          description: 'Scope of the state entry',
        },
        scope_id: { type: 'number', description: 'Project or finding ID (omit for global)' },
        key: { type: 'string', description: 'Optional key to fetch a single entry' },
      },
      required: ['scope'],
    },
    handler: async (args: any) => {
      const scope = String(args.scope);
      if (!['global', 'project', 'finding'].includes(scope)) {
        throw new Error(`Invalid scope "${scope}" (must be global | project | finding)`);
      }
      const scopeId = args.scope_id !== undefined ? Number(args.scope_id) : null;
      const key = args.key ? String(args.key) : undefined;

      const rows = getSessionState(scope, scopeId, key);

      const parsed = rows.map((r: any) => {
        let value: any = r.value;
        try { value = JSON.parse(r.value); } catch { /* leave raw */ }
        return { ...r, value };
      });

      return { entries: parsed, total: parsed.length };
    },
  },

  // ── set_session_state ───────────────────────────────────────────────────
  {
    name: 'set_session_state',
    description: 'Save a piece of session state. Used to leave breadcrumbs for later or for other agents.',
    inputSchema: {
      type: 'object',
      properties: {
        scope: {
          type: 'string',
          enum: ['global', 'project', 'finding'],
          description: 'Scope of the state entry',
        },
        scope_id: { type: 'number', description: 'Project or finding ID (omit for global)' },
        key: { type: 'string', description: 'State key' },
        value: { description: 'Any JSON-serializable value' },
      },
      required: ['scope', 'key'],
    },
    handler: async (args: any) => {
      const scope = String(args.scope);
      if (!['global', 'project', 'finding'].includes(scope)) {
        throw new Error(`Invalid scope "${scope}" (must be global | project | finding)`);
      }
      if (!args.key) throw new Error('key is required');

      const scopeId = args.scope_id !== undefined ? Number(args.scope_id) : null;
      const serialized = JSON.stringify(args.value ?? null);

      setSessionState(scope, scopeId, String(args.key), serialized);
      return { saved: true, scope, scope_id: scopeId, key: args.key };
    },
  },

  // ── get_active_context ──────────────────────────────────────────────────
  {
    name: 'get_active_context',
    description: 'Get the user\'s most recent research context — current project, finding, open hypothesis. Use this to pick up where they left off.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    handler: async () => {
      const readGlobalKey = (key: string): any => {
        const rows = getSessionState('global', null, key);
        if (!rows || rows.length === 0) return null;
        try { return JSON.parse(rows[0].value); }
        catch { return rows[0].value ?? null; }
      };

      const lastProjectRaw = readGlobalKey('last_project_id');
      const lastFindingRaw = readGlobalKey('last_finding_id');
      const lastHypothesisRaw = readGlobalKey('last_hypothesis_id');

      const toId = (v: any): number | null => {
        if (v === null || v === undefined) return null;
        const n = typeof v === 'object' ? Number((v as any).id ?? NaN) : Number(v);
        return isNaN(n) ? null : n;
      };

      const projectId = toId(lastProjectRaw);
      const findingId = toId(lastFindingRaw);
      const hypothesisId = toId(lastHypothesisRaw);

      const project = projectId !== null ? getProjectById(projectId) : null;
      const finding = findingId !== null ? getVulnerabilityById(findingId) : null;
      const hypothesis = hypothesisId !== null ? getNoteById(hypothesisId) : null;

      let pendingCount = 0;
      if (project && project.id !== undefined) {
        try {
          const counts = countScanFindings({ project_id: project.id });
          pendingCount = Number(counts?.pending || 0);
        } catch {
          pendingCount = 0;
        }
      }

      return {
        project: project || null,
        finding: finding || null,
        hypothesis: hypothesis || null,
        pending_count: pendingCount,
      };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // RUNTIME ANALYSIS TOOLS (Theme 3) — fuzzing, debugging, network
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'start_runtime_job',
    description: 'Start a runtime analysis job. Supports fuzzing (libfuzzer), debugging (gdb), packet capture (tcpdump), and port scanning (nmap).',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', enum: ['fuzz', 'debug', 'capture', 'portscan'], description: 'Job type' },
        tool: { type: 'string', description: 'Tool name (libfuzzer, gdb, tcpdump, nmap)' },
        config: { type: 'object', description: 'Tool-specific config' },
        project_id: { type: 'number' },
        finding_id: { type: 'number' },
      },
      required: ['type', 'tool', 'config'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: args.type,
        tool: args.tool,
        config: args.config || {},
        projectId: args.project_id,
        findingId: args.finding_id,
      });
      return { id, status: 'queued', type: args.type, tool: args.tool };
    },
  },

  {
    name: 'list_runtime_jobs',
    description: 'List runtime analysis jobs with optional filters.',
    inputSchema: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        type: { type: 'string' },
        project_id: { type: 'number' },
        finding_id: { type: 'number' },
        limit: { type: 'number' },
      },
    },
    handler: async (args: any) => {
      const jobs = getRuntimeJobs({
        status: args.status,
        type: args.type,
        project_id: args.project_id,
        finding_id: args.finding_id,
        limit: args.limit || 50,
      });
      const parsed = jobs.map(j => ({
        ...j,
        config: j.config ? JSON.parse(j.config) : {},
        stats: j.stats ? JSON.parse(j.stats) : {},
      }));
      return { jobs: parsed, total: jobs.length };
    },
  },

  {
    name: 'get_runtime_job',
    description: 'Get a runtime job full status including config and parsed stats.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    },
    handler: async (args: any) => {
      const job = getRuntimeJobById(args.id);
      if (!job) throw new Error(`Job ${args.id} not found`);
      return {
        ...job,
        config: job.config ? JSON.parse(job.config) : {},
        stats: job.stats ? JSON.parse(job.stats) : {},
      };
    },
  },

  {
    name: 'stop_runtime_job',
    description: 'Signal a running runtime job to stop.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const ok = await runtimeJobRunner.stop(args.id);
      return { stopped: ok };
    },
  },

  {
    name: 'start_fuzz_campaign',
    description: 'Start a libFuzzer campaign on a pre-compiled harness binary. Returns job ID immediately; use get_runtime_job to poll and list_crashes for crashes.',
    inputSchema: {
      type: 'object',
      properties: {
        harness_path: { type: 'string', description: 'Path to compiled libFuzzer binary' },
        corpus_dir: { type: 'string' },
        max_total_time: { type: 'number', description: 'Seconds' },
        max_len: { type: 'number' },
        project_id: { type: 'number' },
        finding_id: { type: 'number' },
      },
      required: ['harness_path'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'fuzz', tool: 'libfuzzer',
        config: {
          harness_path: args.harness_path,
          corpus_dir: args.corpus_dir,
          max_total_time: args.max_total_time || 300,
          max_len: args.max_len,
        },
        projectId: args.project_id,
        findingId: args.finding_id,
      });
      return { id, status: 'queued' };
    },
  },

  {
    name: 'list_crashes',
    description: 'List fuzz crashes, optionally filtered by job, stack hash, or linked finding.',
    inputSchema: {
      type: 'object',
      properties: {
        job_id: { type: 'string' },
        stack_hash: { type: 'string' },
        linked_finding_id: { type: 'number' },
        limit: { type: 'number' },
      },
    },
    handler: async (args: any) => {
      const crashes = getFuzzCrashes({
        job_id: args.job_id,
        stack_hash: args.stack_hash,
        linked_finding_id: args.linked_finding_id,
      });
      const limit = args.limit || 50;
      const unique = new Set(crashes.map(c => c.stack_hash).filter(Boolean));
      return {
        crashes: crashes.slice(0, limit),
        total: crashes.length,
        unique_stack_hashes: unique.size,
      };
    },
  },

  {
    name: 'link_crash_to_finding',
    description: 'Associate a fuzz crash with a vulnerability finding.',
    inputSchema: {
      type: 'object',
      properties: {
        crash_id: { type: 'number' },
        finding_id: { type: 'number' },
      },
      required: ['crash_id', 'finding_id'],
    },
    handler: async (args: any) => {
      const crash = getFuzzCrashById(args.crash_id);
      if (!crash) throw new Error(`Crash ${args.crash_id} not found`);
      updateFuzzCrash(args.crash_id, { linked_finding_id: args.finding_id });
      return getFuzzCrashById(args.crash_id);
    },
  },

  {
    name: 'start_packet_capture',
    description: 'Start a packet capture on a network interface. Returns job ID; use stop_runtime_job to end it or wait for duration to elapse.',
    inputSchema: {
      type: 'object',
      properties: {
        interface: { type: 'string', description: 'eth0, lo, any, etc.' },
        filter: { type: 'string', description: 'BPF filter expression like "port 443"' },
        duration: { type: 'number', description: 'Seconds' },
        max_packets: { type: 'number' },
      },
      required: ['interface'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'capture', tool: 'tcpdump',
        config: {
          interface: args.interface,
          filter: args.filter,
          duration: args.duration || 60,
          max_packets: args.max_packets,
        },
      });
      return { id, status: 'queued' };
    },
  },

  {
    name: 'start_port_scan',
    description: 'Run an nmap port/service scan on a target. Returns job ID; poll get_runtime_job for results.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'IP, hostname, CIDR, or range' },
        ports: { type: 'string', description: 'e.g. "80,443" or "1-1000" or "-" for all' },
        scan_type: { type: 'string', enum: ['syn', 'connect', 'udp', 'version', 'script'] },
        timing: { type: 'number' },
      },
      required: ['target'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'portscan', tool: 'nmap',
        config: {
          target: args.target,
          ports: args.ports,
          scan_type: args.scan_type || 'version',
          timing: args.timing || 3,
        },
      });
      return { id, status: 'queued' };
    },
  },

  {
    name: 'debug_with_breakpoint',
    description: 'Run a binary under gdb with a breakpoint. Useful for validating findings by triggering suspicious lines and inspecting state.',
    inputSchema: {
      type: 'object',
      properties: {
        binary_path: { type: 'string' },
        breakpoint: { type: 'string', description: 'file:line or function name' },
        args: { type: 'array', items: { type: 'string' } },
        check_expr: { type: 'string' },
        timeout: { type: 'number' },
      },
      required: ['binary_path', 'breakpoint'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'debug', tool: 'gdb',
        config: {
          binary_path: args.binary_path,
          breakpoint: args.breakpoint,
          args: args.args,
          check_expr: args.check_expr,
          timeout: args.timeout || 60,
        },
      });

      // Poll until completion (up to timeout + 10s buffer)
      const deadline = Date.now() + (args.timeout || 60) * 1000 + 10000;
      while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 1000));
        const job = getRuntimeJobById(id);
        if (job && (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled')) {
          return {
            id,
            status: job.status,
            stats: job.stats ? JSON.parse(job.stats) : {},
            error: job.error,
          };
        }
      }
      return { id, status: 'timeout', stats: {} };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // HISTORICAL INTELLIGENCE TOOLS (Theme 4) — CVE intel, bisect, patch analysis
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'sync_nvd',
    description: 'Fetch recent CVEs from the NVD API and cross-reference them against imported project dependencies.',
    inputSchema: {
      type: 'object',
      properties: {
        days: { type: 'number', description: 'Number of days back to fetch (default 30)' },
      },
    },
    handler: async (args: any) => {
      const { fullSync } = await import('../pipeline/history/nvd-sync.js');
      return await fullSync(args.days || 30);
    },
  },

  {
    name: 'list_cve_intel',
    description: 'List CVEs from local NVD intelligence cache. Filter by severity or date.',
    inputSchema: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
        since: { type: 'string', description: 'ISO date' },
        limit: { type: 'number' },
      },
    },
    handler: async (args: any) => {
      const cves = getCveIntel({ severity: args.severity, since: args.since, limit: args.limit || 50 });
      return { cves, total: cves.length };
    },
  },

  {
    name: 'get_cve',
    description: 'Get details for a specific CVE from the local intelligence cache.',
    inputSchema: {
      type: 'object',
      properties: { cve_id: { type: 'string' } },
      required: ['cve_id'],
    },
    handler: async (args: any) => {
      const cve = getCveIntelById(args.cve_id);
      if (!cve) throw new Error(`CVE ${args.cve_id} not in local cache. Run sync_nvd first.`);
      return {
        ...cve,
        affected_products: (() => { try { return JSON.parse(cve.affected_products || '[]'); } catch { return []; } })(),
        cve_references: (() => { try { return JSON.parse(cve.cve_references || '[]'); } catch { return []; } })(),
      };
    },
  },

  {
    name: 'get_project_cve_matches',
    description: 'Get CVEs matched against a project via its dependencies.',
    inputSchema: {
      type: 'object',
      properties: { project_id: { type: 'number' } },
      required: ['project_id'],
    },
    handler: async (args: any) => {
      const matches = getCveProjectMatches({ project_id: args.project_id });
      return { matches, total: matches.length };
    },
  },

  {
    name: 'start_bisect',
    description: 'Start a git bisect job to find the commit that introduced a bug. Provide a known-good commit, a known-bad commit, and a test command that exits 0 for good and non-zero for bad.',
    inputSchema: {
      type: 'object',
      properties: {
        project_id: { type: 'number' },
        good_ref: { type: 'string', description: 'Known-good commit/tag (e.g. "v1.0.0")' },
        bad_ref: { type: 'string', description: 'Known-bad commit/tag (e.g. "HEAD")' },
        test_command: { type: 'string', description: 'Shell command; exit 0 = good, non-zero = bad' },
      },
      required: ['project_id', 'good_ref', 'bad_ref', 'test_command'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'bisect' as any,
        tool: 'git',
        config: {
          project_id: args.project_id,
          good_ref: args.good_ref,
          bad_ref: args.bad_ref,
          test_command: args.test_command,
        },
        projectId: args.project_id,
      });
      return { id, status: 'queued' };
    },
  },

  {
    name: 'analyze_patch',
    description: 'Analyze a git commit to identify security-relevant changes and extract patterns for variant hunting.',
    inputSchema: {
      type: 'object',
      properties: {
        project_id: { type: 'number' },
        sha: { type: 'string', description: 'Commit SHA (or ref like "HEAD~1")' },
      },
      required: ['project_id', 'sha'],
    },
    handler: async (args: any) => {
      const { getProjectById } = await import('../db.js');
      const project = getProjectById(args.project_id);
      if (!project?.path) throw new Error(`Project ${args.project_id} has no local path`);
      const { analyzeCommit } = await import('../pipeline/history/patch-analyzer.js');
      return await analyzeCommit(project.path, args.sha);
    },
  },

  {
    name: 'list_bisect_results',
    description: 'List results from past git bisect jobs.',
    inputSchema: {
      type: 'object',
      properties: { job_id: { type: 'string' } },
    },
    handler: async (args: any) => {
      return { results: getBisectResults({ job_id: args.job_id }) };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // EXPLOIT DEVELOPMENT TOOLS (Theme 2) — PoC workbench, proof ladder
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'list_exploits',
    description: 'List exploits/PoCs with optional filters by linked finding or proof ladder tier.',
    inputSchema: {
      type: 'object',
      properties: {
        finding_id: { type: 'number' },
        tier: { type: 'string', enum: ['pattern', 'manual', 'traced', 'poc', 'weaponized'] },
      },
    },
    handler: async (args: any) => {
      const rows = getExploits({ finding_id: args.finding_id, tier: args.tier });
      return { exploits: rows, total: rows.length };
    },
  },

  {
    name: 'get_exploit',
    description: 'Read an exploit by ID, including its full code.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'number' } },
      required: ['id'],
    },
    handler: async (args: any) => {
      const e = getExploitById(args.id);
      if (!e) throw new Error(`Exploit ${args.id} not found`);
      return e;
    },
  },

  {
    name: 'create_exploit',
    description: 'Create a new PoC/exploit. Can be linked to a finding and bootstrapped from a template.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        finding_id: { type: 'number' },
        language: { type: 'string' },
        code: { type: 'string' },
        tier: { type: 'string' },
        notes: { type: 'string' },
        template: { type: 'string', description: 'Optional template ID this PoC derived from' },
      },
      required: ['title'],
    },
    handler: async (args: any) => {
      const id = createExploit({
        title: args.title,
        finding_id: args.finding_id,
        language: args.language || 'python',
        code: args.code || '',
        tier: args.tier || 'pattern',
        notes: args.notes,
        template: args.template,
      });
      return getExploitById(id);
    },
  },

  {
    name: 'update_exploit',
    description: 'Update an exploit\'s code, tier, notes, or title.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number' },
        title: { type: 'string' },
        code: { type: 'string' },
        tier: { type: 'string' },
        notes: { type: 'string' },
        last_run_status: { type: 'string' },
        last_run_output: { type: 'string' },
      },
      required: ['id'],
    },
    handler: async (args: any) => {
      const { id, ...updates } = args;
      const existing = getExploitById(id);
      if (!existing) throw new Error(`Exploit ${id} not found`);
      updateExploit(id, updates);
      return getExploitById(id);
    },
  },

  {
    name: 'get_proof_ladder',
    description: 'Get the proof ladder for a finding — tracks progress from pattern -> manual -> traced -> poc -> weaponized.',
    inputSchema: {
      type: 'object',
      properties: { finding_id: { type: 'number' } },
      required: ['finding_id'],
    },
    handler: async (args: any) => {
      return getProofLadder(args.finding_id) || { finding_id: args.finding_id, current_tier: 'pattern' };
    },
  },

  {
    name: 'advance_proof_tier',
    description: 'Advance a finding\'s proof ladder to a new tier. Tiers are: pattern (regex match), manual (human-reviewed), traced (data flow confirmed), poc (working PoC), weaponized (reliable exploit).',
    inputSchema: {
      type: 'object',
      properties: {
        finding_id: { type: 'number' },
        tier: { type: 'string', enum: ['pattern', 'manual', 'traced', 'poc', 'weaponized'] },
        notes: { type: 'string' },
      },
      required: ['finding_id', 'tier'],
    },
    handler: async (args: any) => {
      setProofTier(args.finding_id, args.tier, args.notes);
      return getProofLadder(args.finding_id);
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // AI COPILOT TOOLS (Theme 8) — investigate mode, assumption extraction
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'start_investigation',
    description: 'Start an interactive AI investigation session with per-step approval. Each step is proposed by the AI and requires explicit user approval before execution. Use propose_next_step and execute_investigation_step to drive the loop.',
    inputSchema: {
      type: 'object',
      properties: {
        goal: { type: 'string', description: 'What you want to investigate' },
        finding_id: { type: 'number', description: 'Optional finding to scope the investigation' },
      },
      required: ['goal'],
    },
    handler: async (args: any) => {
      const { startInvestigation } = await import('../pipeline/ai/investigate.js');
      return await startInvestigation(args.goal, args.finding_id);
    },
  },

  {
    name: 'propose_next_step',
    description: 'Ask the AI to propose the next step in an investigation. Returns a pending step that needs approval.',
    inputSchema: {
      type: 'object',
      properties: { session_id: { type: 'string' } },
      required: ['session_id'],
    },
    handler: async (args: any) => {
      const { proposeNextStep } = await import('../pipeline/ai/investigate.js');
      return await proposeNextStep(args.session_id);
    },
  },

  {
    name: 'execute_investigation_step',
    description: 'Approve and execute a pending investigation step. Runs the proposed action (read_file, grep, git_blame, etc.) and returns the result.',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        step_index: { type: 'number' },
      },
      required: ['session_id', 'step_index'],
    },
    handler: async (args: any) => {
      const { executeStep } = await import('../pipeline/ai/investigate.js');
      return await executeStep(args.session_id, args.step_index);
    },
  },

  {
    name: 'reject_investigation_step',
    description: 'Reject a pending investigation step with an optional reason. The AI will then propose an alternative on the next propose_next_step call.',
    inputSchema: {
      type: 'object',
      properties: {
        session_id: { type: 'string' },
        step_index: { type: 'number' },
        reason: { type: 'string' },
      },
      required: ['session_id', 'step_index'],
    },
    handler: async (args: any) => {
      const { rejectStep } = await import('../pipeline/ai/investigate.js');
      return rejectStep(args.session_id, args.step_index, args.reason);
    },
  },

  {
    name: 'list_investigations',
    description: 'List active and completed investigation sessions.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
    handler: async () => {
      const { listInvestigations } = await import('../pipeline/ai/investigate.js');
      const sessions = listInvestigations();
      return { sessions, total: sessions.length };
    },
  },

  {
    name: 'extract_assumptions',
    description: 'Ask the AI to read a function and list all its implicit assumptions (input validation, state, bounds, invariants). Useful for formal review — you can then mark which assumptions are actually enforced by callers.',
    inputSchema: {
      type: 'object',
      properties: {
        file: { type: 'string', description: 'Absolute path to source file' },
        function: { type: 'string', description: 'Function name to analyze' },
      },
      required: ['file', 'function'],
    },
    handler: async (args: any) => {
      const { extractAssumptions } = await import('../pipeline/ai/assumptions.js');
      return await extractAssumptions(args.file, args.function);
    },
  },

  {
    name: 'generate_hypotheses',
    description: 'AI brainstorms a prioritized list of "places to investigate" for a project by scanning file names and content for security-relevant patterns. Returns 5-10 hypotheses with rationale.',
    inputSchema: {
      type: 'object',
      properties: {
        project_id: { type: 'number' },
      },
      required: ['project_id'],
    },
    handler: async (args: any) => {
      const { getProjectById } = await import('../db.js');
      const project = getProjectById(args.project_id);
      if (!project?.path) throw new Error('Project has no local path');
      const { generateHypotheses } = await import('../pipeline/ai/assumptions.js');
      const hypotheses = await generateHypotheses(project.path);
      return { hypotheses, total: hypotheses.length };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // ADVANCED RUNTIME TOOLS (Theme 3C/3E/3F) — symbolic, memory, binary
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'start_symbolic_exec',
    description: 'Run angr symbolic execution on a binary to reach a target address or symbol. Useful for generating inputs that reach hard-to-hit code paths.',
    inputSchema: {
      type: 'object',
      properties: {
        binary_path: { type: 'string' },
        find_addr: { type: 'string', description: 'Address "0x401234" or symbol name' },
        avoid_addr: { type: 'string' },
        timeout: { type: 'number', description: 'Seconds' },
        stdin_size: { type: 'number' },
      },
      required: ['binary_path', 'find_addr'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'symexec' as any, tool: 'angr',
        config: args,
      });
      return { id, status: 'queued' };
    },
  },

  {
    name: 'analyze_core_dump',
    description: 'Analyze a Linux core dump against its binary to extract signal, backtrace, registers, and shared libs. Uses gdb batch mode.',
    inputSchema: {
      type: 'object',
      properties: {
        binary_path: { type: 'string' },
        core_path: { type: 'string' },
        timeout: { type: 'number' },
      },
      required: ['binary_path', 'core_path'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'memory' as any, tool: 'core-dump',
        config: args,
      });
      return { id, status: 'queued' };
    },
  },

  {
    name: 'analyze_binary',
    description: 'Run radare2/rizin binary analysis on a target. "quick" returns imports/exports/sections/strings; "full" adds aa + function list + main disasm.',
    inputSchema: {
      type: 'object',
      properties: {
        binary_path: { type: 'string' },
        analysis_depth: { type: 'string', enum: ['quick', 'full'] },
        timeout: { type: 'number' },
      },
      required: ['binary_path'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'binary' as any, tool: 'radare2',
        config: args,
      });
      return { id, status: 'queued' };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // EXPORT + AUDIT TOOLS (Themes 7+9)
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'export_sarif',
    description: 'Export findings as SARIF 2.1.0 (compatible with GitHub Code Scanning, GitLab, Azure DevOps).',
    inputSchema: {
      type: 'object',
      properties: { project_id: { type: 'number' } },
    },
    handler: async (args: any) => {
      const { exportSarif } = await import('../pipeline/export/formats.js');
      return exportSarif({ project_id: args.project_id });
    },
  },

  {
    name: 'export_cve_json',
    description: 'Export a finding as CVE JSON 5.0 record (for submission to a CVE Numbering Authority).',
    inputSchema: {
      type: 'object',
      properties: { vuln_id: { type: 'number' } },
      required: ['vuln_id'],
    },
    handler: async (args: any) => {
      const { getVulnerabilityById } = await import('../db.js');
      const vuln = getVulnerabilityById(args.vuln_id);
      if (!vuln) throw new Error(`Vulnerability ${args.vuln_id} not found`);
      const { exportCveJson } = await import('../pipeline/export/formats.js');
      return exportCveJson(vuln);
    },
  },

  {
    name: 'export_workspace',
    description: 'Export the entire workspace as a JSON backup (projects, findings, notes, runtime jobs, disclosures, audit log).',
    inputSchema: { type: 'object', properties: {} },
    handler: async () => {
      const { exportWorkspace } = await import('../pipeline/export/formats.js');
      return await exportWorkspace();
    },
  },

  {
    name: 'get_audit_log',
    description: 'Query the audit trail for entity changes and exports.',
    inputSchema: {
      type: 'object',
      properties: {
        entity_type: { type: 'string' },
        entity_id: { type: 'string' },
        action: { type: 'string' },
        limit: { type: 'number' },
      },
    },
    handler: async (args: any) => {
      const { getAuditLog } = await import('../db.js');
      const log = getAuditLog(args);
      return { entries: log, total: log.length };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // SANDBOX / VM TOOLS
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'start_sandbox',
    description: 'Start a Docker sandbox container. Run anything safely in isolation with resource limits and automatic network capture.',
    inputSchema: {
      type: 'object',
      properties: {
        image: { type: 'string', description: 'Docker image (e.g. "ubuntu:22.04", "kalilinux/kali", "python:3.12")' },
        command: { type: 'array', items: { type: 'string' }, description: 'Command to run' },
        memory_limit: { type: 'string', description: 'e.g. "512m", "2g"' },
        cpu_limit: { type: 'number' },
        network_mode: { type: 'string', enum: ['bridge', 'host', 'none'] },
        timeout: { type: 'number', description: 'Seconds (0 = unlimited)' },
        project_id: { type: 'number' },
        finding_id: { type: 'number' },
      },
      required: ['image'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'sandbox' as any, tool: 'docker',
        config: {
          image: args.image,
          command: args.command,
          memory_limit: args.memory_limit || '512m',
          cpu_limit: args.cpu_limit,
          network_mode: args.network_mode || 'bridge',
          timeout: args.timeout || 0,
        },
        projectId: args.project_id,
        findingId: args.finding_id,
      });
      return { id, status: 'queued' };
    },
  },

  {
    name: 'pause_sandbox',
    description: 'Pause a running sandbox. Freezes all processes inside the container — instant, lossless, resumable.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    },
    handler: async (args: any) => {
      const { updateRuntimeJob } = await import('../db.js');
      updateRuntimeJob(args.id, { status: 'paused' });
      return { paused: true };
    },
  },

  {
    name: 'resume_sandbox',
    description: 'Resume a paused sandbox.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    },
    handler: async (args: any) => {
      const { updateRuntimeJob } = await import('../db.js');
      updateRuntimeJob(args.id, { status: 'running' });
      return { resumed: true };
    },
  },

  {
    name: 'snapshot_sandbox',
    description: 'Create a named snapshot of a running sandbox. You can restore to this point later.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        name: { type: 'string' },
        description: { type: 'string' },
      },
      required: ['id', 'name'],
    },
    handler: async (args: any) => {
      const job = getRuntimeJobById(args.id);
      if (!job || job.type !== 'sandbox') throw new Error('sandbox job required');
      const stats = JSON.parse(job.stats || '{}');
      if (!stats.container_id) throw new Error('no container running');

      const { dockerSnapshot } = await import('../pipeline/runtime/sandbox/introspect.js');
      const { createSandboxSnapshot } = await import('../db.js');

      const tag = await dockerSnapshot(stats.container_id, args.name);
      const snapId = createSandboxSnapshot({ job_id: args.id, name: args.name, type: 'docker', description: args.description });
      return { snapshot_id: snapId, name: args.name, tag };
    },
  },

  {
    name: 'upload_to_sandbox',
    description: 'Copy a file from the host into a running sandbox container.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        host_path: { type: 'string' },
        container_path: { type: 'string' },
      },
      required: ['id', 'host_path', 'container_path'],
    },
    handler: async (args: any) => {
      const job = getRuntimeJobById(args.id);
      if (!job) throw new Error('job not found');
      const stats = JSON.parse(job.stats || '{}');
      if (!stats.container_id) throw new Error('no container');

      const { dockerCopyIn } = await import('../pipeline/runtime/sandbox/introspect.js');
      await dockerCopyIn(stats.container_id, args.host_path, args.container_path);
      return { uploaded: true };
    },
  },

  {
    name: 'list_sandbox_processes',
    description: 'List running processes inside a sandbox container.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    },
    handler: async (args: any) => {
      const job = getRuntimeJobById(args.id);
      if (!job) throw new Error('job not found');
      const stats = JSON.parse(job.stats || '{}');
      if (!stats.container_id) return { processes: [] };

      const { dockerTop } = await import('../pipeline/runtime/sandbox/introspect.js');
      return { processes: await dockerTop(stats.container_id) };
    },
  },

  {
    name: 'get_sandbox_resources',
    description: 'Get live CPU, memory, and network I/O stats for a sandbox container.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    },
    handler: async (args: any) => {
      const job = getRuntimeJobById(args.id);
      if (!job) throw new Error('job not found');
      const stats = JSON.parse(job.stats || '{}');
      if (!stats.container_id) return {};

      const { dockerStats: getDockerStats } = await import('../pipeline/runtime/sandbox/introspect.js');
      return await getDockerStats(stats.container_id);
    },
  },

  {
    name: 'start_vm',
    description: 'Start a QEMU virtual machine. Supports x86_64, ARM, MIPS, RISC-V. Provides VNC for screen, SSH for shell, QMP for machine control.',
    inputSchema: {
      type: 'object',
      properties: {
        disk_image: { type: 'string', description: 'Path to .qcow2, .img, or .iso file' },
        arch: { type: 'string', enum: ['x86_64', 'i386', 'arm', 'aarch64', 'mips', 'riscv64'], description: 'CPU architecture' },
        memory: { type: 'string', description: 'RAM size (e.g. "2G")' },
        cpus: { type: 'number' },
        snapshot_mode: { type: 'boolean', description: 'Discard changes on shutdown' },
        timeout: { type: 'number' },
      },
      required: ['disk_image'],
    },
    handler: async (args: any) => {
      const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: 'sandbox' as any,
        tool: 'qemu',
        config: args,
      });
      return { id, status: 'queued' };
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // TEACH MODE + PATTERN MINING TOOLS (Phase 15)
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'teach_from_decision',
    description: 'Record a user decision on a finding (confirmed/rejected/false_positive) and optionally learn a reusable pattern from it. The AI extracts a grep pattern from confirmed findings for variant hunting.',
    inputSchema: {
      type: 'object',
      properties: {
        finding_id: { type: 'number' },
        action: { type: 'string', enum: ['confirmed', 'rejected', 'false_positive'] },
        reasoning: { type: 'string', description: 'Why you made this decision (stored for training)' },
      },
      required: ['finding_id', 'action'],
    },
    handler: async (args: any) => {
      const { teachFromDecision } = await import('../pipeline/ai/teach.js');
      return await teachFromDecision({
        findingId: args.finding_id,
        action: args.action,
        reasoning: args.reasoning,
      });
    },
  },

  {
    name: 'list_learned_patterns',
    description: 'List all patterns learned from confirmed findings. These are automatically used in future scans.',
    inputSchema: { type: 'object', properties: {} },
    handler: async () => {
      const { getPatterns } = await import('../pipeline/ai/teach.js');
      const patterns = getPatterns();
      return { patterns, total: patterns.length };
    },
  },

  {
    name: 'run_learned_patterns',
    description: 'Run all learned patterns against a project to find new instances of previously confirmed bug classes.',
    inputSchema: {
      type: 'object',
      properties: { project_id: { type: 'number' } },
      required: ['project_id'],
    },
    handler: async (args: any) => {
      const { getProjectById } = await import('../db.js');
      const project = getProjectById(args.project_id);
      if (!project?.path) throw new Error('Project has no local path');
      const { runLearnedPatterns } = await import('../pipeline/ai/teach.js');
      const results = await runLearnedPatterns(project.path);
      return {
        results: results.map(r => ({ pattern_name: r.pattern.name, matches: r.matches.length, first_match: r.matches[0] })),
        total_patterns: results.length,
        total_matches: results.reduce((n, r) => n + r.matches.length, 0),
      };
    },
  },

  {
    name: 'validate_poc_in_sandbox',
    description: 'Run an exploit from the workbench inside a Docker sandbox to validate it works. Returns exit code + output.',
    inputSchema: {
      type: 'object',
      properties: {
        exploit_id: { type: 'number' },
        target_image: { type: 'string', description: 'Docker image to run in (default: ubuntu:22.04)' },
        timeout: { type: 'number', description: 'Seconds (default: 30)' },
      },
      required: ['exploit_id'],
    },
    handler: async (args: any) => {
      const { validatePoCInSandbox } = await import('../pipeline/ai/teach.js');
      return await validatePoCInSandbox({
        exploitId: args.exploit_id,
        targetImage: args.target_image,
        timeout: args.timeout,
      });
    },
  },

  // ═══════════════════════════════════════════════════════════════════════
  // EXTERNAL INTEGRATIONS (Jira, Trello, Slack, GitHub, Linear)
  // ═══════════════════════════════════════════════════════════════════════

  {
    name: 'list_integrations',
    description: 'List configured external service integrations (Jira, Trello, Slack, GitHub, Linear) and available services.',
    inputSchema: { type: 'object', properties: {} },
    handler: async () => {
      const { getIntegrations } = await import('../db.js');
      const { listAvailableIntegrations } = await import('../integrations/registry.js');
      return { configured: getIntegrations(), available: listAvailableIntegrations() };
    },
  },

  {
    name: 'create_ticket',
    description: 'Create a ticket/issue in an external service (Jira, Trello, GitHub, Linear) linked to a VulnForge finding or disclosure.',
    inputSchema: {
      type: 'object',
      properties: {
        integration_id: { type: 'number', description: 'ID of the configured integration' },
        finding_id: { type: 'number', description: 'Finding to create ticket from' },
        disclosure_id: { type: 'number', description: 'Disclosure to create ticket from' },
        title: { type: 'string' },
        description: { type: 'string' },
      },
      required: ['integration_id'],
    },
    handler: async (args: any) => {
      const { getIntegrationById, createIntegrationTicket } = await import('../db.js');
      const { getServiceIntegration } = await import('../integrations/registry.js');

      const integration = getIntegrationById(args.integration_id);
      if (!integration) throw new Error('Integration not found');
      const service = getServiceIntegration(integration.name);
      if (!service) throw new Error(`No service for ${integration.name}`);

      let title = args.title || '';
      let desc = args.description || '';
      let sev: string | undefined;

      if (args.finding_id) {
        const vuln = getVulnerabilityById(args.finding_id);
        if (vuln) { title = title || vuln.title; desc = desc || vuln.description || ''; sev = vuln.severity; }
      }

      const config = JSON.parse(integration.config || '{}');
      const result = await service.createTicket({ title, description: desc, severity: sev }, config);
      createIntegrationTicket({
        integration_id: args.integration_id,
        finding_id: args.finding_id,
        disclosure_id: args.disclosure_id,
        ticket_id: result.ticket_id,
        ticket_url: result.url,
      });
      return result;
    },
  },

  {
    name: 'send_notification',
    description: 'Send a notification to a messaging integration (Slack). Use for alerting on new findings, status changes, etc.',
    inputSchema: {
      type: 'object',
      properties: {
        integration_id: { type: 'number' },
        message: { type: 'string' },
      },
      required: ['integration_id', 'message'],
    },
    handler: async (args: any) => {
      const { getIntegrationById } = await import('../db.js');
      const { getServiceIntegration } = await import('../integrations/registry.js');

      const integration = getIntegrationById(args.integration_id);
      if (!integration) throw new Error('Integration not found');
      const service = getServiceIntegration(integration.name);
      if (!service?.sendNotification) throw new Error(`${integration.name} does not support notifications`);

      const config = JSON.parse(integration.config || '{}');
      await service.sendNotification(args.message, config);
      return { sent: true };
    },
  },

  {
    name: 'list_tickets',
    description: 'List external tickets linked to VulnForge findings and disclosures.',
    inputSchema: {
      type: 'object',
      properties: {
        finding_id: { type: 'number' },
        disclosure_id: { type: 'number' },
      },
    },
    handler: async (args: any) => {
      const { getIntegrationTickets } = await import('../db.js');
      const tickets = getIntegrationTickets({
        finding_id: args.finding_id,
        disclosure_id: args.disclosure_id,
      });
      return { tickets, total: tickets.length };
    },
  },

  {
    name: 'get_vm_screenshot',
    description: 'Get the latest screenshot from a QEMU VM (VNC screen capture). Returns the file path. Future: will return base64 image for AI vision.',
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'string' } },
      required: ['id'],
    },
    handler: async (args: any) => {
      const job = getRuntimeJobById(args.id);
      if (!job) throw new Error('job not found');
      const stats = JSON.parse(job.stats || '{}');
      if (stats.sandbox_type !== 'qemu') throw new Error('Only QEMU VMs support screenshots');
      const ssPath = job.output_dir ? `${job.output_dir}/screenshot.ppm` : null;
      return { screenshot_path: ssPath, vnc_port: stats.vnc_port, ssh_port: stats.ssh_port };
    },
  },
];

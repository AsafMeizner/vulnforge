import { Router, Request, Response } from 'express';
import { readdirSync, statSync, existsSync } from 'fs';
import path from 'path';
import {
  getAllProjects,
  getProjectById,
  createProject,
  updateProject,
  deleteProject,
} from '../db.js';
import {
  validateRepoUrl,
  repoNameFromUrl,
  cloneRepo,
  detectProjectMeta,
  extractDependencies,
} from '../pipeline/git.js';
import { broadcastProgress } from '../ws.js';

const router = Router();

// Detect language from directory contents
function detectLanguage(dirPath: string): string {
  if (!existsSync(dirPath)) return 'unknown';

  try {
    const entries = readdirSync(dirPath, { withFileTypes: true });
    const extensions: Record<string, number> = {};

    const languageExtMap: Record<string, string> = {
      '.c': 'C',
      '.h': 'C',
      '.cpp': 'C++',
      '.cc': 'C++',
      '.cxx': 'C++',
      '.hpp': 'C++',
      '.py': 'Python',
      '.js': 'JavaScript',
      '.ts': 'TypeScript',
      '.go': 'Go',
      '.rs': 'Rust',
      '.java': 'Java',
      '.rb': 'Ruby',
      '.php': 'PHP',
      '.cs': 'C#',
      '.swift': 'Swift',
      '.kt': 'Kotlin',
    };

    function scanDir(dir: string, depth: number): void {
      if (depth > 3) return;
      try {
        const items = readdirSync(dir, { withFileTypes: true });
        for (const item of items) {
          if (item.name.startsWith('.') || item.name === 'node_modules') continue;
          if (item.isFile()) {
            const ext = path.extname(item.name).toLowerCase();
            if (languageExtMap[ext]) {
              extensions[languageExtMap[ext]] = (extensions[languageExtMap[ext]] || 0) + 1;
            }
          } else if (item.isDirectory()) {
            scanDir(path.join(dir, item.name), depth + 1);
          }
        }
      } catch {
        // ignore permission errors
      }
    }

    scanDir(dirPath, 0);

    const sorted = Object.entries(extensions).sort(([, a], [, b]) => b - a);
    return sorted.length > 0 ? sorted[0][0] : 'unknown';
  } catch {
    return 'unknown';
  }
}

// GET /api/projects
router.get('/', (_req: Request, res: Response) => {
  try {
    const projects = getAllProjects();
    res.json({ data: projects, total: projects.length });
  } catch (err: any) {
    console.error('GET /projects error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/projects/export - returns all projects as a JSON document
// suitable for re-importing via POST /import-bulk. Includes a schema
// version so the server can evolve the shape without breaking clients.
//
// IMPORTANT: this route MUST be declared before `/:id` below or Express
// matches `/:id` first and tries to parse the literal "export" as a
// project ID (returns 400 "Invalid ID").
router.get('/export', (_req: Request, res: Response) => {
  try {
    const projects = (getAllProjects() as any[]).map((p: any) => ({
      name: p.name,
      path: p.path,
      repo_url: p.repo_url,
      branch: p.branch,
      language: p.language,
    }));
    res.json({
      schema: 'vulnforge.projects.v1',
      exported_at: new Date().toISOString(),
      count: projects.length,
      projects,
    });
  } catch (err: any) {
    console.error('GET /projects/export error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/projects/:id
router.get('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const project = getProjectById(id);
    if (!project) {
      res.status(404).json({ error: 'Project not found' });
      return;
    }
    res.json(project);
  } catch (err: any) {
    console.error(`GET /projects/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/projects - import project by path
router.post('/', (req: Request, res: Response) => {
  try {
    const { path: projectPath, name, repo_url, branch } = req.body;

    if (!projectPath) {
      res.status(400).json({ error: 'path is required' });
      return;
    }

    // Detect name from directory if not provided
    const detectedName = name || path.basename(projectPath);
    const language = detectLanguage(projectPath);

    const id = createProject({
      name: detectedName,
      path: projectPath,
      repo_url: repo_url || null,
      branch: branch || null,
      language,
    });

    const created = getProjectById(id);
    res.status(201).json(created);
  } catch (err: any) {
    console.error('POST /projects error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/projects/import-bulk - bulk-insert projects from an export JSON.
// Body: { projects: [{ name, path, repo_url?, branch?, language? }, ...] }
// Returns: { imported, skipped, errors }
//
// Used by the Projects page Import JSON flow (round-trip with /export).
// Skips rows whose name already exists so re-importing is idempotent.
router.post('/import-bulk', (req: Request, res: Response) => {
  try {
    const body = req.body as { projects?: any };
    const projects = Array.isArray(body?.projects) ? body.projects : null;
    if (!projects) {
      res.status(400).json({ error: 'body must have a projects array' });
      return;
    }
    let imported = 0;
    const skipped: string[] = [];
    const errors: Array<{ name: string; error: string }> = [];
    const existing = new Set(
      (getAllProjects() as any[]).map((p) => (p.name || '').toLowerCase())
    );
    for (const row of projects) {
      try {
        if (!row || typeof row !== 'object') continue;
        if (!row.name || (!row.path && !row.repo_url)) {
          errors.push({ name: row?.name || '(unnamed)', error: 'name plus path or repo_url required' });
          continue;
        }
        if (existing.has(String(row.name).toLowerCase())) {
          skipped.push(row.name);
          continue;
        }
        createProject({
          name: String(row.name),
          path: row.path || null,
          repo_url: row.repo_url || null,
          branch: row.branch || null,
          language: row.language || detectLanguage(row.path || ''),
        } as any);
        imported++;
      } catch (e: any) {
        errors.push({ name: row?.name || '(unnamed)', error: e.message });
      }
    }
    res.json({ imported, skipped: skipped.length, skippedNames: skipped, errors });
  } catch (err: any) {
    console.error('POST /projects/import-bulk error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/projects/import-url - clone a git repo and import
router.post('/import-url', async (req: Request, res: Response) => {
  try {
    const { url, branch, depth } = req.body;

    if (!url || typeof url !== 'string') {
      res.status(400).json({ error: 'url is required' });
      return;
    }
    if (!validateRepoUrl(url)) {
      res.status(400).json({ error: 'Invalid git repository URL' });
      return;
    }

    const name = repoNameFromUrl(url);

    // Create project immediately with cloning status
    const projectId = createProject({
      name,
      repo_url: url,
      branch: branch || null,
      language: 'detecting...',
    });
    updateProject(projectId, { clone_status: 'cloning' } as any);

    // Return 202 immediately - clone happens async
    res.status(202).json({ id: projectId, name, status: 'cloning' });

    // Async clone + analysis
    const pipelineId = `clone-${projectId}`;
    broadcastProgress('clone', pipelineId, {
      step: 'Cloning repository',
      detail: `git clone ${url}`,
      progress: 10,
      status: 'running',
    });

    try {
      const result = await cloneRepo(url, { branch, depth: depth || 1 });

      broadcastProgress('clone', pipelineId, {
        step: 'Analyzing project',
        detail: 'Detecting languages, build systems, and dependencies',
        progress: 60,
        status: 'running',
      });

      const meta = detectProjectMeta(result.localPath);
      const deps = extractDependencies(result.localPath);

      updateProject(projectId, {
        path: result.localPath,
        branch: result.branch,
        language: meta.primaryLanguage,
        clone_status: 'ready',
        commit_hash: result.commitHash,
        build_system: JSON.stringify(meta.buildSystems),
        dependencies: JSON.stringify(deps),
        languages: JSON.stringify(meta.languages),
      } as any);

      broadcastProgress('clone', pipelineId, {
        step: 'Import complete',
        detail: `${meta.languages.join(', ')} project with ${deps.reduce((s, d) => s + d.packages.length, 0)} dependencies`,
        progress: 100,
        status: 'complete',
      });
    } catch (cloneErr: any) {
      updateProject(projectId, {
        clone_status: 'failed',
        clone_error: cloneErr.message,
      } as any);

      broadcastProgress('clone', pipelineId, {
        step: 'Clone failed',
        detail: cloneErr.message,
        progress: 0,
        status: 'error',
      });
    }
  } catch (err: any) {
    console.error('POST /projects/import-url error:', err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/projects/:id
router.delete('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const existing = getProjectById(id);
    if (!existing) {
      res.status(404).json({ error: 'Project not found' });
      return;
    }
    deleteProject(id);
    res.status(204).send();
  } catch (err: any) {
    console.error(`DELETE /projects/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

import { Router, Request, Response } from 'express';
import {
  NoteRow,
  NotesProviderRow,
  NoteFilters,
  getNotes,
  getNoteById,
  createNote,
  updateNote,
  deleteNote,
  getNotesProviders,
  getNotesProviderById,
  getNotesProviderByName,
  getDefaultNotesProvider,
  createNotesProvider,
  updateNotesProvider,
  deleteNotesProvider,
} from '../db.js';
import type { NotesProvider, NoteMeta, FileRef } from '../pipeline/notes/provider.js';
// `getProvider(name)` is expected to be exported from the provider registry at
// ../pipeline/notes/index.ts (owned by another subagent). Import is dynamic
// so these routes remain loadable even if the registry is still being built.
async function loadProviderRegistry(): Promise<{ getProvider: (name: string) => NotesProvider | null }> {
  return import('../pipeline/notes/index.js') as unknown as Promise<{
    getProvider: (name: string) => NotesProvider | null;
  }>;
}

const router = Router();

// ── Helpers ────────────────────────────────────────────────────────────────

function parseJsonField<T>(raw: string | undefined | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

/** Resolve a provider instance by name, or fall back to the default provider row. */
async function resolveProvider(
  name?: string
): Promise<{ providerRow: NotesProviderRow; provider: NotesProvider }> {
  const registry = await loadProviderRegistry();

  let providerRow: NotesProviderRow | null = null;
  if (name) {
    providerRow = getNotesProviderByName(name);
    if (!providerRow) throw new Error(`Notes provider '${name}' not found`);
  } else {
    providerRow = getDefaultNotesProvider();
    if (!providerRow) throw new Error('No default notes provider configured');
  }
  // `enabled` is a number column: 1 = enabled, 0 = disabled. Undefined
  // defaults to enabled so new providers aren't accidentally rejected.
  if (providerRow.enabled === 0) {
    throw new Error(`Notes provider '${providerRow.name}' is disabled`);
  }

  const provider = registry.getProvider(providerRow.name);
  if (!provider) {
    throw new Error(`Notes provider '${providerRow.name}' is not registered`);
  }
  return { providerRow, provider };
}

/** Merge a DB NoteRow with live content fetched from the provider. */
async function hydrateNote(row: NoteRow): Promise<Record<string, unknown>> {
  const base = {
    id: row.id,
    provider: row.provider,
    external_id: row.external_id,
    title: row.title,
    type: row.type || 'note',
    status: row.status || null,
    tags: parseJsonField<string[]>(row.tags, []),
    project_id: row.project_id ?? null,
    finding_ids: parseJsonField<number[]>(row.finding_ids, []),
    file_refs: parseJsonField<FileRef[]>(row.file_refs, []),
    confidence: row.confidence ?? null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    content: '' as string,
  };

  try {
    const registry = await loadProviderRegistry();
    const providerInstance = registry.getProvider(row.provider);
    if (providerInstance) {
      const noteContent = await providerInstance.readNote(row.external_id);
      base.content = noteContent.markdown;
    }
  } catch (err: any) {
    // Provider unreachable - return DB row with empty content; don't fail the whole request
    console.warn(`[notes] hydrateNote failed for id=${row.id}:`, err.message);
  }

  return base;
}

// ── Providers sub-routes (MUST come before /:id) ──────────────────────────

// GET /api/notes/providers
router.get('/providers', (_req: Request, res: Response) => {
  try {
    const rows = getNotesProviders().map((p) => ({
      id: p.id,
      name: p.name,
      type: p.type,
      enabled: p.enabled === 1 || p.enabled === undefined,
      is_default: p.is_default === 1,
      config: parseJsonField<Record<string, unknown>>(p.config, {}),
    }));
    res.json({ data: rows, total: rows.length });
  } catch (err: any) {
    console.error('GET /notes/providers error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/notes/providers
router.post('/providers', (req: Request, res: Response) => {
  try {
    const { name, type, config, enabled, is_default } = req.body || {};
    if (!name || typeof name !== 'string') {
      res.status(400).json({ error: 'name is required' });
      return;
    }
    if (!type || typeof type !== 'string') {
      res.status(400).json({ error: 'type is required' });
      return;
    }

    const existing = getNotesProviderByName(name);
    if (existing) {
      res.status(409).json({ error: `Provider '${name}' already exists` });
      return;
    }

    const configJson = typeof config === 'string' ? config : JSON.stringify(config || {});
    const id = createNotesProvider({
      name,
      type,
      config: configJson,
      enabled: enabled === false ? 0 : 1,
      is_default: is_default ? 1 : 0,
    });

    const created = getNotesProviderById(id);
    res.status(201).json({
      id: created?.id,
      name: created?.name,
      type: created?.type,
      enabled: created?.enabled === 1,
      is_default: created?.is_default === 1,
      config: parseJsonField<Record<string, unknown>>(created?.config, {}),
    });
  } catch (err: any) {
    console.error('POST /notes/providers error:', err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/notes/providers/:id
router.put('/providers/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const existing = getNotesProviderById(id);
    if (!existing) {
      res.status(404).json({ error: 'Provider not found' });
      return;
    }

    const updates: Partial<NotesProviderRow> = {};
    const { name, type, config, enabled, is_default } = req.body || {};
    if (typeof name === 'string') updates.name = name;
    if (typeof type === 'string') updates.type = type;
    if (config !== undefined) {
      updates.config = typeof config === 'string' ? config : JSON.stringify(config);
    }
    if (typeof enabled === 'boolean') updates.enabled = enabled ? 1 : 0;
    if (typeof is_default === 'boolean') updates.is_default = is_default ? 1 : 0;

    updateNotesProvider(id, updates);
    const updated = getNotesProviderById(id);
    res.json({
      id: updated?.id,
      name: updated?.name,
      type: updated?.type,
      enabled: updated?.enabled === 1,
      is_default: updated?.is_default === 1,
      config: parseJsonField<Record<string, unknown>>(updated?.config, {}),
    });
  } catch (err: any) {
    console.error(`PUT /notes/providers/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/notes/providers/:id
router.delete('/providers/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const existing = getNotesProviderById(id);
    if (!existing) {
      res.status(404).json({ error: 'Provider not found' });
      return;
    }
    deleteNotesProvider(id);
    res.status(204).send();
  } catch (err: any) {
    console.error(`DELETE /notes/providers/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/notes/providers/:id/test
router.post('/providers/:id/test', async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const row = getNotesProviderById(id);
    if (!row) {
      res.status(404).json({ error: 'Provider not found' });
      return;
    }

    try {
      const registry = await loadProviderRegistry();
      const instance = registry.getProvider(row.name);
      if (!instance) {
        res.json({ ok: false, error: `Provider '${row.name}' is not registered` });
        return;
      }
      const result = await instance.testConnection();
      res.json(result);
    } catch (innerErr: any) {
      res.json({ ok: false, error: innerErr.message });
    }
  } catch (err: any) {
    console.error(`POST /notes/providers/${req.params.id}/test error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// ── Notes search (MUST come before /:id) ──────────────────────────────────

// POST /api/notes/search
router.post('/search', async (req: Request, res: Response) => {
  try {
    const { query, project_id } = req.body || {};
    if (!query || typeof query !== 'string') {
      res.status(400).json({ error: 'query is required' });
      return;
    }

    const registry = await loadProviderRegistry();

    // Gather unique providers referenced by existing notes (filtered by project if given)
    const filters: NoteFilters = {};
    if (project_id !== undefined) filters.project_id = Number(project_id);
    const rows = getNotes(filters);
    const providerNames = Array.from(new Set(rows.map((r) => r.provider)));

    const hits: Array<{
      externalId: string;
      title: string;
      updatedAt: string;
      provider: string;
      note_id?: number;
    }> = [];

    for (const name of providerNames) {
      const instance = registry.getProvider(name);
      if (!instance) continue;
      try {
        const results = await instance.searchNotes(query);
        for (const r of results) {
          const dbRow = rows.find(
            (row) => row.provider === name && row.external_id === r.externalId
          );
          hits.push({
            externalId: r.externalId,
            title: r.title,
            updatedAt: r.updatedAt,
            provider: name,
            note_id: dbRow?.id,
          });
        }
      } catch (innerErr: any) {
        console.warn(`[notes] search failed on provider '${name}':`, innerErr.message);
      }
    }

    res.json({ data: hits, total: hits.length });
  } catch (err: any) {
    console.error('POST /notes/search error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Notes CRUD ─────────────────────────────────────────────────────────────

// GET /api/notes
router.get('/', (req: Request, res: Response) => {
  try {
    const filters: NoteFilters = {};
    if (req.query.project_id !== undefined) filters.project_id = Number(req.query.project_id);
    if (typeof req.query.type === 'string') filters.type = req.query.type;
    if (typeof req.query.status === 'string') filters.status = req.query.status;
    if (typeof req.query.tag === 'string') filters.tag = req.query.tag;
    if (req.query.finding_id !== undefined) filters.finding_id = Number(req.query.finding_id);
    if (req.query.limit !== undefined) filters.limit = Number(req.query.limit);
    if (req.query.offset !== undefined) filters.offset = Number(req.query.offset);

    const rows = getNotes(filters).map((r) => ({
      id: r.id,
      provider: r.provider,
      external_id: r.external_id,
      title: r.title,
      type: r.type || 'note',
      status: r.status || null,
      tags: parseJsonField<string[]>(r.tags, []),
      project_id: r.project_id ?? null,
      finding_ids: parseJsonField<number[]>(r.finding_ids, []),
      file_refs: parseJsonField<FileRef[]>(r.file_refs, []),
      confidence: r.confidence ?? null,
      created_at: r.created_at,
      updated_at: r.updated_at,
    }));

    res.json({ data: rows, total: rows.length });
  } catch (err: any) {
    console.error('GET /notes error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/notes
router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      title,
      content,
      type,
      status,
      project_id,
      finding_ids,
      file_refs,
      tags,
      confidence,
      provider,
    } = req.body || {};

    if (!title || typeof title !== 'string') {
      res.status(400).json({ error: 'title is required' });
      return;
    }
    if (content === undefined || content === null) {
      res.status(400).json({ error: 'content is required' });
      return;
    }

    const { providerRow, provider: providerInstance } = await resolveProvider(provider);

    const findingIdsArr: number[] = Array.isArray(finding_ids)
      ? finding_ids.map((n: any) => Number(n)).filter((n: number) => !isNaN(n))
      : [];
    const fileRefsArr: FileRef[] = Array.isArray(file_refs) ? file_refs : [];
    const tagsArr: string[] = Array.isArray(tags) ? tags : [];

    const now = new Date().toISOString();
    const meta: NoteMeta = {
      title,
      type: type || 'note',
      status,
      tags: tagsArr,
      projectId: project_id !== undefined ? Number(project_id) : undefined,
      findingIds: findingIdsArr,
      fileRefs: fileRefsArr,
      confidence: typeof confidence === 'number' ? confidence : undefined,
      createdAt: now,
      updatedAt: now,
    };

    const result = await providerInstance.createNote(meta, String(content));

    const id = createNote({
      provider: providerRow.name,
      external_id: result.externalId,
      title,
      type: type || 'note',
      status: status || undefined,
      tags: JSON.stringify(tagsArr),
      project_id: project_id !== undefined ? Number(project_id) : undefined,
      finding_ids: JSON.stringify(findingIdsArr),
      file_refs: JSON.stringify(fileRefsArr),
      confidence: typeof confidence === 'number' ? confidence : undefined,
    });

    const row = getNoteById(id);
    res.status(201).json({
      id,
      provider: row?.provider,
      external_id: row?.external_id,
      title: row?.title,
      type: row?.type || 'note',
      status: row?.status || null,
      tags: parseJsonField<string[]>(row?.tags, []),
      project_id: row?.project_id ?? null,
      finding_ids: parseJsonField<number[]>(row?.finding_ids, []),
      file_refs: parseJsonField<FileRef[]>(row?.file_refs, []),
      confidence: row?.confidence ?? null,
      created_at: row?.created_at,
      updated_at: row?.updated_at,
      content: String(content),
    });
  } catch (err: any) {
    console.error('POST /notes error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/notes/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const row = getNoteById(id);
    if (!row) {
      res.status(404).json({ error: 'Note not found' });
      return;
    }
    const hydrated = await hydrateNote(row);
    res.json(hydrated);
  } catch (err: any) {
    console.error(`GET /notes/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/notes/:id
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const row = getNoteById(id);
    if (!row) {
      res.status(404).json({ error: 'Note not found' });
      return;
    }

    const {
      title,
      content,
      type,
      status,
      project_id,
      finding_ids,
      file_refs,
      tags,
      confidence,
    } = req.body || {};

    // Build updated metadata (for provider call) from whatever the client sent,
    // falling back to existing DB values.
    const existingTags = parseJsonField<string[]>(row.tags, []);
    const existingFindingIds = parseJsonField<number[]>(row.finding_ids, []);
    const existingFileRefs = parseJsonField<FileRef[]>(row.file_refs, []);

    const newTags: string[] = Array.isArray(tags) ? tags : existingTags;
    const newFindingIds: number[] = Array.isArray(finding_ids)
      ? finding_ids.map((n: any) => Number(n)).filter((n: number) => !isNaN(n))
      : existingFindingIds;
    const newFileRefs: FileRef[] = Array.isArray(file_refs) ? file_refs : existingFileRefs;

    const newMeta: Partial<NoteMeta> = {
      title: typeof title === 'string' ? title : row.title,
      type: typeof type === 'string' ? type : row.type,
      status: typeof status === 'string' ? status : row.status,
      tags: newTags,
      projectId:
        project_id !== undefined
          ? Number(project_id)
          : row.project_id ?? undefined,
      findingIds: newFindingIds,
      fileRefs: newFileRefs,
      confidence: typeof confidence === 'number' ? confidence : row.confidence ?? undefined,
      updatedAt: new Date().toISOString(),
    };

    // If content was supplied, push the update through the provider
    if (content !== undefined && content !== null) {
      try {
        const registry = await loadProviderRegistry();
        const providerInstance = registry.getProvider(row.provider);
        if (!providerInstance) {
          throw new Error(`Notes provider '${row.provider}' is not registered`);
        }
        await providerInstance.updateNote(row.external_id, String(content), newMeta);
      } catch (innerErr: any) {
        res.status(500).json({ error: `Provider update failed: ${innerErr.message}` });
        return;
      }
    }

    // Build DB updates - only fields explicitly provided in the request
    const updates: Partial<NoteRow> = {};
    if (typeof title === 'string') updates.title = title;
    if (typeof type === 'string') updates.type = type;
    if (typeof status === 'string') updates.status = status;
    if (tags !== undefined) updates.tags = JSON.stringify(newTags);
    if (project_id !== undefined) updates.project_id = Number(project_id);
    if (finding_ids !== undefined) updates.finding_ids = JSON.stringify(newFindingIds);
    if (file_refs !== undefined) updates.file_refs = JSON.stringify(newFileRefs);
    if (typeof confidence === 'number') updates.confidence = confidence;

    if (Object.keys(updates).length > 0) {
      updateNote(id, updates);
    } else if (content !== undefined) {
      // Force updated_at to refresh even when only content changed
      updateNote(id, { title: typeof title === 'string' ? title : row.title });
    }

    const fresh = getNoteById(id);
    if (!fresh) {
      res.status(404).json({ error: 'Note not found after update' });
      return;
    }
    const hydrated = await hydrateNote(fresh);
    res.json(hydrated);
  } catch (err: any) {
    console.error(`PUT /notes/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/notes/:id
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const row = getNoteById(id);
    if (!row) {
      res.status(404).json({ error: 'Note not found' });
      return;
    }

    // Best-effort: delete from provider first, but tolerate errors
    try {
      const registry = await loadProviderRegistry();
      const providerInstance = registry.getProvider(row.provider);
      if (providerInstance) {
        await providerInstance.deleteNote(row.external_id);
      }
    } catch (innerErr: any) {
      console.warn(`[notes] provider delete failed for id=${id}:`, innerErr.message);
    }

    deleteNote(id);
    res.status(204).send();
  } catch (err: any) {
    console.error(`DELETE /notes/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/notes/:id/link
router.post('/:id/link', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const row = getNoteById(id);
    if (!row) {
      res.status(404).json({ error: 'Note not found' });
      return;
    }

    const { finding_id, file, line_start, line_end } = req.body || {};
    if (finding_id === undefined && !file) {
      res.status(400).json({ error: 'finding_id or file is required' });
      return;
    }

    const findingIds = parseJsonField<number[]>(row.finding_ids, []);
    const fileRefs = parseJsonField<FileRef[]>(row.file_refs, []);

    const updates: Partial<NoteRow> = {};

    if (finding_id !== undefined) {
      const n = Number(finding_id);
      if (isNaN(n)) {
        res.status(400).json({ error: 'finding_id must be a number' });
        return;
      }
      if (!findingIds.includes(n)) {
        findingIds.push(n);
        updates.finding_ids = JSON.stringify(findingIds);
      }
    }

    if (file && typeof file === 'string') {
      const newRef: FileRef = {
        file,
        line_start: line_start !== undefined ? Number(line_start) : undefined,
        line_end: line_end !== undefined ? Number(line_end) : undefined,
      };
      const duplicate = fileRefs.some(
        (r) =>
          r.file === newRef.file &&
          r.line_start === newRef.line_start &&
          r.line_end === newRef.line_end
      );
      if (!duplicate) {
        fileRefs.push(newRef);
        updates.file_refs = JSON.stringify(fileRefs);
      }
    }

    if (Object.keys(updates).length > 0) {
      updateNote(id, updates);
    }

    const fresh = getNoteById(id);
    res.json({
      id: fresh?.id,
      finding_ids: parseJsonField<number[]>(fresh?.finding_ids, []),
      file_refs: parseJsonField<FileRef[]>(fresh?.file_refs, []),
      updated_at: fresh?.updated_at,
    });
  } catch (err: any) {
    console.error(`POST /notes/${req.params.id}/link error:`, err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

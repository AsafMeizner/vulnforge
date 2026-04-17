/**
 * Notes Provider Interface
 *
 * All note content lives in a pluggable backend (local fs, Obsidian vault, Notion, etc.).
 * VulnForge stores metadata in SQLite but delegates read/write of markdown to the provider.
 */

export interface FileRef {
  file: string;
  line_start?: number;
  line_end?: number;
}

export interface NoteMeta {
  title: string;
  type?: string;               // note | hypothesis | observation | exploit-idea | todo
  status?: string;             // open | investigating | confirmed | disproved | obsolete
  tags?: string[];
  projectId?: number;
  findingIds?: number[];
  fileRefs?: FileRef[];
  confidence?: number;         // 0-1
  createdAt?: string;
  updatedAt?: string;
}

export interface NoteRef {
  externalId: string;
  title: string;
  updatedAt: string;
}

export interface ProviderResult {
  externalId: string;
}

export interface NoteContent {
  markdown: string;
  meta: NoteMeta;
}

export interface NotesProvider {
  readonly name: string;
  readonly type: string;

  /** Create a new note. Returns the provider-specific ID (file path, page ID, etc.). */
  createNote(meta: NoteMeta, markdown: string): Promise<ProviderResult>;

  /** Read a note's content and frontmatter-extracted meta. */
  readNote(externalId: string): Promise<NoteContent>;

  /** Update markdown and/or frontmatter. */
  updateNote(externalId: string, markdown: string, meta?: Partial<NoteMeta>): Promise<void>;

  /** Delete a note permanently. */
  deleteNote(externalId: string): Promise<void>;

  /** List notes with optional filters. Implementations may ignore filters they can't support. */
  listNotes(filter?: { tag?: string; since?: string }): Promise<NoteRef[]>;

  /** Full-text (or best-effort) search. */
  searchNotes(query: string): Promise<NoteRef[]>;

  /** Verify configuration is valid and backend is reachable. */
  testConnection(): Promise<{ ok: boolean; error?: string }>;
}

// ── Frontmatter serialization helpers ─────────────────────────────────────

/** Serialize a NoteMeta to YAML frontmatter + markdown body. */
export function buildNoteFile(meta: NoteMeta, markdown: string): string {
  const frontmatter = [
    '---',
    'vulnforge:',
    `  type: ${meta.type || 'note'}`,
    meta.status ? `  status: ${meta.status}` : null,
    meta.confidence !== undefined ? `  confidence: ${meta.confidence}` : null,
    meta.projectId !== undefined ? `  project_id: ${meta.projectId}` : null,
    meta.findingIds && meta.findingIds.length > 0 ? `  finding_ids: [${meta.findingIds.join(', ')}]` : null,
    meta.tags && meta.tags.length > 0 ? `  tags: [${meta.tags.map(t => JSON.stringify(t)).join(', ')}]` : null,
    meta.fileRefs && meta.fileRefs.length > 0 ? `  file_refs:` : null,
    ...(meta.fileRefs || []).map(r => `    - { file: ${JSON.stringify(r.file)}, line_start: ${r.line_start ?? 'null'}, line_end: ${r.line_end ?? 'null'} }`),
    `  created_at: ${meta.createdAt || new Date().toISOString()}`,
    `  updated_at: ${meta.updatedAt || new Date().toISOString()}`,
    '---',
    '',
    `# ${meta.title}`,
    '',
    markdown,
  ].filter(l => l !== null).join('\n');

  return frontmatter;
}

/** Parse a note file back into NoteMeta + markdown body. */
export function parseNoteFile(content: string): { meta: NoteMeta; markdown: string } {
  const fmMatch = content.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);

  if (!fmMatch) {
    // No frontmatter - treat whole file as markdown, title = first h1 or first line
    const titleMatch = content.match(/^#\s+(.+)$/m);
    return {
      meta: { title: titleMatch?.[1] || 'Untitled', type: 'note' },
      markdown: content,
    };
  }

  const yaml = fmMatch[1];
  const body = fmMatch[2];
  const meta: NoteMeta = { title: 'Untitled' };

  // Simple YAML parse - only handle what we wrote
  const vfBlock = yaml.match(/vulnforge:\s*\n([\s\S]+?)(?:\n[a-z]|\n*$)/i);
  const lines = (vfBlock ? vfBlock[1] : yaml).split('\n');

  for (const line of lines) {
    const m = line.match(/^\s{2,}(\w+):\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    const val = m[2].trim();

    switch (key) {
      case 'type': meta.type = val; break;
      case 'status': meta.status = val; break;
      case 'confidence': meta.confidence = parseFloat(val); break;
      case 'project_id': meta.projectId = parseInt(val); break;
      case 'created_at': meta.createdAt = val; break;
      case 'updated_at': meta.updatedAt = val; break;
      case 'finding_ids': {
        const arrMatch = val.match(/\[([^\]]*)\]/);
        if (arrMatch) {
          meta.findingIds = arrMatch[1].split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
        }
        break;
      }
      case 'tags': {
        const arrMatch = val.match(/\[([^\]]*)\]/);
        if (arrMatch) {
          meta.tags = arrMatch[1].split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
        }
        break;
      }
    }
  }

  // Extract title from first h1, or fall back to filename-like
  const titleMatch = body.match(/^#\s+(.+)$/m);
  if (titleMatch) meta.title = titleMatch[1];

  // Strip the title line from body for clean markdown
  const cleanBody = body.replace(/^#\s+.+\n+/, '');

  return { meta, markdown: cleanBody };
}

/** Sanitize a title for filesystem use. */
export function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .slice(0, 60) || 'untitled';
}

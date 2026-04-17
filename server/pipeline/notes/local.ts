/**
 * LocalNotesProvider
 *
 * Stores notes as markdown files on disk. Layout:
 *   {base_path}/project-{id}/YYYY-MM-DD-{slug}.md
 *   {base_path}/global/YYYY-MM-DD-{slug}.md
 *
 * externalId is the path relative to base_path (e.g. "project-3/2026-04-15-uaf.md").
 */

import { promises as fs } from 'fs';
import path from 'path';
import {
  NotesProvider,
  NoteMeta,
  NoteRef,
  ProviderResult,
  NoteContent,
  buildNoteFile,
  parseNoteFile,
  slugify,
} from './provider.js';

export interface LocalNotesProviderConfig {
  base_path?: string;
}

const DEFAULT_BASE_PATH = 'X:/vulnforge/data/notes';

export class LocalNotesProvider implements NotesProvider {
  readonly name: string;
  readonly type: string = 'local';
  protected basePath: string;

  constructor(config: LocalNotesProviderConfig = {}, name: string = 'local') {
    this.name = name;
    this.basePath = path.resolve(config.base_path || DEFAULT_BASE_PATH);
  }

  // ── Path helpers ────────────────────────────────────────────────────────

  /** Directory where notes for a given project (or globals) live. */
  protected bucketDir(projectId?: number): string {
    const bucket = projectId !== undefined && projectId !== null
      ? `project-${projectId}`
      : 'global';
    return path.join(this.basePath, bucket);
  }

  /** Build a filename from a title - YYYY-MM-DD-{slug}.md. */
  protected buildFilename(title: string, createdAt?: string): string {
    const d = createdAt ? new Date(createdAt) : new Date();
    const iso = isNaN(d.getTime()) ? new Date() : d;
    const yyyy = iso.getFullYear();
    const mm = String(iso.getMonth() + 1).padStart(2, '0');
    const dd = String(iso.getDate()).padStart(2, '0');
    return `${yyyy}-${mm}-${dd}-${slugify(title)}.md`;
  }

  /** Turn an externalId (relative path) into an absolute filesystem path. */
  protected absPath(externalId: string): string {
    // Normalize forward/back slashes and strip any leading separators to keep it under basePath.
    const rel = externalId.replace(/\\/g, '/').replace(/^\/+/, '');
    return path.join(this.basePath, rel);
  }

  /** Ensure a directory exists. */
  protected async ensureDir(dir: string): Promise<void> {
    await fs.mkdir(dir, { recursive: true });
  }

  /** Walk a directory recursively and return absolute paths of all `.md` files. */
  protected async walkMarkdown(root: string): Promise<string[]> {
    const out: string[] = [];

    async function walk(dir: string): Promise<void> {
      let entries: import('fs').Dirent[];
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch (err: any) {
        if (err?.code === 'ENOENT') return;
        throw err;
      }

      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(full);
        } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
          out.push(full);
        }
      }
    }

    await walk(root);
    return out;
  }

  /** Convert an absolute path back to an externalId relative to basePath. */
  protected toExternalId(absFile: string): string {
    const rel = path.relative(this.basePath, absFile);
    return rel.replace(/\\/g, '/');
  }

  // ── NotesProvider API ──────────────────────────────────────────────────

  async createNote(meta: NoteMeta, markdown: string): Promise<ProviderResult> {
    const dir = this.bucketDir(meta.projectId);
    await this.ensureDir(dir);

    const filename = this.buildFilename(meta.title, meta.createdAt);
    const absFile = path.join(dir, filename);

    const now = new Date().toISOString();
    const merged: NoteMeta = {
      ...meta,
      createdAt: meta.createdAt || now,
      updatedAt: now,
    };

    const content = buildNoteFile(merged, markdown);
    await fs.writeFile(absFile, content, 'utf8');

    return { externalId: this.toExternalId(absFile) };
  }

  async readNote(externalId: string): Promise<NoteContent> {
    const absFile = this.absPath(externalId);
    let raw: string;
    try {
      raw = await fs.readFile(absFile, 'utf8');
    } catch (err: any) {
      if (err?.code === 'ENOENT') {
        throw new Error(`Note not found: ${externalId}`);
      }
      throw err;
    }
    const parsed = parseNoteFile(raw);
    return { markdown: parsed.markdown, meta: parsed.meta };
  }

  async updateNote(externalId: string, markdown: string, meta: Partial<NoteMeta> = {}): Promise<void> {
    const absFile = this.absPath(externalId);

    let existing: { meta: NoteMeta; markdown: string };
    try {
      const raw = await fs.readFile(absFile, 'utf8');
      existing = parseNoteFile(raw);
    } catch (err: any) {
      if (err?.code === 'ENOENT') {
        throw new Error(`Note not found: ${externalId}`);
      }
      throw err;
    }

    const mergedMeta: NoteMeta = {
      ...existing.meta,
      ...meta,
      // Title can be explicitly overridden; fall back to existing.
      title: meta.title ?? existing.meta.title,
      createdAt: existing.meta.createdAt,
      updatedAt: new Date().toISOString(),
    };

    const content = buildNoteFile(mergedMeta, markdown);
    await fs.writeFile(absFile, content, 'utf8');
  }

  async deleteNote(externalId: string): Promise<void> {
    const absFile = this.absPath(externalId);
    try {
      await fs.unlink(absFile);
    } catch (err: any) {
      if (err?.code === 'ENOENT') return; // idempotent delete
      throw err;
    }
  }

  async listNotes(filter: { tag?: string; since?: string } = {}): Promise<NoteRef[]> {
    const files = await this.walkMarkdown(this.basePath);
    const sinceDate = filter.since ? new Date(filter.since) : null;
    const out: NoteRef[] = [];

    for (const absFile of files) {
      let raw: string;
      try {
        raw = await fs.readFile(absFile, 'utf8');
      } catch {
        continue;
      }
      const { meta } = parseNoteFile(raw);

      if (filter.tag) {
        if (!meta.tags || !meta.tags.includes(filter.tag)) continue;
      }

      const updatedAt = meta.updatedAt || meta.createdAt || '';
      if (sinceDate && updatedAt) {
        const ua = new Date(updatedAt);
        if (!isNaN(ua.getTime()) && ua < sinceDate) continue;
      }

      out.push({
        externalId: this.toExternalId(absFile),
        title: meta.title || path.basename(absFile, '.md'),
        updatedAt: updatedAt || '',
      });
    }

    out.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
    return out;
  }

  async searchNotes(query: string): Promise<NoteRef[]> {
    const needle = (query || '').toLowerCase();
    if (!needle) return this.listNotes();

    const files = await this.walkMarkdown(this.basePath);
    const out: NoteRef[] = [];

    for (const absFile of files) {
      let raw: string;
      try {
        raw = await fs.readFile(absFile, 'utf8');
      } catch {
        continue;
      }

      const { meta, markdown } = parseNoteFile(raw);
      const title = meta.title || '';
      const hay = `${title}\n${markdown}`.toLowerCase();

      if (hay.includes(needle)) {
        out.push({
          externalId: this.toExternalId(absFile),
          title: title || path.basename(absFile, '.md'),
          updatedAt: meta.updatedAt || meta.createdAt || '',
        });
      }
    }

    out.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
    return out;
  }

  async testConnection(): Promise<{ ok: boolean; error?: string }> {
    try {
      // mkdir -p to create base_path if missing.
      await this.ensureDir(this.basePath);

      // Probe writability with a temp file.
      const probe = path.join(this.basePath, `.vf-probe-${Date.now()}`);
      await fs.writeFile(probe, 'probe', 'utf8');
      await fs.unlink(probe);

      return { ok: true };
    } catch (err: any) {
      return {
        ok: false,
        error: `LocalNotesProvider at "${this.basePath}": ${err?.message || String(err)}`,
      };
    }
  }
}

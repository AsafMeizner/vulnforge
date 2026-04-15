/**
 * Notes provider registry / factory.
 *
 * Loads provider rows from the `notes_providers` table and constructs the
 * matching NotesProvider implementation. Instances are cached by name so
 * repeated calls don't re-parse config or re-initialize filesystem state.
 *
 * Callers should invoke `clearProviderCache(name?)` whenever a provider row
 * is updated or deleted to force a fresh load on the next `getProvider` call.
 */

import { getNotesProviderByName, getDefaultNotesProvider } from '../../db.js';
import type { NotesProvider } from './provider.js';
import { LocalNotesProvider } from './local.js';
import { ObsidianNotesProvider } from './obsidian.js';

// ── Cache ────────────────────────────────────────────────────────────────

const providerCache = new Map<string, NotesProvider>();

/**
 * Clear one cached provider (by name) or the entire cache if no name given.
 * Call this after mutating a `notes_providers` row.
 */
export function clearProviderCache(name?: string): void {
  if (name === undefined) {
    providerCache.clear();
    return;
  }
  providerCache.delete(name);
}

// ── Factory ─────────────────────────────────────────────────────────────

/**
 * Construct a NotesProvider for a given type + config. Used internally by
 * `getProvider` / `getDefaultProvider` and exported for tests that want to
 * instantiate a provider directly without touching the database.
 */
export function createProviderInstance(type: string, config: any, name?: string): NotesProvider {
  const safeConfig = config && typeof config === 'object' ? config : {};

  switch (type) {
    case 'local':
      return new LocalNotesProvider(safeConfig, name ?? 'local');

    case 'obsidian':
      return new ObsidianNotesProvider(safeConfig, name ?? 'obsidian');

    default:
      throw new Error(`Unknown provider type: ${type}`);
  }
}

// ── DB-backed loaders ───────────────────────────────────────────────────

/** Parse a provider row's config JSON, tolerating invalid/missing values. */
function parseConfig(raw: string | undefined | null): any {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Resolve a NotesProvider by its row name. Caches the instance after first
 * construction. Throws if no row exists or the provider row is disabled.
 */
export async function getProvider(name: string): Promise<NotesProvider> {
  const cached = providerCache.get(name);
  if (cached) return cached;

  const row = getNotesProviderByName(name);
  if (!row) {
    throw new Error(`No notes provider registered with name: ${name}`);
  }
  if (row.enabled !== undefined && row.enabled !== null && Number(row.enabled) === 0) {
    throw new Error(`Notes provider "${name}" is disabled`);
  }

  const config = parseConfig(row.config);
  const instance = createProviderInstance(row.type, config, row.name);

  providerCache.set(name, instance);
  return instance;
}

/**
 * Resolve the default NotesProvider (the row with is_default=1 and enabled=1).
 * Caches under its row name. Throws if no default is configured.
 */
export async function getDefaultProvider(): Promise<NotesProvider> {
  const row = getDefaultNotesProvider();
  if (!row) {
    throw new Error('No default notes provider configured');
  }

  const cached = providerCache.get(row.name);
  if (cached) return cached;

  const config = parseConfig(row.config);
  const instance = createProviderInstance(row.type, config, row.name);

  providerCache.set(row.name, instance);
  return instance;
}

// Re-export the provider classes so callers can import everything from
// `./notes/index.js` if they prefer the barrel style.
export { LocalNotesProvider } from './local.js';
export { ObsidianNotesProvider } from './obsidian.js';
export type {
  NotesProvider,
  NoteMeta,
  NoteRef,
  NoteContent,
  ProviderResult,
  FileRef,
} from './provider.js';

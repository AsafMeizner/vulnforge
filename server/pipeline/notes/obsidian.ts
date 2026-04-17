/**
 * ObsidianNotesProvider
 *
 * Stores notes as markdown files inside an Obsidian vault.
 * Layout:
 *   {vault_path}/{subfolder}/project-{id}/*.md
 *   {vault_path}/{subfolder}/global/*.md
 *
 * Detection: a directory is treated as a vault iff it contains a ".obsidian/"
 * sub-directory. Notes are scoped to {subfolder} (default "VulnForge") so we
 * never walk the user's entire vault when listing.
 */

import { promises as fs } from 'fs';
import path from 'path';
import { LocalNotesProvider } from './local.js';

export interface ObsidianNotesProviderConfig {
  vault_path: string;
  subfolder?: string;
}

const DEFAULT_SUBFOLDER = 'VulnForge';

export class ObsidianNotesProvider extends LocalNotesProvider {
  protected vaultPath: string;
  protected subfolder: string;

  constructor(config: ObsidianNotesProviderConfig, name: string = 'obsidian') {
    if (!config || !config.vault_path) {
      throw new Error('ObsidianNotesProvider requires config.vault_path');
    }

    const subfolder = config.subfolder?.trim() || DEFAULT_SUBFOLDER;
    const vaultPath = path.resolve(config.vault_path);
    const notesRoot = path.join(vaultPath, subfolder);

    // Seed the Local base_path with the vault's VulnForge subfolder so all
    // inherited path/walk/read/write logic Just Works.
    super({ base_path: notesRoot }, name);

    // Override the inherited type string in-place. TypeScript allows writing
    // to a readonly field from within a subclass constructor.
    (this as { type: string }).type = 'obsidian';

    this.vaultPath = vaultPath;
    this.subfolder = subfolder;
  }

  /** Verify the vault directory exists and looks like an Obsidian vault. */
  async testConnection(): Promise<{ ok: boolean; error?: string }> {
    try {
      let vaultStat: import('fs').Stats;
      try {
        vaultStat = await fs.stat(this.vaultPath);
      } catch (err: any) {
        if (err?.code === 'ENOENT') {
          return {
            ok: false,
            error: `Obsidian vault path does not exist: ${this.vaultPath}`,
          };
        }
        throw err;
      }

      if (!vaultStat.isDirectory()) {
        return {
          ok: false,
          error: `Obsidian vault path is not a directory: ${this.vaultPath}`,
        };
      }

      // Obsidian vaults are identified by the presence of a `.obsidian/` dir.
      const markerPath = path.join(this.vaultPath, '.obsidian');
      try {
        const markerStat = await fs.stat(markerPath);
        if (!markerStat.isDirectory()) {
          return {
            ok: false,
            error: `Path does not appear to be an Obsidian vault (missing .obsidian directory): ${this.vaultPath}`,
          };
        }
      } catch (err: any) {
        if (err?.code === 'ENOENT') {
          return {
            ok: false,
            error: `Path does not appear to be an Obsidian vault (missing .obsidian directory): ${this.vaultPath}`,
          };
        }
        throw err;
      }

      // Ensure our subfolder exists and is writable - create it if missing.
      await fs.mkdir(this.basePath, { recursive: true });

      const probe = path.join(this.basePath, `.vf-probe-${Date.now()}`);
      await fs.writeFile(probe, 'probe', 'utf8');
      await fs.unlink(probe);

      return { ok: true };
    } catch (err: any) {
      return {
        ok: false,
        error: `ObsidianNotesProvider at "${this.vaultPath}" (subfolder: ${this.subfolder}): ${err?.message || String(err)}`,
      };
    }
  }
}

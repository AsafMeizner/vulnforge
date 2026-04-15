/**
 * Checklist loader — reads JSON files from the project-root /checklists/
 * directory and upserts them into the database.
 */
import { readFileSync, readdirSync, existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import {
  getAllChecklists,
  createChecklist,
  getChecklistItems,
  createChecklistItem,
  type Checklist,
  type ChecklistItem,
} from '../db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CHECKLISTS_DIR = path.resolve(__dirname, '..', '..', 'checklists');

// ── JSON schema for a checklist file ─────────────────────────────────────────

interface ChecklistJson {
  name: string;
  source_url?: string;
  category?: string;
  items: Array<{
    category?: string;
    title: string;
    description?: string;
    severity?: string;
    tool_names?: string;
  }>;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseChecklistFile(filePath: string): ChecklistJson | null {
  try {
    const raw = readFileSync(filePath, { encoding: 'utf8' });
    const parsed = JSON.parse(raw) as ChecklistJson;
    if (!parsed.name || !Array.isArray(parsed.items)) {
      console.warn(`[ChecklistLoader] Skipping ${filePath}: missing name or items array`);
      return null;
    }
    return parsed;
  } catch (err: any) {
    console.error(`[ChecklistLoader] Failed to parse ${filePath}: ${err.message}`);
    return null;
  }
}

/**
 * Load all *.json files from the checklists directory into the database.
 * Skips any checklist whose name already exists in the DB to avoid duplication.
 * Returns the number of checklists newly inserted.
 */
export async function loadAllChecklists(): Promise<number> {
  if (!existsSync(CHECKLISTS_DIR)) {
    console.warn(`[ChecklistLoader] Checklists directory not found: ${CHECKLISTS_DIR}`);
    return 0;
  }

  const files = readdirSync(CHECKLISTS_DIR).filter(f => f.endsWith('.json'));
  if (files.length === 0) {
    console.log('[ChecklistLoader] No checklist JSON files found');
    return 0;
  }

  // Build a set of already-loaded checklist names for duplicate detection
  const existing = getAllChecklists();
  const existingNames = new Set(existing.map(c => c.name.toLowerCase()));

  let inserted = 0;

  for (const file of files) {
    const filePath = path.join(CHECKLISTS_DIR, file);
    const data = parseChecklistFile(filePath);
    if (!data) continue;

    if (existingNames.has(data.name.toLowerCase())) {
      console.log(`[ChecklistLoader] "${data.name}" already loaded, skipping`);
      continue;
    }

    const checklistId = createChecklist({
      name: data.name,
      source_url: data.source_url,
      category: data.category,
      total_items: data.items.length,
    });

    for (const item of data.items) {
      createChecklistItem({
        checklist_id: checklistId,
        category: item.category,
        title: item.title,
        description: item.description,
        severity: item.severity,
        tool_names: item.tool_names,
        verified: 0,
      });
    }

    console.log(`[ChecklistLoader] Loaded "${data.name}" (${data.items.length} items)`);
    existingNames.add(data.name.toLowerCase());
    inserted++;
  }

  console.log(`[ChecklistLoader] Done — ${inserted} new checklists loaded`);
  return inserted;
}

/**
 * Load a single checklist file by path.
 * Returns the newly created checklist ID, or null if it was already present.
 */
export function loadChecklistFile(filePath: string): number | null {
  const data = parseChecklistFile(filePath);
  if (!data) return null;

  const existing = getAllChecklists();
  const dupe = existing.find(c => c.name.toLowerCase() === data.name.toLowerCase());
  if (dupe) {
    console.log(`[ChecklistLoader] "${data.name}" already exists (id=${dupe.id})`);
    return null;
  }

  const checklistId = createChecklist({
    name: data.name,
    source_url: data.source_url,
    category: data.category,
    total_items: data.items.length,
  });

  for (const item of data.items) {
    createChecklistItem({
      checklist_id: checklistId,
      category: item.category,
      title: item.title,
      description: item.description,
      severity: item.severity,
      tool_names: item.tool_names,
      verified: 0,
    });
  }

  console.log(`[ChecklistLoader] Loaded "${data.name}" (id=${checklistId})`);
  return checklistId;
}

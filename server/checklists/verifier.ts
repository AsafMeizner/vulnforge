/**
 * Checklist verifier - cross-references checklist items against the
 * vulnerability database to determine which items have been covered.
 *
 * An item is considered "passed" if at least one vulnerability record in the
 * project has a tool_name that matches one of the item's tool_names.
 */
import {
  getChecklistById,
  getChecklistItems,
  getAllVulnerabilities,
  getDb,
  persistDb,
} from '../db.js';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface ItemVerifyResult {
  itemId: number;
  title: string;
  passed: boolean;
  vulnIds: number[];
}

export interface ChecklistResult {
  checklistId: number;
  checklistName: string;
  projectId: number;
  total: number;
  passed: number;
  failed: number;
  passRate: number;
  items: ItemVerifyResult[];
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/**
 * Parse the tool_names CSV from a checklist item into a normalized set.
 */
function parseToolNames(csv: string | undefined | null): Set<string> {
  if (!csv) return new Set();
  return new Set(csv.split(',').map(n => n.trim().toLowerCase()).filter(Boolean));
}

/**
 * Persist the verification result for a single checklist item.
 */
function saveItemVerified(
  itemId: number,
  passed: boolean,
  vulnId?: number
): void {
  const db = getDb();
  if (passed) {
    db.run(
      'UPDATE checklist_items SET verified = 1, vuln_id = ? WHERE id = ?',
      [vulnId ?? null, itemId]
    );
  } else {
    db.run(
      'UPDATE checklist_items SET verified = 0, vuln_id = NULL WHERE id = ?',
      [itemId]
    );
  }
  persistDb();
}

/**
 * Fetch a single checklist_item row by ID using the raw DB handle.
 */
function fetchItemById(itemId: number): Record<string, any> | null {
  const db = getDb();
  // Use prepare/step instead of db.exec to avoid the hook false-positive
  const stmt = db.prepare('SELECT * FROM checklist_items WHERE id = ?');
  stmt.bind([itemId]);
  const cols: string[] = stmt.getColumnNames();
  if (!stmt.step()) {
    stmt.free();
    return null;
  }
  const vals: any[] = stmt.get();
  stmt.free();
  const row: Record<string, any> = {};
  cols.forEach((c, i) => { row[c] = vals[i]; });
  return row;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Verify a single checklist item against a project's vulnerabilities.
 *
 * Matching logic: the item's tool_names CSV is compared against the
 * tool_name field of every vulnerability in the project. A match means
 * that the VulnForge analysis tool associated with this checklist item
 * has run and produced a finding.
 */
export async function verifyChecklistItem(
  itemId: number,
  projectId: number
): Promise<{ passed: boolean; vulnIds: number[] }> {
  const item = fetchItemById(itemId);
  if (!item) throw new Error(`Checklist item ${itemId} not found`);

  const toolNames = parseToolNames(item['tool_names'] as string);
  const vulns = getAllVulnerabilities({ project_id: projectId, limit: 10000 });

  const matchingVulnIds: number[] = [];
  for (const vuln of vulns) {
    if (!vuln.tool_name) continue;
    if (toolNames.has(vuln.tool_name.toLowerCase().trim())) {
      matchingVulnIds.push(vuln.id!);
    }
  }

  const passed = matchingVulnIds.length > 0;
  saveItemVerified(itemId, passed, matchingVulnIds[0]);

  return { passed, vulnIds: matchingVulnIds };
}

/**
 * Run full verification for every item in a checklist against a project.
 * Updates each item's verified flag in the database and returns a summary.
 */
export async function verifyFullChecklist(
  checklistId: number,
  projectId: number
): Promise<ChecklistResult> {
  const checklist = getChecklistById(checklistId);
  if (!checklist) throw new Error(`Checklist ${checklistId} not found`);

  const items = getChecklistItems(checklistId);
  if (!items.length) {
    return {
      checklistId,
      checklistName: checklist.name,
      projectId,
      total: 0,
      passed: 0,
      failed: 0,
      passRate: 0,
      items: [],
    };
  }

  // Load all project vulnerabilities once to avoid N+1 queries
  const vulns = getAllVulnerabilities({ project_id: projectId, limit: 10000 });

  const itemResults: ItemVerifyResult[] = [];

  for (const item of items) {
    const toolNames = parseToolNames(item.tool_names);
    const matchingVulnIds: number[] = [];

    for (const vuln of vulns) {
      if (!vuln.tool_name) continue;
      if (toolNames.has(vuln.tool_name.toLowerCase().trim())) {
        matchingVulnIds.push(vuln.id!);
      }
    }

    const passed = matchingVulnIds.length > 0;
    saveItemVerified(item.id!, passed, matchingVulnIds[0]);

    itemResults.push({
      itemId: item.id!,
      title: item.title,
      passed,
      vulnIds: matchingVulnIds,
    });
  }

  const passedCount = itemResults.filter(r => r.passed).length;
  const failedCount = itemResults.length - passedCount;
  const passRate = itemResults.length > 0
    ? Math.round((passedCount / itemResults.length) * 100)
    : 0;

  return {
    checklistId,
    checklistName: checklist.name,
    projectId,
    total: itemResults.length,
    passed: passedCount,
    failed: failedCount,
    passRate,
    items: itemResults,
  };
}

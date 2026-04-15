import { Router, Request, Response } from 'express';
import {
  getAllChecklists,
  getChecklistById,
  getChecklistItems,
  getDb,
  persistDb,
} from '../db.js';
import {
  verifyChecklistItem,
  verifyFullChecklist,
} from '../checklists/verifier.js';

const router = Router();

// ── GET /api/checklists ───────────────────────────────────────────────────────
// Returns all checklists with progress statistics.

router.get('/', (_req: Request, res: Response) => {
  try {
    const checklists = getAllChecklists();

    const enriched = checklists.map(cl => {
      const items = getChecklistItems(cl.id!);
      const verifiedCount = items.filter(i => i.verified).length;
      return {
        ...cl,
        total_items: items.length,
        verified_count: verifiedCount,
        progress_pct: items.length > 0
          ? Math.round((verifiedCount / items.length) * 100)
          : 0,
      };
    });

    res.json({ data: enriched, total: enriched.length });
  } catch (err: any) {
    console.error('[GET /checklists] error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/checklists/:id ───────────────────────────────────────────────────
// Returns a single checklist with all items and their verification status.

router.get('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid checklist ID' });
      return;
    }

    const checklist = getChecklistById(id);
    if (!checklist) {
      res.status(404).json({ error: `Checklist ${id} not found` });
      return;
    }

    const items = getChecklistItems(id);
    const verifiedCount = items.filter(i => i.verified).length;

    res.json({
      ...checklist,
      total_items: items.length,
      verified_count: verifiedCount,
      progress_pct: items.length > 0
        ? Math.round((verifiedCount / items.length) * 100)
        : 0,
      items,
    });
  } catch (err: any) {
    console.error(`[GET /checklists/${req.params.id}] error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/checklists/:id/verify ──────────────────────────────────────────
// Run automated verification of all items against a project's findings.
// Body: { project_id: number }

router.post('/:id/verify', async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid checklist ID' });
      return;
    }

    const { project_id } = req.body as { project_id?: number };
    if (!project_id || isNaN(Number(project_id))) {
      res.status(400).json({ error: 'project_id (number) is required' });
      return;
    }

    const checklist = getChecklistById(id);
    if (!checklist) {
      res.status(404).json({ error: `Checklist ${id} not found` });
      return;
    }

    const result = await verifyFullChecklist(id, Number(project_id));
    res.json(result);
  } catch (err: any) {
    console.error(`[POST /checklists/${req.params.id}/verify] error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /api/checklists/items/:id ─────────────────────────────────────────────
// Manually update a checklist item's status (verified, notes, vuln_id).

router.put('/items/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid item ID' });
      return;
    }

    const allowedFields = ['verified', 'vuln_id', 'notes', 'severity'];
    const updates = req.body as Record<string, any>;

    const fields: string[] = [];
    const values: any[] = [];

    for (const key of allowedFields) {
      if (key in updates) {
        fields.push(`${key} = ?`);
        values.push(updates[key]);
      }
    }

    if (fields.length === 0) {
      res.status(400).json({ error: 'No valid fields to update' });
      return;
    }

    const db = getDb();
    // Verify the item exists first
    const checkStmt = db.prepare('SELECT id FROM checklist_items WHERE id = ?');
    checkStmt.bind([id]);
    const exists = checkStmt.step();
    checkStmt.free();

    if (!exists) {
      res.status(404).json({ error: `Checklist item ${id} not found` });
      return;
    }

    db.run(
      `UPDATE checklist_items SET ${fields.join(', ')} WHERE id = ?`,
      [...values, id]
    );
    persistDb();

    // Return the updated item
    const stmt = db.prepare('SELECT * FROM checklist_items WHERE id = ?');
    stmt.bind([id]);
    const cols: string[] = stmt.getColumnNames();
    stmt.step();
    const vals: any[] = stmt.get();
    stmt.free();

    const item: Record<string, any> = {};
    cols.forEach((c, i) => { item[c] = vals[i]; });

    res.json(item);
  } catch (err: any) {
    console.error(`[PUT /checklists/items/${req.params.id}] error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/checklists/items/:id/verify ─────────────────────────────────────
// Verify a single item against a project.
// Body: { project_id: number }

router.post('/items/:id/verify', async (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid item ID' });
      return;
    }

    const { project_id } = req.body as { project_id?: number };
    if (!project_id || isNaN(Number(project_id))) {
      res.status(400).json({ error: 'project_id (number) is required' });
      return;
    }

    const result = await verifyChecklistItem(id, Number(project_id));
    res.json({ itemId: id, ...result });
  } catch (err: any) {
    console.error(`[POST /checklists/items/${req.params.id}/verify] error:`, err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

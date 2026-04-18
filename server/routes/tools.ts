import { Router, Request, Response } from 'express';
import { getAllTools, getToolById, updateTool, deleteTool } from '../db.js';
import { listAllDescriptions, describeTool } from '../lib/tool-descriptions.js';

const router = Router();

// GET /api/tools/descriptions - returns the canonical
// tool_name -> one-sentence description map. Used by Review + Findings
// cards to tell users what class of issue each scanner looks for.
// Must be declared BEFORE `/:id` so Express doesn't try to parse
// "descriptions" as a numeric tool ID.
router.get('/descriptions', (_req: Request, res: Response) => {
  try {
    const map = listAllDescriptions();
    res.json({ data: map, total: Object.keys(map).length });
  } catch (err: any) {
    console.error('GET /tools/descriptions error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/tools/describe?name=<tool_name> - single-tool lookup with
// the resolver's fuzzy-matching (prefix / dash-to-underscore).
router.get('/describe', (req: Request, res: Response) => {
  const name = String(req.query.name || '').trim();
  if (!name) { res.status(400).json({ error: 'name required' }); return; }
  res.json({ name, description: describeTool(name) });
});

// GET /api/tools
router.get('/', (_req: Request, res: Response) => {
  try {
    const tools = getAllTools();
    res.json({ data: tools, total: tools.length });
  } catch (err: any) {
    console.error('GET /tools error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/tools/:id
router.get('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid ID' });
      return;
    }
    const tool = getToolById(id);
    if (!tool) {
      res.status(404).json({ error: 'Tool not found' });
      return;
    }
    res.json(tool);
  } catch (err: any) {
    console.error(`GET /tools/${req.params.id} error:`, err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/tools/:id - primarily for the Enable/Disable toggle.
// Accepts any subset of { enabled, name, category, description,
// docs, track_record, file_path, config_schema }.
router.put('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }
    const existing = getToolById(id);
    if (!existing) { res.status(404).json({ error: 'Tool not found' }); return; }
    updateTool(id, req.body || {});
    res.json(getToolById(id));
  } catch (err: any) {
    console.error('PUT /tools/:id error:', err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/tools/:id - removes the row but leaves the .py file on
// disk. Use the seed process or a re-scan to pick it back up if you
// didn't mean it.
router.delete('/:id', (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: 'Invalid ID' }); return; }
    const existing = getToolById(id);
    if (!existing) { res.status(404).json({ error: 'Tool not found' }); return; }
    deleteTool(id);
    res.status(204).send();
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;

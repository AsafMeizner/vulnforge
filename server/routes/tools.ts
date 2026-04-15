import { Router, Request, Response } from 'express';
import { getAllTools, getToolById } from '../db.js';

const router = Router();

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

export default router;

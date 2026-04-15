import { Router, Request, Response } from 'express';
import { getStats } from '../db.js';

const router = Router();

// GET /api/stats
router.get('/', (_req: Request, res: Response) => {
  try {
    const stats = getStats();
    res.json(stats);
  } catch (err: any) {
    console.error('GET /stats error:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

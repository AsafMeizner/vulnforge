import { Router, Request, Response, NextFunction } from 'express';
import { getStats } from '../db.js';

const router = Router();

// GET /api/stats
router.get('/', (_req: Request, res: Response, next: NextFunction) => {
  try {
    const stats = getStats();
    res.json(stats);
  } catch (err: any) {
    console.error('GET /stats error:', err);
    next(err);
  }
});

export default router;

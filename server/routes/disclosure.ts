import { Router, type Request, type Response, NextFunction } from 'express';
import {
  getVendors,
  getVendorById,
  createVendor,
  updateVendor,
  deleteVendor,
  getDisclosures,
  getDisclosureById,
  createDisclosure,
  updateDisclosure,
  deleteDisclosure,
  getDisclosureEvents,
  createDisclosureEvent,
} from '../db.js';

const router = Router();

// ── Vendors ──────────────────────────────────────────────────────────────

router.get('/vendors', (_req: Request, res: Response, next: NextFunction) => {
  try {
    const data = getVendors();
    res.json({ data, total: data.length });
  } catch (err: any) { next(err); }
});

router.get('/vendors/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const v = getVendorById(Number(req.params.id));
    if (!v) { res.status(404).json({ error: 'vendor not found' }); return; }
    res.json(v);
  } catch (err: any) { next(err); }
});

router.post('/vendors', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { name } = req.body;
    if (!name) { res.status(400).json({ error: 'name required' }); return; }
    const id = createVendor(req.body);
    res.status(201).json(getVendorById(id));
  } catch (err: any) { next(err); }
});

router.put('/vendors/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    updateVendor(Number(req.params.id), req.body);
    res.json(getVendorById(Number(req.params.id)));
  } catch (err: any) { next(err); }
});

router.delete('/vendors/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    deleteVendor(Number(req.params.id));
    res.json({ deleted: true });
  } catch (err: any) { next(err); }
});

// ── Disclosures ──────────────────────────────────────────────────────────

router.get('/', (req: Request, res: Response, next: NextFunction) => {
  try {
    const filters: any = {};
    if (req.query.status) filters.status = String(req.query.status);
    if (req.query.vendor_id) filters.vendor_id = Number(req.query.vendor_id);
    if (req.query.finding_id) filters.finding_id = Number(req.query.finding_id);
    const data = getDisclosures(filters);

    // Compute SLA warnings for each disclosure
    const now = Date.now();
    const enriched = data.map(d => {
      let sla_deadline: string | null = null;
      let sla_days_remaining: number | null = null;
      let sla_status: 'on_track' | 'warning' | 'overdue' | 'n_a' = 'n_a';

      if (d.submission_date && d.status !== 'resolved' && d.status !== 'public' && d.status !== 'cancelled') {
        const submitted = new Date(d.submission_date).getTime();
        const deadline = submitted + (d.sla_days || 90) * 86400 * 1000;
        sla_deadline = new Date(deadline).toISOString();
        sla_days_remaining = Math.round((deadline - now) / (86400 * 1000));
        if (sla_days_remaining < 0) sla_status = 'overdue';
        else if (sla_days_remaining < 14) sla_status = 'warning';
        else sla_status = 'on_track';
      }
      return { ...d, sla_deadline, sla_days_remaining, sla_status };
    });

    res.json({ data: enriched, total: enriched.length });
  } catch (err: any) { next(err); }
});

router.get('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const d = getDisclosureById(Number(req.params.id));
    if (!d) { res.status(404).json({ error: 'disclosure not found' }); return; }
    const events = getDisclosureEvents(Number(req.params.id));
    const vendor = d.vendor_id ? getVendorById(d.vendor_id) : null;
    res.json({ ...d, events, vendor });
  } catch (err: any) { next(err); }
});

router.post('/', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { title } = req.body;
    if (!title) { res.status(400).json({ error: 'title required' }); return; }
    const id = createDisclosure(req.body);
    res.status(201).json(getDisclosureById(id));
  } catch (err: any) { next(err); }
});

router.put('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    const existing = getDisclosureById(id);
    if (!existing) { res.status(404).json({ error: 'not found' }); return; }

    // If status changed, emit a disclosure event
    if (req.body.status && req.body.status !== existing.status) {
      createDisclosureEvent({
        disclosure_id: id,
        event_type: req.body.status,
        actor: req.body.actor || 'user',
        description: req.body.status_note || `Status changed to ${req.body.status}`,
      });
    }
    updateDisclosure(id, req.body);
    res.json(getDisclosureById(id));
  } catch (err: any) { next(err); }
});

router.delete('/:id', (req: Request, res: Response, next: NextFunction) => {
  try {
    deleteDisclosure(Number(req.params.id));
    res.json({ deleted: true });
  } catch (err: any) { next(err); }
});

router.post('/:id/events', (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = createDisclosureEvent({
      disclosure_id: Number(req.params.id),
      event_type: req.body.event_type,
      actor: req.body.actor,
      description: req.body.description,
    });
    res.status(201).json({ id });
  } catch (err: any) { next(err); }
});

// ── Analytics ────────────────────────────────────────────────────────────

router.get('/analytics/summary', (_req: Request, res: Response, next: NextFunction) => {
  try {
    const all = getDisclosures();
    const byStatus: Record<string, number> = {};
    let totalBounty = 0;
    let bountyCount = 0;

    for (const d of all) {
      byStatus[d.status || 'draft'] = (byStatus[d.status || 'draft'] || 0) + 1;
      if (d.bounty_amount) {
        totalBounty += d.bounty_amount;
        bountyCount++;
      }
    }

    res.json({
      total_disclosures: all.length,
      by_status: byStatus,
      total_bounty_usd: Math.round(totalBounty),
      bounty_count: bountyCount,
      average_bounty_usd: bountyCount > 0 ? Math.round(totalBounty / bountyCount) : 0,
    });
  } catch (err: any) { next(err); }
});

export default router;

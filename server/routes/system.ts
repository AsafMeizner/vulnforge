/**
 * /api/system/* - read-only host introspection routes.
 *
 * Intentionally small. Today this exposes `network-interfaces` so the
 * Runtime Packet-Capture form can populate its "Interface" field with
 * a dropdown of real NICs instead of a blind text box. Add more
 * diagnostics here (CPU arch, disk free, GPU presence) as the UI
 * needs them.
 */
import { Router, type Request, type Response } from 'express';
import os from 'os';

const router = Router();

/**
 * GET /api/system/network-interfaces
 *
 * Returns [{ name, addresses: string[], family: 'IPv4'|'IPv6'|'mixed', internal: boolean }, ...]
 * de-duplicated by interface name. `any` and `lo`/`loopback` are
 * appended last so the dropdown has a sensible order for capture tools.
 */
router.get('/network-interfaces', (_req: Request, res: Response) => {
  try {
    const raw = os.networkInterfaces();
    const out: Array<{
      name: string;
      addresses: string[];
      family: 'IPv4' | 'IPv6' | 'mixed';
      internal: boolean;
    }> = [];

    for (const [name, addrs] of Object.entries(raw)) {
      if (!addrs || addrs.length === 0) continue;
      const families = new Set(addrs.map((a) => a.family));
      const family: 'IPv4' | 'IPv6' | 'mixed' =
        families.size > 1 ? 'mixed' : (addrs[0].family as 'IPv4' | 'IPv6');
      out.push({
        name,
        addresses: addrs.map((a) => a.address),
        family,
        internal: addrs.every((a) => a.internal === true),
      });
    }

    // Synthetic "any" entry - means tshark/tcpdump should listen on all.
    out.unshift({
      name: 'any',
      addresses: [],
      family: 'mixed',
      internal: false,
    });

    res.json({ data: out, total: out.length });
  } catch (err: any) {
    console.error('GET /system/network-interfaces error:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

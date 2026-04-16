/**
 * RBAC check — ask the `permissions` table whether a (role, resource, action)
 * triple is authorized. Admin short-circuits. Solo-mode short-circuits.
 *
 * Usage in a route:
 *
 *   router.post('/vulnerabilities', (req, res) => {
 *     if (!assertPermission(req, 'findings', 'write', res)) return;
 *     // ... do the write
 *   });
 *
 * assertPermission writes the 403 response itself and returns false so the
 * caller can early-return without repeating the error shape.
 */
import type { Request, Response } from 'express';

type PermissionChecker = (role: string, resource: string, action: string) => boolean;

let checkerImpl: PermissionChecker | null = null;

/** Called once at startup after db.ts is initialized. */
export function installPermissionChecker(fn: PermissionChecker): void {
  checkerImpl = fn;
}

function defaultChecker(role: string, _resource: string, _action: string): boolean {
  // Until the real DB-backed checker is installed, allow admin only.
  // This is safer than allow-all during startup races.
  return role === 'admin';
}

export function hasPermission(role: string, resource: string, action: string): boolean {
  const fn = checkerImpl ?? defaultChecker;
  if (role === 'admin') return true;
  return fn(role, resource, action);
}

/**
 * Check and write 403 on denial. Returns true if allowed.
 * Solo-mode middleware already attached a synthetic admin user, so this
 * naturally passes there.
 */
export function assertPermission(
  req: Request,
  resource: string,
  action: string,
  res: Response,
): boolean {
  if (!req.user) {
    res.status(401).json({ error: 'not authenticated' });
    return false;
  }
  if (hasPermission(req.user.role, resource, action)) return true;
  res.status(403).json({
    error: 'forbidden',
    required: { resource, action },
    role: req.user.role,
  });
  return false;
}

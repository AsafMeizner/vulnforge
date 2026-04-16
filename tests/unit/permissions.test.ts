import { describe, it, expect, beforeEach } from 'vitest';
import {
  hasPermission,
  installPermissionChecker,
  assertPermission,
} from '../../server/auth/permissions';
import type { Request, Response } from 'express';

describe('hasPermission', () => {
  beforeEach(() => {
    // Swap in a deterministic checker for each test.
    installPermissionChecker((role, resource, action) => {
      if (role === 'researcher' && resource === 'findings' && action === 'write') return true;
      if (role === 'viewer' && action === 'read') return true;
      return false;
    });
  });

  it('admin short-circuits to allow', () => {
    expect(hasPermission('admin', 'anything', 'anything')).toBe(true);
  });

  it('delegates to checker for non-admin', () => {
    expect(hasPermission('researcher', 'findings', 'write')).toBe(true);
    expect(hasPermission('researcher', 'settings', 'admin')).toBe(false);
    expect(hasPermission('viewer', 'findings', 'read')).toBe(true);
    expect(hasPermission('viewer', 'findings', 'write')).toBe(false);
  });
});

describe('assertPermission', () => {
  function mkRes() {
    const state: { status: number; body: any } = { status: 200, body: null };
    const res = {
      status(c: number) { state.status = c; return this; },
      json(b: any) { state.body = b; return this; },
    } as unknown as Response;
    return { res, state };
  }

  beforeEach(() => {
    installPermissionChecker((role, resource, action) => {
      return role === 'researcher' && resource === 'findings' && action === 'write';
    });
  });

  it('returns false + 401 when unauthenticated', () => {
    const { res, state } = mkRes();
    const req = {} as Request;
    expect(assertPermission(req, 'findings', 'write', res)).toBe(false);
    expect(state.status).toBe(401);
    expect(state.body.error).toBe('not authenticated');
  });

  it('returns true when allowed', () => {
    const { res } = mkRes();
    const req = { user: { id: 1, role: 'researcher', device_id: 'x' } } as any;
    expect(assertPermission(req, 'findings', 'write', res)).toBe(true);
  });

  it('returns false + 403 when denied', () => {
    const { res, state } = mkRes();
    const req = { user: { id: 1, role: 'viewer', device_id: 'x' } } as any;
    expect(assertPermission(req, 'findings', 'write', res)).toBe(false);
    expect(state.status).toBe(403);
    expect(state.body.error).toBe('forbidden');
    expect(state.body.required).toEqual({ resource: 'findings', action: 'write' });
  });
});

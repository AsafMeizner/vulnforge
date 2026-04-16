import { Router, Request, Response } from 'express';
import {
  SessionStateRow,
  getSessionState,
  setSessionState,
  deleteSessionState,
} from '../db.js';

const router = Router();

type SessionScope = 'global' | 'project' | 'finding';

const VALID_SCOPES: ReadonlySet<SessionScope> = new Set(['global', 'project', 'finding']);

function parseScope(raw: unknown): SessionScope | null {
  if (typeof raw !== 'string') return null;
  return VALID_SCOPES.has(raw as SessionScope) ? (raw as SessionScope) : null;
}

/**
 * Parse the `scope_id` query/body value according to scope rules:
 *   - global: must be null (ignored if provided)
 *   - project/finding: must be a valid number
 * Returns { ok: true, value } or { ok: false, error }.
 */
function parseScopeId(
  scope: SessionScope,
  raw: unknown
): { ok: true; value: number | null } | { ok: false; error: string } {
  if (scope === 'global') {
    return { ok: true, value: null };
  }
  if (raw === undefined || raw === null || raw === '') {
    return { ok: false, error: `scope_id is required for scope='${scope}'` };
  }
  const n = Number(raw);
  if (isNaN(n)) {
    return { ok: false, error: 'scope_id must be a number' };
  }
  return { ok: true, value: n };
}

/** Convert a DB row to the public API shape (value parsed from JSON). */
function rowToResponse(row: SessionStateRow): Record<string, unknown> {
  let parsedValue: unknown;
  try {
    parsedValue = JSON.parse(row.value);
  } catch {
    parsedValue = row.value;
  }
  return {
    scope: row.scope,
    scope_id: row.scope_id ?? null,
    key: row.key,
    value: parsedValue,
    updated_at: row.updated_at,
  };
}

// ── GET /api/session ───────────────────────────────────────────────────────
// Query params: scope (required), scope_id (required unless scope=global), key (optional)

router.get('/', (req: Request, res: Response) => {
  try {
    const scope = parseScope(req.query.scope);
    if (!scope) {
      res.status(400).json({ error: "scope must be one of 'global' | 'project' | 'finding'" });
      return;
    }

    const scopeIdResult = parseScopeId(scope, req.query.scope_id);
    if (scopeIdResult.ok === false) {
      res.status(400).json({ error: scopeIdResult.error });
      return;
    }

    const key = typeof req.query.key === 'string' ? req.query.key : undefined;

    const rows = getSessionState(scope, scopeIdResult.value, key);
    const data = rows.map(rowToResponse);
    res.json({ data, total: data.length });
  } catch (err: any) {
    console.error('GET /session error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/session ──────────────────────────────────────────────────────
// Body: { scope, scope_id?, key, value } — upsert a single key

router.post('/', (req: Request, res: Response) => {
  try {
    const { scope: rawScope, scope_id: rawScopeId, key, value } = req.body || {};

    const scope = parseScope(rawScope);
    if (!scope) {
      res.status(400).json({ error: "scope must be one of 'global' | 'project' | 'finding'" });
      return;
    }

    const scopeIdResult = parseScopeId(scope, rawScopeId);
    if (scopeIdResult.ok === false) {
      res.status(400).json({ error: scopeIdResult.error });
      return;
    }

    if (!key || typeof key !== 'string') {
      res.status(400).json({ error: 'key is required' });
      return;
    }

    if (value === undefined) {
      res.status(400).json({ error: 'value is required' });
      return;
    }

    // The API accepts a JSON-typed value and stringifies it for storage
    const stored = JSON.stringify(value);
    setSessionState(scope, scopeIdResult.value, key, stored);

    const rows = getSessionState(scope, scopeIdResult.value, key);
    if (rows.length === 0) {
      res.status(500).json({ error: 'Failed to persist session state' });
      return;
    }
    res.status(201).json(rowToResponse(rows[0]));
  } catch (err: any) {
    console.error('POST /session error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE /api/session ────────────────────────────────────────────────────
// Query params: scope (required), scope_id (required unless scope=global), key (required)

router.delete('/', (req: Request, res: Response) => {
  try {
    const scope = parseScope(req.query.scope);
    if (!scope) {
      res.status(400).json({ error: "scope must be one of 'global' | 'project' | 'finding'" });
      return;
    }

    const scopeIdResult = parseScopeId(scope, req.query.scope_id);
    if (scopeIdResult.ok === false) {
      res.status(400).json({ error: scopeIdResult.error });
      return;
    }

    const key = typeof req.query.key === 'string' ? req.query.key : undefined;
    if (!key) {
      res.status(400).json({ error: 'key is required' });
      return;
    }

    deleteSessionState(scope, scopeIdResult.value, key);
    res.status(204).send();
  } catch (err: any) {
    console.error('DELETE /session error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/session/clear ────────────────────────────────────────────────
// Body: { scope, scope_id? } — remove all keys for the given scope

router.post('/clear', (req: Request, res: Response) => {
  try {
    const { scope: rawScope, scope_id: rawScopeId } = req.body || {};

    const scope = parseScope(rawScope);
    if (!scope) {
      res.status(400).json({ error: "scope must be one of 'global' | 'project' | 'finding'" });
      return;
    }

    const scopeIdResult = parseScopeId(scope, rawScopeId);
    if (scopeIdResult.ok === false) {
      res.status(400).json({ error: scopeIdResult.error });
      return;
    }

    deleteSessionState(scope, scopeIdResult.value);
    res.status(204).send();
  } catch (err: any) {
    console.error('POST /session/clear error:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;

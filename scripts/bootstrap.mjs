#!/usr/bin/env node
/**
 * First-run DB bootstrap for the server tarball installer.
 *
 * Run after install-server.sh has dropped the service in place but
 * before starting it, OR run automatically by the systemd unit's
 * ExecStartPre if you prefer.
 *
 * Responsibilities:
 *   - Ensure the SQLite DB file exists and is readable by the service user
 *   - Run all schema CREATE + migrations (same path as regular boot)
 *   - Seed default RBAC permissions
 *   - Exit 0 on success, non-zero on any failure
 *
 * Does NOT create users - that happens when the first admin POSTs
 * to /api/session/bootstrap from the desktop wizard.
 */
import { initDb } from '../dist-server/server/db.js';

const t0 = Date.now();
console.log('[bootstrap] initializing DB…');
try {
  await initDb();
  console.log(`[bootstrap] ok - schema + seed ready (${Date.now() - t0}ms)`);
  process.exit(0);
} catch (err) {
  console.error('[bootstrap] failed:', err?.message || err);
  process.exit(1);
}

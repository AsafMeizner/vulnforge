#!/usr/bin/env node
/**
 * Idempotent schema migration runner. Safe to re-run on every deploy.
 *
 * Reuses initDb() because every CREATE is `IF NOT EXISTS` and every ALTER
 * is wrapped in try/catch — running it against an already-up-to-date DB
 * is a no-op.
 *
 * Usage:
 *   node scripts/migrate.mjs
 *   or bake into your install-server.sh upgrade path.
 */
import { initDb } from '../dist-server/server/db.js';

const t0 = Date.now();
console.log('[migrate] running…');
try {
  await initDb();
  console.log(`[migrate] ok (${Date.now() - t0}ms)`);
  process.exit(0);
} catch (err) {
  console.error('[migrate] failed:', err?.message || err);
  process.exit(1);
}

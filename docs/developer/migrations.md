# Schema migrations

VulnForge's schema lives in `server/db.ts::createTables()` and `migrateSchema()`. Both are **idempotent** - safe to run on every startup without checks.

## Rules

1. **Never** modify existing columns or drop columns. SQLite's `ALTER TABLE` can't rename or drop, and removing a column means a slow rewrite. Add new columns instead; deprecate old ones by leaving them unused.

2. New columns go into `migrateSchema()`, **not** the original `CREATE TABLE`. The `CREATE TABLE` is for fresh installs; `migrateSchema()` catches existing DBs up to the latest shape.

3. Always default new columns (`DEFAULT 'value'` or `DEFAULT 0`). The migration run is `ALTER TABLE ... ADD COLUMN ...` - SQLite populates existing rows with the default.

4. Wrap each ALTER in `try { db.run(...) } catch {}`. Running the same ALTER twice is the normal case and must not crash the server.

5. Data backfills go in a separate function called after `migrateSchema()` - like `backfillSyncColumns()`. Query for rows with the new column still at its NULL/default state; write the computed value.

6. Bump `package.json::version` when you change the schema. Clients send it in `X-VulnForge-Version` so mismatched clients see a 426.

## Adding a new syncable table

1. Add it to `SYNCABLE_TABLES` in `server/sync/model.ts`.
2. Add it to `SYNC_ENABLED_TABLES` in `server/db.ts` (migrations iterate over this).
3. Define `CREATE TABLE` for fresh installs - include the 7 sync columns directly.
4. Restart the server - existing installs get the columns via `migrateSchema()` + `backfillSyncColumns()`.
5. Document the new table in [`../architecture/data-model.md`](../architecture/data-model.md).
6. Add a row-to-resource mapping in `server/routes/sync.ts::toResource()` if the default ("findings") doesn't fit.

## Running migrations manually

```bash
npm run migrate                         # dev
node scripts/migrate.mjs                # production (from extracted tarball)
```

Both call `initDb()` which runs `createTables()` + `migrateSchema()` + `backfillSyncColumns()` + `seedDefaultPermissions()` and `seedDefaultNotesProvider()`.

## Testing migrations

Always test against a copy of a real user DB before shipping:

```bash
cp vulnforge.db vulnforge.db.backup
VULNFORGE_DB_PATH=$(pwd)/vulnforge.db.backup npm run migrate
# Verify row counts + a sample query, restore original if bad
mv vulnforge.db.backup vulnforge.db  # to rollback
```

If you touch `migrateSchema()`, run the full initDb against a fresh empty DB and against an existing seeded DB. Both must succeed and preserve all rows.

## Gotchas

- **sql.js** (the WASM SQLite we use) quirks: `last_insert_rowid()` must be run in a separate `db.exec` - see `execRun()`.
- **`ALTER TABLE ADD COLUMN` with DEFAULT**: requires a constant default - no functions. For `DEFAULT Date.now()` equivalent, add the column with no default + backfill.
- **`NOT NULL` columns on ALTER**: require a default. `ALTER TABLE x ADD COLUMN foo TEXT NOT NULL` fails if the table has rows; add `DEFAULT 'x'` too.
- **Partial indexes** (`CREATE UNIQUE INDEX ... WHERE ...`): not supported in old SQLite. We try the partial form first and fall back to plain unique index.

/**
 * cleanup.ts — Delete auto-scan findings (keep original 36 seeded vulns)
 * Run: npx tsx cleanup.ts
 */
import initSqlJs from 'sql.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, 'vulnforge.db');

async function main() {
  const SQL = await initSqlJs({
    locateFile: (f: string) => path.join(__dirname, 'node_modules', 'sql.js', 'dist', f),
  });

  const dbBuf = fs.readFileSync(DB_PATH);
  const db = new SQL.Database(dbBuf);

  const before = (db.exec('SELECT COUNT(*) as c FROM vulnerabilities')[0]?.values[0]?.[0] as number) || 0;

  // Delete all findings that were created by automated scans (id > 36)
  db.run('DELETE FROM vulnerabilities WHERE id > 36');

  // Also clean up scans table
  db.run('DELETE FROM scans');

  const after = (db.exec('SELECT COUNT(*) as c FROM vulnerabilities')[0]?.values[0]?.[0] as number) || 0;

  console.log('Before: ' + before + ' vulns');
  console.log('After:  ' + after + ' vulns');
  console.log('Deleted: ' + (before - after) + ' auto-scan findings');

  // Save
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
  db.close();
}

main().catch(console.error);

// fix-projects.ts — Link vulns to projects + set project display names
// Run: npx tsx fix-projects.ts
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
  const db = new SQL.Database(fs.readFileSync(DB_PATH));

  // Add project text column if not exists
  try { db.run('ALTER TABLE vulnerabilities ADD COLUMN project TEXT DEFAULT ""'); console.log('Added project column'); } catch { /* exists */ }

  // Build project name -> id map
  const pRows = db.exec('SELECT id, name FROM projects');
  const pMap = new Map<string, number>();
  if (pRows.length) for (const r of pRows[0].values) pMap.set((r[1] as string).toLowerCase(), r[0] as number);

  // Vuln ID -> project name mapping (from the original security-solver data)
  const names: [number, string, string][] = [
    [1,'libarchive','libarchive'],[2,'jq','jq'],[3,'jq','jq'],[4,'jq','jq'],
    [5,'mongoose','mongoose'],[6,'civetweb','civetweb'],[7,'civetweb','civetweb'],
    [8,'civetweb','civetweb'],[9,'libssh2','libssh2'],[10,'wolfssl','wolfSSL'],
    [11,'gravity','gravity'],[12,'contiki','contiki-ng'],[13,'libhv','libhv'],
    [14,'redis','redis'],[15,'rt-thread','rt-thread'],[16,'stb','stb'],
    [17,'pcre2','pcre2'],[18,'c-ares','c-ares'],[19,'libevent','libevent'],
    [20,'libevent','libevent'],[21,'libyaml','libyaml'],[22,'libexpat','libexpat'],
    [23,'jansson','jansson'],[24,'picotls','picotls'],[25,'cosmopolitan','cosmopolitan'],
    [26,'libwebsockets','libwebsockets'],[27,'sqlite','SQLite'],[28,'sqlite','SQLite'],
    [29,'node','Node.js'],[30,'openssh','OpenSSH'],[31,'openssh','OpenSSH'],
    [32,'linux','Linux kernel'],[33,'systemd','systemd'],[34,'mruby','mruby'],
    [35,'v7','v7'],[36,'node','Node.js'],
  ];

  let fixed = 0;
  for (const [id, key, display] of names) {
    const pid = pMap.get(key) || null;
    db.run('UPDATE vulnerabilities SET project = ?, project_id = ? WHERE id = ?', [display, pid, id]);
    fixed++;
  }

  console.log('Fixed ' + fixed + ' vulns with project names');
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
  db.close();
}

main().catch(console.error);

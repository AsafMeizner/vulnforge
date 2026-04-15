/**
 * fix-ai.ts — Enable claude_cli as default provider, disable claude API
 * Run: npx tsx fix-ai.ts
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

  // Check current providers
  const providers = db.exec('SELECT id, name, model, enabled FROM ai_providers');
  console.log('Current providers:', JSON.stringify(providers[0]?.values));

  // Check if claude_cli exists
  const hasCli = db.exec("SELECT COUNT(*) FROM ai_providers WHERE name = 'claude_cli'");
  const cliCount = (hasCli[0]?.values[0]?.[0] as number) || 0;

  if (cliCount === 0) {
    db.run("INSERT INTO ai_providers (name, model, api_key, base_url, enabled, config) VALUES ('claude_cli', 'claude-code', '', '', 1, '{}')");
    console.log('Added claude_cli provider (enabled)');
  } else {
    db.run("UPDATE ai_providers SET enabled = 1 WHERE name = 'claude_cli'");
    console.log('Enabled claude_cli provider');
  }

  // Disable claude API provider (no API key = errors)
  db.run("UPDATE ai_providers SET enabled = 0 WHERE name = 'claude' AND (api_key IS NULL OR api_key = '')");
  console.log('Disabled claude API (no key configured)');

  const after = db.exec('SELECT id, name, model, enabled FROM ai_providers');
  console.log('After:', JSON.stringify(after[0]?.values));

  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
  db.close();
  console.log('Done.');
}

main().catch(console.error);

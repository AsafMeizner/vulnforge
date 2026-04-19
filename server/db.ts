import { createRequire } from 'module';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import { ulid as __ulid } from './utils/ulid.js';
import { encryptSecret, decryptSecret, isEncrypted } from './lib/crypto.js';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DB_PATH = process.env.VULNFORGE_DB_PATH || path.join(process.cwd(), 'vulnforge.db');

/**
 * Resolve the sql.js WASM path.
 *
 * Order:
 *   1. VULNFORGE_WASM_PATH env var - set by Electron main for packaged apps
 *      where process.cwd() points at win-unpacked/ and node_modules lives
 *      inside app.asar.unpacked/.
 *   2. require.resolve('sql.js/dist/sql-wasm.wasm') - works for both dev
 *      runs and any install layout Node can resolve.
 *   3. process.cwd()/node_modules/... - last-resort dev fallback for
 *      niche launchers that can't resolve packages.
 */
function resolveWasmPath(): string {
  if (process.env.VULNFORGE_WASM_PATH) return process.env.VULNFORGE_WASM_PATH;
  try {
    return require.resolve('sql.js/dist/sql-wasm.wasm');
  } catch {
    /* fall through to cwd fallback */
  }
  return path.join(process.cwd(), 'node_modules', 'sql.js', 'dist', 'sql-wasm.wasm');
}
const WASM_PATH = resolveWasmPath();

// ── Types ──────────────────────────────────────────────────────────────────

export interface Project {
  id?: number;
  name: string;
  path?: string;
  repo_url?: string;
  branch?: string;
  language?: string;
  last_scanned?: string;
  created_at?: string;
}

export interface Vulnerability {
  id?: number;
  project_id?: number;
  title: string;
  severity?: string;
  status?: string;
  cvss?: string;
  cvss_vector?: string;
  cwe?: string;
  file?: string;
  line_start?: number;
  line_end?: number;
  code_snippet?: string;
  description?: string;
  impact?: string;
  reproduction_steps?: string;
  suggested_fix?: string;
  fix_diff?: string;
  method?: string;
  tool_name?: string;
  confidence?: number;
  verified?: number;
  false_positive?: number;
  advisory?: string;
  advisory_url?: string;
  submit_to?: string;
  submit_email?: string;
  email_chain_url?: string;
  issue_url?: string;
  response?: string;
  rejection_reason?: string;
  sub_findings?: string;
  disclosure_content?: string;
  how_to_submit_content?: string;
  ai_triage?: string;
  ai_summary?: string;
  found_at?: string;
  submitted_at?: string;
  resolved_at?: string;
  updated_at?: string;
}

export interface Scan {
  id?: number;
  project_id: number;
  tool_name: string;
  status?: string;
  started_at?: string;
  completed_at?: string;
  output?: string;
  findings_count?: number;
  config?: string;
}

export interface Tool {
  id?: number;
  name: string;
  category?: string;
  description?: string;
  docs?: string;
  track_record?: string;
  file_path?: string;
  config_schema?: string;
  enabled?: number;
}

export interface Checklist {
  id?: number;
  name: string;
  source_url?: string;
  category?: string;
  total_items?: number;
}

export interface ChecklistItem {
  id?: number;
  checklist_id: number;
  category?: string;
  title: string;
  description?: string;
  severity?: string;
  tool_names?: string;
  verified?: number;
  vuln_id?: number;
  notes?: string;
}

export interface Plugin {
  id?: number;
  name: string;
  type?: string;
  source_url?: string;
  install_path?: string;
  version?: string;
  manifest?: string;
  enabled?: number;
  installed_at?: string;
}

export interface AIProvider {
  id?: number;
  name: string;
  model?: string;
  api_key?: string;
  base_url?: string;
  enabled?: number;
  config?: string;
}

export interface Report {
  id?: number;
  vuln_id?: number;
  type?: string;
  format?: string;
  content?: string;
  generated_by?: string;
  created_at?: string;
}

export interface ScanFinding {
  id?: number;
  scan_id?: number;
  project_id?: number;
  pipeline_id?: string;
  title: string;
  severity?: string;
  cvss?: string;
  cwe?: string;
  file?: string;
  line_start?: number;
  line_end?: number;
  code_snippet?: string;
  description?: string;
  impact?: string;
  tool_name?: string;
  confidence?: string;
  raw_output?: string;
  status?: string;          // pending | accepted | rejected | auto_rejected
  rejection_reason?: string;
  merged_tools?: string;
  ai_filter_reason?: string;
  ai_verification?: string;
  suggested_fix?: string;
  created_at?: string;
}

export interface PipelineRun {
  id: string;
  project_id: number;
  status: string;  // pending | cloning | scanning | filtering | verifying | ready | failed | cancelled
  current_stage: string;
  progress: number;
  scan_job_ids: string;   // JSON array
  findings_total: number;
  findings_after_filter: number;
  findings_after_verify: number;
  config: string;         // JSON
  error?: string;
  started_at: string;
  completed_at?: string;
}

// ── DB Init ────────────────────────────────────────────────────────────────

let db: any = null;
let SQL: any = null;

export async function initDb(): Promise<void> {
  const initSqlJs = require('sql.js');
  const wasmBinary = readFileSync(WASM_PATH);
  SQL = await initSqlJs({ wasmBinary });

  if (existsSync(DB_PATH)) {
    const fileBuffer = readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  createTables();
  persistDb();
}

export function getDb(): any {
  if (!db) throw new Error('Database not initialized - call initDb() first');
  return db;
}

export function persistDb(): void {
  const data = db.export();
  writeFileSync(DB_PATH, Buffer.from(data));
}

// ── Schema ─────────────────────────────────────────────────────────────────

function createTables(): void {
  db.run(`
    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      path TEXT,
      repo_url TEXT,
      branch TEXT,
      language TEXT,
      last_scanned TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER,
      title TEXT NOT NULL,
      severity TEXT,
      status TEXT DEFAULT 'Open',
      cvss TEXT,
      cvss_vector TEXT,
      cwe TEXT,
      file TEXT,
      line_start INTEGER,
      line_end INTEGER,
      code_snippet TEXT,
      description TEXT,
      impact TEXT,
      reproduction_steps TEXT,
      suggested_fix TEXT,
      fix_diff TEXT,
      method TEXT,
      tool_name TEXT,
      confidence REAL,
      verified INTEGER DEFAULT 0,
      false_positive INTEGER DEFAULT 0,
      advisory TEXT,
      advisory_url TEXT,
      submit_to TEXT,
      submit_email TEXT,
      email_chain_url TEXT,
      issue_url TEXT,
      response TEXT,
      rejection_reason TEXT,
      sub_findings TEXT,
      disclosure_content TEXT,
      how_to_submit_content TEXT,
      ai_triage TEXT,
      ai_summary TEXT,
      found_at TEXT DEFAULT (datetime('now')),
      submitted_at TEXT,
      resolved_at TEXT,
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (project_id) REFERENCES projects(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL,
      tool_name TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      started_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      output TEXT,
      findings_count INTEGER DEFAULT 0,
      config TEXT,
      FOREIGN KEY (project_id) REFERENCES projects(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tools (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      category TEXT,
      description TEXT,
      docs TEXT,
      track_record TEXT,
      file_path TEXT,
      config_schema TEXT,
      enabled INTEGER DEFAULT 1
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS checklists (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      source_url TEXT,
      category TEXT,
      total_items INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS checklist_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      checklist_id INTEGER NOT NULL,
      category TEXT,
      title TEXT NOT NULL,
      description TEXT,
      severity TEXT,
      tool_names TEXT,
      verified INTEGER DEFAULT 0,
      vuln_id INTEGER,
      notes TEXT,
      FOREIGN KEY (checklist_id) REFERENCES checklists(id),
      FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS plugins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT,
      source_url TEXT,
      install_path TEXT,
      version TEXT,
      manifest TEXT,
      enabled INTEGER DEFAULT 1,
      installed_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ai_providers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      model TEXT,
      api_key TEXT,
      base_url TEXT,
      enabled INTEGER DEFAULT 0,
      config TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vuln_id INTEGER,
      type TEXT,
      format TEXT,
      content TEXT,
      generated_by TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS scan_findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER REFERENCES scans(id),
      project_id INTEGER,
      title TEXT NOT NULL,
      severity TEXT DEFAULT 'Medium',
      cvss TEXT DEFAULT '',
      cwe TEXT DEFAULT '',
      file TEXT DEFAULT '',
      line_start INTEGER,
      line_end INTEGER,
      code_snippet TEXT DEFAULT '',
      description TEXT DEFAULT '',
      tool_name TEXT DEFAULT '',
      confidence TEXT DEFAULT 'Medium',
      raw_output TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      rejection_reason TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS pipeline_runs (
      id TEXT PRIMARY KEY,
      project_id INTEGER NOT NULL,
      status TEXT DEFAULT 'pending',
      current_stage TEXT DEFAULT '',
      progress INTEGER DEFAULT 0,
      scan_job_ids TEXT DEFAULT '[]',
      findings_total INTEGER DEFAULT 0,
      findings_after_filter INTEGER DEFAULT 0,
      findings_after_verify INTEGER DEFAULT 0,
      config TEXT DEFAULT '{}',
      error TEXT,
      started_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      FOREIGN KEY (project_id) REFERENCES projects(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS routing_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task TEXT NOT NULL,
      provider TEXT NOT NULL,
      model TEXT NOT NULL,
      priority INTEGER DEFAULT 1,
      enabled INTEGER DEFAULT 1
    )
  `);

  // Research Workspace tables
  db.run(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL DEFAULT 'local',
      external_id TEXT NOT NULL,
      title TEXT NOT NULL,
      type TEXT DEFAULT 'note',
      status TEXT,
      tags TEXT DEFAULT '[]',
      project_id INTEGER,
      finding_ids TEXT DEFAULT '[]',
      file_refs TEXT DEFAULT '[]',
      confidence REAL,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notes_providers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      type TEXT NOT NULL,
      enabled INTEGER DEFAULT 1,
      is_default INTEGER DEFAULT 0,
      config TEXT DEFAULT '{}'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS session_state (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scope TEXT NOT NULL,
      scope_id INTEGER,
      key TEXT NOT NULL,
      value TEXT NOT NULL,
      updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(scope, scope_id, key)
    )
  `);

  // Runtime Analysis (Theme 3) tables
  db.run(`
    CREATE TABLE IF NOT EXISTS runtime_jobs (
      id TEXT PRIMARY KEY,
      project_id INTEGER,
      finding_id INTEGER,
      type TEXT NOT NULL,
      tool TEXT NOT NULL,
      status TEXT DEFAULT 'queued',
      config TEXT DEFAULT '{}',
      output_dir TEXT,
      stats TEXT DEFAULT '{}',
      error TEXT,
      started_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      FOREIGN KEY (project_id) REFERENCES projects(id),
      FOREIGN KEY (finding_id) REFERENCES vulnerabilities(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS fuzz_crashes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id TEXT NOT NULL,
      stack_hash TEXT,
      input_path TEXT NOT NULL,
      input_size INTEGER,
      signal TEXT,
      stack_trace TEXT,
      exploitability TEXT DEFAULT 'unknown',
      minimized INTEGER DEFAULT 0,
      linked_finding_id INTEGER,
      discovered_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (job_id) REFERENCES runtime_jobs(id),
      FOREIGN KEY (linked_finding_id) REFERENCES vulnerabilities(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS captures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id TEXT NOT NULL,
      pcap_path TEXT NOT NULL,
      packet_count INTEGER DEFAULT 0,
      bytes INTEGER DEFAULT 0,
      filter TEXT,
      start_time TEXT,
      end_time TEXT,
      FOREIGN KEY (job_id) REFERENCES runtime_jobs(id)
    )
  `);

  // Historical Intelligence (Theme 4) tables
  db.run(`
    CREATE TABLE IF NOT EXISTS bisect_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id TEXT NOT NULL,
      first_bad_commit TEXT,
      first_bad_date TEXT,
      commit_message TEXT,
      diff TEXT,
      author TEXT,
      tests_run INTEGER DEFAULT 0,
      FOREIGN KEY (job_id) REFERENCES runtime_jobs(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS cve_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL UNIQUE,
      published TEXT,
      modified TEXT,
      severity TEXT,
      cvss_score REAL,
      description TEXT,
      affected_products TEXT,
      cve_references TEXT,
      synced_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS cve_project_matches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL,
      project_id INTEGER NOT NULL,
      match_reason TEXT,
      dependency_name TEXT,
      dependency_version TEXT,
      confidence REAL,
      matched_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Exploit Development (Theme 2) tables
  db.run(`
    CREATE TABLE IF NOT EXISTS exploits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      finding_id INTEGER,
      title TEXT NOT NULL,
      language TEXT DEFAULT 'python',
      code TEXT DEFAULT '',
      tier TEXT DEFAULT 'pattern',
      notes TEXT DEFAULT '',
      template TEXT,
      last_run_status TEXT,
      last_run_output TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (finding_id) REFERENCES vulnerabilities(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS proof_ladder (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      finding_id INTEGER NOT NULL UNIQUE,
      current_tier TEXT DEFAULT 'pattern',
      pattern_at TEXT,
      manual_at TEXT,
      traced_at TEXT,
      poc_at TEXT,
      weaponized_at TEXT,
      notes TEXT DEFAULT '',
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (finding_id) REFERENCES vulnerabilities(id)
    )
  `);

  // Disclosure & Bounty Ops (Theme 5) tables
  db.run(`
    CREATE TABLE IF NOT EXISTS vendors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      security_email TEXT,
      disclosure_policy_url TEXT,
      platform TEXT,
      typical_response_days INTEGER,
      preferred_format TEXT,
      notes TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS disclosures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      finding_id INTEGER,
      vendor_id INTEGER,
      title TEXT NOT NULL,
      status TEXT DEFAULT 'draft',
      submission_date TEXT,
      sla_days INTEGER DEFAULT 90,
      response_date TEXT,
      patch_date TEXT,
      public_date TEXT,
      cve_id TEXT,
      tracking_id TEXT,
      bounty_amount REAL,
      bounty_currency TEXT DEFAULT 'USD',
      bounty_paid_date TEXT,
      notes TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (finding_id) REFERENCES vulnerabilities(id),
      FOREIGN KEY (vendor_id) REFERENCES vendors(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS disclosure_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      disclosure_id INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      event_date TEXT DEFAULT (datetime('now')),
      actor TEXT,
      description TEXT,
      FOREIGN KEY (disclosure_id) REFERENCES disclosures(id)
    )
  `);

  // User Accounts + RBAC (Phase 14)
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'researcher',
      display_name TEXT,
      email TEXT,
      active INTEGER DEFAULT 1,
      last_login TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS api_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL UNIQUE,
      name TEXT,
      expires_at TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Sandbox Snapshots (VM integration)
  db.run(`
    CREATE TABLE IF NOT EXISTS sandbox_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      size_bytes INTEGER DEFAULT 0,
      description TEXT,
      FOREIGN KEY (job_id) REFERENCES runtime_jobs(id)
    )
  `);

  // External Service Integrations
  db.run(`
    CREATE TABLE IF NOT EXISTS integrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      enabled INTEGER DEFAULT 0,
      config TEXT DEFAULT '{}',
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS integration_tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      integration_id INTEGER NOT NULL,
      finding_id INTEGER,
      disclosure_id INTEGER,
      ticket_id TEXT NOT NULL,
      ticket_url TEXT,
      status TEXT,
      last_synced TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (integration_id) REFERENCES integrations(id),
      FOREIGN KEY (finding_id) REFERENCES vulnerabilities(id),
      FOREIGN KEY (disclosure_id) REFERENCES disclosures(id)
    )
  `);

  // Subsystem B - Auth (JWT refresh tokens) + RBAC (permissions)
  db.run(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      device_id TEXT NOT NULL,
      device_name TEXT DEFAULT '',
      expires_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      last_used_at INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_device ON refresh_tokens(device_id)`);

  db.run(`
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role TEXT NOT NULL,
      resource TEXT NOT NULL,
      action TEXT NOT NULL,
      UNIQUE(role, resource, action)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS oidc_providers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      issuer_url TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT NOT NULL,
      scopes TEXT DEFAULT 'openid email profile',
      role_mapping_json TEXT DEFAULT '{}',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS pipeline_jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sync_id TEXT UNIQUE NOT NULL,
      project_id INTEGER,
      requested_by_user_id INTEGER,
      executor TEXT NOT NULL CHECK(executor IN ('local','server')),
      status TEXT NOT NULL DEFAULT 'queued',
      priority INTEGER NOT NULL DEFAULT 5,
      stages_json TEXT DEFAULT '[]',
      worker_id TEXT,
      queued_at INTEGER NOT NULL,
      claimed_at INTEGER,
      finished_at INTEGER,
      error TEXT,
      FOREIGN KEY (project_id) REFERENCES projects(id),
      FOREIGN KEY (requested_by_user_id) REFERENCES users(id)
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_status ON pipeline_jobs(status, priority)`);

  // CR-audit-21 (MEDIUM): indexes on hot filter columns.
  // Every row below was backing a full-table scan in list endpoints
  // because the table held no index on the WHERE / ORDER BY columns.
  // `IF NOT EXISTS` keeps this idempotent on upgrade; sql.js ignores
  // duplicates silently.
  const HOT_INDEXES: Array<[string, string, string]> = [
    // vulnerabilities - filtered by status + severity + project_id,
    // ordered by found_at
    ['idx_vuln_status',       'vulnerabilities', 'status'],
    ['idx_vuln_severity',     'vulnerabilities', 'severity'],
    ['idx_vuln_project',      'vulnerabilities', 'project_id'],
    ['idx_vuln_found_at',     'vulnerabilities', 'found_at'],
    // scan_findings - filtered per pipeline, by status, by severity
    ['idx_scan_findings_pipe',    'scan_findings', 'pipeline_id'],
    ['idx_scan_findings_status',  'scan_findings', 'status'],
    ['idx_scan_findings_sev',     'scan_findings', 'severity'],
    ['idx_scan_findings_project', 'scan_findings', 'project_id'],
    // audit_log - time-ordered reads, filtered by actor + entity
    ['idx_audit_created_at',  'audit_log', 'created_at'],
    ['idx_audit_actor',       'audit_log', 'actor'],
    ['idx_audit_entity',      'audit_log', 'entity_type'],
    // notes - filtered by project_id
    ['idx_notes_project',     'notes', 'project_id'],
    // scans - filtered per project, by status
    ['idx_scans_project',     'scans', 'project_id'],
    ['idx_scans_status',      'scans', 'status'],
    // pipeline_runs - time ordered + per-project
    ['idx_pipeline_runs_project', 'pipeline_runs', 'project_id'],
    ['idx_pipeline_runs_status',  'pipeline_runs', 'status'],
  ];
  for (const [name, table, col] of HOT_INDEXES) {
    try {
      db.run(`CREATE INDEX IF NOT EXISTS ${name} ON ${table}(${col})`);
    } catch {
      // Table might not exist yet on very old DBs - migrateSchema() below
      // backfills, and re-running this block on the next boot will catch up.
    }
  }

  // Teach Mode + Pattern Mining (Phase 15)
  db.run(`
    CREATE TABLE IF NOT EXISTS teach_examples (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      finding_id INTEGER,
      action TEXT NOT NULL,
      reasoning TEXT,
      pattern_extracted TEXT,
      code_context TEXT,
      user_id INTEGER,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (finding_id) REFERENCES vulnerabilities(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS learned_patterns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      source_finding_id INTEGER,
      pattern_type TEXT,
      grep_pattern TEXT,
      description TEXT,
      confidence REAL DEFAULT 0.5,
      times_matched INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (source_finding_id) REFERENCES vulnerabilities(id)
    )
  `);

  // Collaboration & Compliance (Themes 7+9)
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT DEFAULT (datetime('now')),
      actor TEXT,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      details TEXT
    )
  `);

  migrateSchema();
  backfillSyncColumns();
  seedDefaultNotesProvider();
  seedDefaultPermissions();
  // One-time encryption pass on any legacy plaintext secret columns.
  // Idempotent - isEncrypted() guards prevent double-encrypt on reboot.
  migrateAIProviderSecrets();
  persistDb();
}

/** Seed the local notes provider on first run. */
function seedDefaultNotesProvider(): void {
  const rows = execQuery('SELECT COUNT(*) as c FROM notes_providers');
  const count = (rows[0]?.c as number) || 0;
  if (count === 0) {
    // Seed a portable notes path — env override first, then the
    // server's cwd. Earlier seeds hardcoded a drive-letter path that
    // broke every install that wasn't on the original dev's machine.
    const basePath =
      process.env.VULNFORGE_NOTES_DIR ||
      `${process.cwd().replace(/\\/g, '/')}/data/notes`;
    db.run(
      `INSERT INTO notes_providers (name, type, enabled, is_default, config) VALUES (?, ?, ?, ?, ?)`,
      ['local', 'local', 1, 1, JSON.stringify({ base_path: basePath })]
    );
  }
}

/**
 * Seed RBAC defaults on first run. Idempotent - INSERT OR IGNORE uses
 * the (role, resource, action) UNIQUE constraint to avoid dupes.
 *
 * Three starter roles:
 *   admin    - full access everywhere
 *   analyst  - day-to-day researcher: read/write findings + run pipelines + use integrations
 *   viewer   - read-only observer
 */
function seedDefaultPermissions(): void {
  const defaults: Array<[string, string, string]> = [
    ['admin', '*', '*'],
    // analyst
    ['researcher', 'findings', 'read'],
    ['researcher', 'findings', 'write'],
    ['researcher', 'projects', 'read'],
    ['researcher', 'projects', 'write'],
    ['researcher', 'pipelines', 'read'],
    ['researcher', 'pipelines', 'run'],
    ['researcher', 'integrations', 'use'],
    ['researcher', 'ai', 'use'],
    ['researcher', 'plugins', 'read'],
    ['researcher', 'notes', 'read'],
    ['researcher', 'notes', 'write'],
    // viewer
    ['viewer', 'findings', 'read'],
    ['viewer', 'projects', 'read'],
    ['viewer', 'pipelines', 'read'],
    ['viewer', 'notes', 'read'],
    ['viewer', 'plugins', 'read'],
  ];
  for (const [role, resource, action] of defaults) {
    try {
      db.run(
        `INSERT OR IGNORE INTO permissions (role, resource, action) VALUES (?, ?, ?)`,
        [role, resource, action],
      );
    } catch { /* table may not exist in very old DB - migrateSchema creates it */ }
  }
}

/**
 * Tables that participate in multi-device sync (subsystem B).
 * Every row gets the 7 sync columns below.
 * Keep this list in sync with SYNCABLE_TABLES in server/sync/model.ts.
 */
const SYNC_ENABLED_TABLES = [
  'projects',
  'vulnerabilities',
  'scan_findings',
  'pipeline_runs',
  'notes',
  'session_state',
  'reports',
  'checklists',
  'checklist_items',
  'scans',
] as const;

/** Add columns to existing tables without breaking existing data. */
function migrateSchema(): void {
  const migrations: string[] = [
    // Projects: clone support
    "ALTER TABLE projects ADD COLUMN clone_status TEXT DEFAULT 'ready'",
    "ALTER TABLE projects ADD COLUMN clone_error TEXT",
    "ALTER TABLE projects ADD COLUMN commit_hash TEXT",
    "ALTER TABLE projects ADD COLUMN build_system TEXT",
    "ALTER TABLE projects ADD COLUMN dependencies TEXT",
    "ALTER TABLE projects ADD COLUMN languages TEXT",
    // ScanFindings: pipeline + enrichment columns
    "ALTER TABLE scan_findings ADD COLUMN pipeline_id TEXT DEFAULT ''",
    "ALTER TABLE scan_findings ADD COLUMN merged_tools TEXT DEFAULT ''",
    "ALTER TABLE scan_findings ADD COLUMN ai_filter_reason TEXT DEFAULT ''",
    "ALTER TABLE scan_findings ADD COLUMN ai_verification TEXT DEFAULT ''",
    "ALTER TABLE scan_findings ADD COLUMN impact TEXT DEFAULT ''",
    "ALTER TABLE scan_findings ADD COLUMN suggested_fix TEXT DEFAULT ''",
    // Vulnerabilities: a dedicated column for human-authored triage
    // notes. Kept separate from ai_triage / ai_summary so the UI can
    // show both side-by-side and the user can write their own analysis
    // without any AI provider involved.
    "ALTER TABLE vulnerabilities ADD COLUMN manual_triage TEXT DEFAULT ''",
  ];

  // Subsystem B: capability tables (ai_providers + integrations) pick up
  // a `source` column so clients can distinguish locally-configured from
  // server-exposed entries. `task_tags` on ai_providers feeds the manifest.
  migrations.push(
    `ALTER TABLE ai_providers ADD COLUMN source TEXT NOT NULL DEFAULT 'local'`,
    `ALTER TABLE ai_providers ADD COLUMN task_tags TEXT DEFAULT '[]'`,
    `ALTER TABLE integrations ADD COLUMN source TEXT NOT NULL DEFAULT 'local'`,
  );

  // Subsystem B: sync columns on every syncable table.
  // `sync_scope` (not `scope`) because session_state already uses `scope`.
  for (const table of SYNC_ENABLED_TABLES) {
    migrations.push(
      `ALTER TABLE ${table} ADD COLUMN sync_id TEXT`,
      `ALTER TABLE ${table} ADD COLUMN sync_scope TEXT NOT NULL DEFAULT 'private'`,
      `ALTER TABLE ${table} ADD COLUMN owner_user_id INTEGER`,
      `ALTER TABLE ${table} ADD COLUMN updated_at_ms INTEGER`,
      `ALTER TABLE ${table} ADD COLUMN server_updated_at_ms INTEGER`,
      `ALTER TABLE ${table} ADD COLUMN tombstone INTEGER NOT NULL DEFAULT 0`,
      `ALTER TABLE ${table} ADD COLUMN sync_status TEXT NOT NULL DEFAULT 'local'`,
    );
  }

  for (const sql of migrations) {
    try { db.run(sql); } catch { /* column already exists - expected */ }
  }

  // Unique index on sync_id so two rows never collide.
  for (const table of SYNC_ENABLED_TABLES) {
    try {
      db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_${table}_sync_id ON ${table}(sync_id) WHERE sync_id IS NOT NULL`);
    } catch { /* expected on older SQLite without partial indexes - falls back to plain index */
      try { db.run(`CREATE INDEX IF NOT EXISTS idx_${table}_sync_id ON ${table}(sync_id)`); } catch {}
    }
  }
}

/**
 * Backfill sync columns on rows that predate the migration.
 * Runs once per startup; no-op after everything is populated.
 * Uses ulid() for sync_id so each row gets a sortable unique identifier.
 */
function backfillSyncColumns(): void {
  const ulid = __ulid;
  const nowMs = Date.now();

  for (const table of SYNC_ENABLED_TABLES) {
    let rows: Record<string, any>[] = [];
    try {
      const stmt = db.prepare(`SELECT rowid AS rid FROM ${table} WHERE sync_id IS NULL OR sync_id = ''`);
      while (stmt.step()) {
        const vals = stmt.get();
        rows.push({ rid: vals[0] });
      }
      stmt.free();
    } catch {
      // Table may not exist yet on a very old DB - skip gracefully.
      continue;
    }

    for (const row of rows) {
      const id = ulid();
      try {
        db.run(
          `UPDATE ${table}
             SET sync_id = ?,
                 updated_at_ms = COALESCE(updated_at_ms, ?),
                 sync_scope = COALESCE(sync_scope, 'private'),
                 sync_status = COALESCE(sync_status, 'local')
           WHERE rowid = ?`,
          [id, nowMs, row.rid],
        );
      } catch { /* best-effort - skip bad rows */ }
    }
  }
}

// ── Generic helpers ────────────────────────────────────────────────────────

function stmtToArray(stmt: any): Record<string, any>[] {
  const rows: Record<string, any>[] = [];
  const cols = stmt.getColumnNames();
  while (stmt.step()) {
    const vals = stmt.get();
    const obj: Record<string, any> = {};
    cols.forEach((col: string, i: number) => { obj[col] = vals[i]; });
    rows.push(obj);
  }
  stmt.free();
  return rows;
}

function execQuery(sql: string, params: any[] = []): Record<string, any>[] {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  return stmtToArray(stmt);
}

// Column-name allowlist regex used by safeSetClause. `[a-z_]` start
// then any `[a-z0-9_]` - identical to SQLite's unquoted-identifier
// rules. Anything else throws before the UPDATE is built.
const _SAFE_COLUMN_RE = /^[a-z_][a-z0-9_]*$/;

/**
 * Build `col1 = ?, col2 = ?` safely. Previously each update helper
 * interpolated `${f} = ?` with no validation, so a key like
 * `"name = 'pwn' --"` sneaking in from req.body could corrupt the
 * UPDATE and silently drop the placeholder. Throws if any field
 * is not a valid identifier.
 *
 * Callers should still filter their input to a per-table allowlist
 * (picking named columns out of req.body) - this helper is
 * defence-in-depth.
 */
function safeSetClause(fields: string[]): string {
  for (const f of fields) {
    if (typeof f !== 'string' || !_SAFE_COLUMN_RE.test(f)) {
      throw new Error(`invalid column name in update: ${JSON.stringify(f)}`);
    }
  }
  return fields.map(f => `${f} = ?`).join(', ');
}

function execRun(sql: string, params: any[] = []): number {
  db.run(sql, params);
  const result = db.exec('SELECT last_insert_rowid() as id');
  persistDb();
  if (result.length > 0 && result[0].values.length > 0) {
    return result[0].values[0][0] as number;
  }
  return 0;
}

// ── Projects CRUD ──────────────────────────────────────────────────────────

export function getAllProjects(): Project[] {
  return execQuery('SELECT * FROM projects ORDER BY created_at DESC') as unknown as Project[];
}

export function getProjectById(id: number): Project | null {
  const rows = execQuery('SELECT * FROM projects WHERE id = ?', [id]);
  return rows[0] as Project || null;
}

export function createProject(p: Project): number {
  return execRun(
    `INSERT INTO projects (name, path, repo_url, branch, language, last_scanned)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [p.name, p.path || null, p.repo_url || null, p.branch || null, p.language || null, p.last_scanned || null]
  );
}

export function updateProject(id: number, p: Partial<Project>): void {
  const fields = Object.keys(p).filter(k => k !== 'id');
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (p as any)[f]);
  db.run(`UPDATE projects SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteProject(id: number): void {
  db.run('DELETE FROM projects WHERE id = ?', [id]);
  persistDb();
}

// ── Vulnerabilities CRUD ───────────────────────────────────────────────────

export interface VulnFilters {
  severity?: string;
  status?: string;
  project_id?: number;
  search?: string;
  sort?: string;
  order?: string;
  limit?: number;
  offset?: number;
}

export function getAllVulnerabilities(filters: VulnFilters = {}): Vulnerability[] {
  const conditions: string[] = [];
  const params: any[] = [];

  if (filters.severity) {
    conditions.push('v.severity = ?');
    params.push(filters.severity);
  }
  if (filters.status) {
    conditions.push('v.status = ?');
    params.push(filters.status);
  }
  if (filters.project_id) {
    conditions.push('v.project_id = ?');
    params.push(filters.project_id);
  }
  if (filters.search) {
    conditions.push('(v.title LIKE ? OR v.description LIKE ? OR v.file LIKE ?)');
    const like = `%${filters.search}%`;
    params.push(like, like, like);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const allowedSort = ['id', 'title', 'severity', 'status', 'cvss', 'found_at', 'updated_at'];
  const sortRaw = allowedSort.includes(filters.sort || '') ? filters.sort : 'found_at';
  const sort = `v.${sortRaw}`;
  const order = filters.order === 'asc' ? 'ASC' : 'DESC';
  // Default to 100, hard-cap at 1000 regardless of caller input.
  // Previously an omitted `limit` meant "every row", which OOMs the
  // server once the table grows past a few thousand findings and is
  // trivially DoS-able by any authenticated user.
  const DEFAULT_LIMIT = 100;
  const MAX_LIMIT = 1000;
  const limitNum = Math.min(
    MAX_LIMIT,
    Math.max(1, Number(filters.limit) || DEFAULT_LIMIT),
  );
  const limitClause = `LIMIT ${limitNum}`;
  const offsetClause = filters.offset !== undefined ? `OFFSET ${Number(filters.offset)}` : '';

  return execQuery(
    `SELECT v.*, COALESCE(p.name, '') as project_name FROM vulnerabilities v
     LEFT JOIN projects p ON v.project_id = p.id
     ${where} ORDER BY ${sort} ${order} ${limitClause} ${offsetClause}`,
    params
  ) as unknown as Vulnerability[];
}

export function countVulnerabilities(filters: VulnFilters = {}): number {
  const conditions: string[] = [];
  const params: any[] = [];

  if (filters.severity) { conditions.push('v.severity = ?'); params.push(filters.severity); }
  if (filters.status) { conditions.push('v.status = ?'); params.push(filters.status); }
  if (filters.project_id) { conditions.push('v.project_id = ?'); params.push(filters.project_id); }
  if (filters.search) {
    conditions.push('(v.title LIKE ? OR v.description LIKE ? OR v.file LIKE ?)');
    const like = `%${filters.search}%`;
    params.push(like, like, like);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const rows = execQuery(
    `SELECT COUNT(*) as c FROM vulnerabilities v ${where}`,
    params
  );
  return (rows[0]?.c as number) || 0;
}

export function getVulnerabilityById(id: number): Vulnerability | null {
  const rows = execQuery('SELECT * FROM vulnerabilities WHERE id = ?', [id]);
  return rows[0] as Vulnerability || null;
}

export function createVulnerability(v: Vulnerability): number {
  const fields = [
    'project_id', 'title', 'severity', 'status', 'cvss', 'cvss_vector', 'cwe',
    'file', 'line_start', 'line_end', 'code_snippet', 'description', 'impact',
    'reproduction_steps', 'suggested_fix', 'fix_diff', 'method', 'tool_name',
    'confidence', 'verified', 'false_positive', 'advisory', 'advisory_url',
    'submit_to', 'submit_email', 'email_chain_url', 'issue_url', 'response',
    'rejection_reason', 'sub_findings', 'disclosure_content', 'how_to_submit_content',
    'ai_triage', 'ai_summary', 'found_at', 'submitted_at', 'resolved_at'
  ];
  const values = fields.map(f => (v as any)[f] ?? null);
  const placeholders = fields.map(() => '?').join(', ');
  return execRun(
    `INSERT INTO vulnerabilities (${fields.join(', ')}) VALUES (${placeholders})`,
    values
  );
}

// Whitelist of columns that actually exist on the vulnerabilities
// table. Matches the CREATE TABLE above. Kept here so
// updateVulnerability silently drops unknown keys (e.g. legacy TS
// aliases like `line_number`, or type-only fields like `notes` that
// were never migrated) instead of letting SQLite return a 500 on the
// unknown-column error. If you add a new column, migrate the table
// AND extend this list.
const VULN_COLUMNS = new Set([
  'project_id', 'title', 'severity', 'status', 'cvss', 'cvss_vector', 'cwe',
  'file', 'line_start', 'line_end', 'code_snippet',
  'description', 'impact', 'reproduction_steps',
  'suggested_fix', 'fix_diff',
  'method', 'tool_name', 'confidence',
  'verified', 'false_positive',
  'advisory', 'advisory_url',
  'submit_to', 'submit_email', 'email_chain_url', 'issue_url',
  'response', 'rejection_reason',
  'sub_findings',
  'disclosure_content', 'how_to_submit_content',
  'ai_triage', 'ai_summary', 'manual_triage',
  'submitted_at', 'resolved_at',
]);

export function updateVulnerability(id: number, v: Partial<Vulnerability>): void {
  // Drop unknown keys before building the SQL. This avoids 500s when
  // callers send legacy aliases (e.g. the TS `line_number` field that
  // was never a real column) and provides a cheap safety net against
  // SQL injection via column names (only whitelisted identifiers can
  // reach the SET clause).
  const mut: Record<string, unknown> = {};
  for (const k of Object.keys(v)) {
    if (VULN_COLUMNS.has(k)) mut[k] = (v as any)[k];
  }

  // Auto-promote status from New/Open -> Triaged the moment a user
  // records triage content. This keeps the status column meaningful
  // without requiring a separate "mark triaged" click: if you've
  // written analysis (manual or AI), the finding has been triaged.
  // Explicit status in the update still wins — callers that want to
  // set Submitted/Fixed/Rejected/etc. are never overridden.
  const addsManual = typeof mut.manual_triage === 'string' && mut.manual_triage.trim().length > 0;
  const addsAi = typeof mut.ai_triage === 'string' && mut.ai_triage.trim().length > 0;
  if ((addsManual || addsAi) && mut.status === undefined) {
    const rows = execQuery('SELECT status FROM vulnerabilities WHERE id = ?', [id]);
    const current = (rows[0] as { status?: string } | undefined)?.status;
    if (current === 'New' || current === 'Open' || !current) {
      mut.status = 'Triaged';
    }
  }

  const fields = Object.keys(mut);
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map((f) => mut[f]);
  db.run(
    `UPDATE vulnerabilities SET ${setClause}, updated_at = datetime('now') WHERE id = ?`,
    [...values, id]
  );
  persistDb();
}

export function deleteVulnerability(id: number): void {
  db.run('DELETE FROM vulnerabilities WHERE id = ?', [id]);
  persistDb();
}

// ── Scans CRUD ─────────────────────────────────────────────────────────────

export function getAllScans(limit = 50): Scan[] {
  return execQuery(
    'SELECT * FROM scans ORDER BY started_at DESC LIMIT ?',
    [limit]
  ) as unknown as Scan[];
}

export function getScanById(id: number): Scan | null {
  const rows = execQuery('SELECT * FROM scans WHERE id = ?', [id]);
  return rows[0] as Scan || null;
}

export function createScan(s: Scan): number {
  return execRun(
    `INSERT INTO scans (project_id, tool_name, status, config)
     VALUES (?, ?, ?, ?)`,
    [s.project_id, s.tool_name, s.status || 'pending', s.config || null]
  );
}

export function updateScan(id: number, s: Partial<Scan>): void {
  const exclude = ['id'];
  const fields = Object.keys(s).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (s as any)[f]);
  db.run(`UPDATE scans SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

// ── Tools CRUD ─────────────────────────────────────────────────────────────

export function getAllTools(): Tool[] {
  return execQuery('SELECT * FROM tools ORDER BY name') as unknown as Tool[];
}

export function getToolById(id: number): Tool | null {
  const rows = execQuery('SELECT * FROM tools WHERE id = ?', [id]);
  return rows[0] as Tool || null;
}

export function getToolByName(name: string): Tool | null {
  const rows = execQuery('SELECT * FROM tools WHERE name = ?', [name]);
  return rows[0] as Tool || null;
}

export function upsertTool(t: Tool): number {
  const existing = getToolByName(t.name);
  if (existing) {
    const fields = ['category', 'description', 'docs', 'track_record', 'file_path', 'config_schema', 'enabled'];
    const setClause = safeSetClause(fields);
    const values = fields.map(f => (t as any)[f] ?? null);
    db.run(`UPDATE tools SET ${setClause} WHERE name = ?`, [...values, t.name]);
    persistDb();
    return existing.id!;
  }
  return execRun(
    `INSERT INTO tools (name, category, description, docs, track_record, file_path, config_schema, enabled)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [t.name, t.category || null, t.description || null, t.docs || null,
     t.track_record || null, t.file_path || null, t.config_schema || null,
     t.enabled ?? 1]
  );
}

export function updateTool(id: number, t: Partial<Tool>): void {
  const allowed = new Set(['name', 'category', 'description', 'docs', 'track_record', 'file_path', 'config_schema', 'enabled']);
  const fields = Object.keys(t).filter((k) => allowed.has(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  // Coerce enabled to a 0/1 integer since SQLite doesn't have booleans
  // and the column is INTEGER.
  const values = fields.map((f) => {
    const v = (t as any)[f];
    if (f === 'enabled') return v ? 1 : 0;
    return v ?? null;
  });
  db.run(`UPDATE tools SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteTool(id: number): void {
  db.run('DELETE FROM tools WHERE id = ?', [id]);
  persistDb();
}

// Bulk delete vulnerabilities by id list. Kept separate from
// deleteVulnerability() so the UI can show a "Delete N" action with
// one round-trip instead of N.
export function deleteVulnerabilitiesBulk(ids: number[]): number {
  if (!Array.isArray(ids) || ids.length === 0) return 0;
  const placeholders = ids.map(() => '?').join(',');
  db.run(`DELETE FROM vulnerabilities WHERE id IN (${placeholders})`, ids);
  persistDb();
  return ids.length;
}

// ── Checklists CRUD ────────────────────────────────────────────────────────

export function getAllChecklists(): Checklist[] {
  return execQuery('SELECT * FROM checklists ORDER BY name') as unknown as Checklist[];
}

export function getChecklistById(id: number): Checklist | null {
  const rows = execQuery('SELECT * FROM checklists WHERE id = ?', [id]);
  return rows[0] as Checklist || null;
}

export function createChecklist(c: Checklist): number {
  return execRun(
    `INSERT INTO checklists (name, source_url, category, total_items) VALUES (?, ?, ?, ?)`,
    [c.name, c.source_url || null, c.category || null, c.total_items || 0]
  );
}

export function getChecklistItems(checklistId: number): ChecklistItem[] {
  return execQuery('SELECT * FROM checklist_items WHERE checklist_id = ? ORDER BY id', [checklistId]) as unknown as ChecklistItem[];
}

export function createChecklistItem(item: ChecklistItem): number {
  return execRun(
    `INSERT INTO checklist_items (checklist_id, category, title, description, severity, tool_names, verified, vuln_id, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [item.checklist_id, item.category || null, item.title, item.description || null,
     item.severity || null, item.tool_names || null, item.verified || 0,
     item.vuln_id || null, item.notes || null]
  );
}

export function updateChecklist(id: number, c: Partial<Checklist>): void {
  const allowed = new Set(['name', 'source_url', 'category', 'total_items']);
  const fields = Object.keys(c).filter((k) => allowed.has(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map((f) => (c as any)[f] ?? null);
  db.run(`UPDATE checklists SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteChecklist(id: number): void {
  db.run('DELETE FROM checklist_items WHERE checklist_id = ?', [id]);
  db.run('DELETE FROM checklists WHERE id = ?', [id]);
  persistDb();
}

export function deleteChecklistItem(id: number): void {
  db.run('DELETE FROM checklist_items WHERE id = ?', [id]);
  persistDb();
}

// ── Plugins CRUD ───────────────────────────────────────────────────────────

export function getAllPlugins(): Plugin[] {
  return execQuery('SELECT * FROM plugins ORDER BY name') as unknown as Plugin[];
}

export function getPluginById(id: number): Plugin | null {
  const rows = execQuery('SELECT * FROM plugins WHERE id = ?', [id]);
  return rows[0] as Plugin || null;
}

export function createPlugin(p: Plugin): number {
  return execRun(
    `INSERT INTO plugins (name, type, source_url, install_path, version, manifest, enabled)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [p.name, p.type || null, p.source_url || null, p.install_path || null,
     p.version || null, p.manifest || null, p.enabled ?? 1]
  );
}

export function updatePlugin(id: number, p: Partial<Plugin>): void {
  const fields = Object.keys(p).filter(k => k !== 'id');
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (p as any)[f]);
  db.run(`UPDATE plugins SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

// ── AI Providers CRUD ──────────────────────────────────────────────────────
// Security CR-08: api_key is encrypted at rest via server/lib/crypto.
// Every read path decrypts before returning; every write encrypts
// before storing. Callers continue to pass / receive plaintext so
// encryption is transparent above this layer.

function _decryptProviderRow(row: AIProvider | null): AIProvider | null {
  if (!row) return row;
  try {
    return { ...row, api_key: (row as any).api_key ? decryptSecret((row as any).api_key) : (row as any).api_key };
  } catch (err: any) {
    // Surface a placeholder so the UI can at least render the rest of
    // the row even if one key is unreadable (e.g. operator rotated
    // VULNFORGE_DATA_KEY without running a re-encrypt pass).
    console.warn(`[crypto] could not decrypt api_key for provider "${row.name}": ${err?.message || err}`);
    return { ...row, api_key: '__undecryptable__' } as any;
  }
}

export function getAllAIProviders(): AIProvider[] {
  const rows = execQuery('SELECT * FROM ai_providers ORDER BY name') as unknown as AIProvider[];
  return rows.map((r) => _decryptProviderRow(r) as AIProvider);
}

export function getAIProviderById(id: number): AIProvider | null {
  const rows = execQuery('SELECT * FROM ai_providers WHERE id = ?', [id]);
  return _decryptProviderRow(rows[0] as AIProvider || null);
}

export function getEnabledAIProvider(): AIProvider | null {
  const rows = execQuery('SELECT * FROM ai_providers WHERE enabled = 1 LIMIT 1');
  return _decryptProviderRow(rows[0] as AIProvider || null);
}

export function upsertAIProvider(p: AIProvider): number {
  const encryptedKey = p.api_key ? encryptSecret(p.api_key) : null;
  const existing = execQuery('SELECT * FROM ai_providers WHERE name = ?', [p.name]);
  if (existing.length > 0) {
    db.run(
      `UPDATE ai_providers SET model = ?, api_key = ?, base_url = ?, enabled = ?, config = ? WHERE name = ?`,
      [p.model || null, encryptedKey, p.base_url || null, p.enabled ?? 0, p.config || null, p.name]
    );
    persistDb();
    return existing[0].id as number;
  }
  return execRun(
    `INSERT INTO ai_providers (name, model, api_key, base_url, enabled, config) VALUES (?, ?, ?, ?, ?, ?)`,
    [p.name, p.model || null, encryptedKey, p.base_url || null, p.enabled ?? 0, p.config || null]
  );
}

/**
 * One-time migration: find plaintext api_key rows and encrypt them.
 * Called once from initDb(). Safe to re-run — isEncrypted() makes
 * encryptSecret() idempotent.
 */
export function migrateAIProviderSecrets(): void {
  try {
    const rows = execQuery('SELECT id, name, api_key FROM ai_providers WHERE api_key IS NOT NULL AND api_key != \'\'');
    let migrated = 0;
    for (const r of rows) {
      const key = (r as any).api_key as string;
      if (!isEncrypted(key)) {
        const enc = encryptSecret(key);
        db.run('UPDATE ai_providers SET api_key = ? WHERE id = ?', [enc, (r as any).id]);
        migrated++;
      }
    }
    if (migrated > 0) {
      persistDb();
      console.log(`[crypto] migrated ${migrated} plaintext api_key rows to encrypted form`);
    }
  } catch (err: any) {
    console.warn(`[crypto] migrateAIProviderSecrets failed: ${err?.message || err}`);
  }
}

// ── Reports CRUD ───────────────────────────────────────────────────────────

export function getAllReports(): Report[] {
  return execQuery('SELECT * FROM reports ORDER BY created_at DESC');
}

export function getReportById(id: number): Report | null {
  const rows = execQuery('SELECT * FROM reports WHERE id = ?', [id]);
  return rows[0] as Report || null;
}

export function createReport(r: Report): number {
  return execRun(
    `INSERT INTO reports (vuln_id, type, format, content, generated_by) VALUES (?, ?, ?, ?, ?)`,
    [r.vuln_id || null, r.type || null, r.format || null, r.content || null, r.generated_by || null]
  );
}

// Edit an existing report (typically the AI-generated content after
// the user refined it). Only the content-bearing columns are
// whitelisted here - reports don't have an owner/timestamp relationship
// that should be user-editable.
export function updateReport(id: number, r: Partial<Report>): void {
  const allowed = new Set(['type', 'format', 'content', 'generated_by']);
  const fields = Object.keys(r).filter((k) => allowed.has(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map((f) => (r as any)[f] ?? null);
  db.run(`UPDATE reports SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteReport(id: number): void {
  db.run('DELETE FROM reports WHERE id = ?', [id]);
  persistDb();
}

// ── ScanFindings CRUD ──────────────────────────────────────────────────────

export interface ScanFindingFilters {
  scan_id?: number;
  project_id?: number;
  pipeline_id?: string;
  status?: string;
}

export function getScanFindings(filters: ScanFindingFilters = {}): ScanFinding[] {
  const conditions: string[] = [];
  const params: any[] = [];

  if (filters.scan_id !== undefined) { conditions.push('scan_id = ?'); params.push(filters.scan_id); }
  if (filters.project_id !== undefined) { conditions.push('project_id = ?'); params.push(filters.project_id); }
  if (filters.pipeline_id) { conditions.push('pipeline_id = ?'); params.push(filters.pipeline_id); }
  if (filters.status) { conditions.push('status = ?'); params.push(filters.status); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  return execQuery(`SELECT * FROM scan_findings ${where} ORDER BY id DESC`, params) as unknown as ScanFinding[];
}

export function getScanFindingById(id: number): ScanFinding | null {
  const rows = execQuery('SELECT * FROM scan_findings WHERE id = ?', [id]);
  return rows[0] as ScanFinding || null;
}

export function createScanFinding(f: ScanFinding): number {
  return execRun(
    `INSERT INTO scan_findings
       (scan_id, project_id, pipeline_id, title, severity, cvss, cwe, file, line_start, line_end,
        code_snippet, description, impact, tool_name, confidence, raw_output, status,
        rejection_reason, merged_tools, suggested_fix)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      f.scan_id ?? null, f.project_id ?? null, f.pipeline_id || '',
      f.title, f.severity || 'Medium', f.cvss || '', f.cwe || '',
      f.file || '', f.line_start ?? null, f.line_end ?? null,
      f.code_snippet || '', f.description || '', f.impact || '',
      f.tool_name || '', f.confidence || 'Medium',
      f.raw_output || '', f.status || 'pending', f.rejection_reason || '',
      f.merged_tools || '', f.suggested_fix || '',
    ]
  );
}

export function updateScanFinding(id: number, updates: Partial<ScanFinding>): void {
  const exclude = ['id', 'created_at'];
  const fields = Object.keys(updates).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE scan_findings SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteScanFinding(id: number): void {
  db.run('DELETE FROM scan_findings WHERE id = ?', [id]);
  persistDb();
}

export function countScanFindings(filters: ScanFindingFilters = {}): Record<string, number> {
  const params: any[] = [];
  const conditions: string[] = [];
  if (filters.scan_id !== undefined) { conditions.push('scan_id = ?'); params.push(filters.scan_id); }
  if (filters.project_id !== undefined) { conditions.push('project_id = ?'); params.push(filters.project_id); }
  if (filters.pipeline_id) { conditions.push('pipeline_id = ?'); params.push(filters.pipeline_id); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const rows = execQuery(
    `SELECT status, COUNT(*) as c FROM scan_findings ${where} GROUP BY status`,
    params
  );
  const counts: Record<string, number> = { pending: 0, accepted: 0, rejected: 0, auto_rejected: 0 };
  for (const row of rows) { counts[row.status as string] = row.c as number; }
  return counts;
}

// ── Stats ──────────────────────────────────────────────────────────────────

export function getStats(): Record<string, any> {
  const totalVulns = (execQuery('SELECT COUNT(*) as c FROM vulnerabilities')[0]?.c as number) || 0;
  const critical = (execQuery("SELECT COUNT(*) as c FROM vulnerabilities WHERE severity = 'Critical'")[0]?.c as number) || 0;
  const high = (execQuery("SELECT COUNT(*) as c FROM vulnerabilities WHERE severity = 'High'")[0]?.c as number) || 0;
  const medium = (execQuery("SELECT COUNT(*) as c FROM vulnerabilities WHERE severity = 'Medium'")[0]?.c as number) || 0;
  const low = (execQuery("SELECT COUNT(*) as c FROM vulnerabilities WHERE severity = 'Low'")[0]?.c as number) || 0;
  const submitted = (execQuery("SELECT COUNT(*) as c FROM vulnerabilities WHERE status IN ('Submitted','Fixed','Responded','HackerOne','Partial')")[0]?.c as number) || 0;
  const verified = (execQuery('SELECT COUNT(*) as c FROM vulnerabilities WHERE verified = 1')[0]?.c as number) || 0;
  const totalProjects = (execQuery('SELECT COUNT(*) as c FROM projects')[0]?.c as number) || 0;
  const totalTools = (execQuery('SELECT COUNT(*) as c FROM tools WHERE enabled = 1')[0]?.c as number) || 0;
  const recentScans = execQuery('SELECT * FROM scans ORDER BY started_at DESC LIMIT 5');
  const recentVulns = execQuery('SELECT * FROM vulnerabilities ORDER BY found_at DESC LIMIT 5');
  const bySeverity = execQuery(
    "SELECT severity, COUNT(*) as count FROM vulnerabilities WHERE severity IS NOT NULL GROUP BY severity"
  );
  const byStatus = execQuery(
    "SELECT status, COUNT(*) as count FROM vulnerabilities WHERE status IS NOT NULL GROUP BY status"
  );

  return {
    totalVulns,
    critical,
    high,
    medium,
    low,
    submitted,
    verified,
    totalProjects,
    totalTools,
    recentScans,
    recentVulns,
    bySeverity,
    byStatus,
  };
}

// ── Pipeline Runs CRUD ────────────────────────────────────────────────────

export function createPipelineRun(p: PipelineRun): string {
  db.run(
    `INSERT INTO pipeline_runs
       (id, project_id, status, current_stage, progress, scan_job_ids,
        findings_total, findings_after_filter, findings_after_verify, config, error)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      p.id, p.project_id, p.status || 'pending', p.current_stage || '',
      p.progress || 0, p.scan_job_ids || '[]',
      p.findings_total || 0, p.findings_after_filter || 0,
      p.findings_after_verify || 0, p.config || '{}', p.error || null,
    ]
  );
  persistDb();
  return p.id;
}

export function getPipelineRun(id: string): PipelineRun | null {
  const rows = execQuery('SELECT * FROM pipeline_runs WHERE id = ?', [id]);
  return rows[0] as PipelineRun || null;
}

export function getPipelineRuns(status?: string): PipelineRun[] {
  if (status) {
    return execQuery(
      'SELECT * FROM pipeline_runs WHERE status = ? ORDER BY started_at DESC',
      [status]
    ) as unknown as PipelineRun[];
  }
  return execQuery('SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT 50') as unknown as PipelineRun[];
}

export function getActivePipelineRuns(): PipelineRun[] {
  return execQuery(
    "SELECT * FROM pipeline_runs WHERE status NOT IN ('ready', 'failed', 'cancelled') ORDER BY started_at DESC"
  ) as unknown as PipelineRun[];
}

export function updatePipelineRun(id: string, updates: Partial<PipelineRun>): void {
  const exclude = ['id', 'started_at'];
  const fields = Object.keys(updates).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE pipeline_runs SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

// ── Routing Rules CRUD ────────────────────────────────────────────────────

export interface RoutingRuleRow {
  id?: number;
  task: string;
  provider: string;
  model: string;
  priority: number;
  enabled: number;
}

// ── Research Workspace types ──────────────────────────────────────────────

export interface NoteRow {
  id?: number;
  provider: string;
  external_id: string;
  title: string;
  type?: string;
  status?: string;
  tags?: string;             // JSON array
  project_id?: number;
  finding_ids?: string;      // JSON array
  file_refs?: string;        // JSON array
  confidence?: number;
  created_at?: string;
  updated_at?: string;
}

export interface NotesProviderRow {
  id?: number;
  name: string;
  type: string;
  enabled?: number;
  is_default?: number;
  config?: string;           // JSON
}

export interface SessionStateRow {
  id?: number;
  scope: string;             // global | project | finding
  scope_id?: number;
  key: string;
  value: string;             // JSON
  updated_at?: string;
}

// ── Runtime Analysis (Theme 3) types ──────────────────────────────────────

export interface RuntimeJobRow {
  id: string;
  project_id?: number;
  finding_id?: number;
  type: string;               // fuzz | debug | capture | portscan | mitm
  tool: string;               // libfuzzer | afl | gdb | tcpdump | tshark | nmap
  status?: string;            // queued | running | paused | completed | failed | cancelled
  config?: string;            // JSON
  output_dir?: string;
  stats?: string;             // JSON
  error?: string;
  started_at?: string;
  completed_at?: string;
}

export interface FuzzCrashRow {
  id?: number;
  job_id: string;
  stack_hash?: string;
  input_path: string;
  input_size?: number;
  signal?: string;
  stack_trace?: string;
  exploitability?: string;    // high | medium | low | unknown
  minimized?: number;         // 0 or 1
  linked_finding_id?: number;
  discovered_at?: string;
}

export interface CaptureRow {
  id?: number;
  job_id: string;
  pcap_path: string;
  packet_count?: number;
  bytes?: number;
  filter?: string;
  start_time?: string;
  end_time?: string;
}

// ── Historical Intelligence (Theme 4) types ──────────────────────────────

export interface BisectResultRow {
  id?: number;
  job_id: string;
  first_bad_commit?: string;
  first_bad_date?: string;
  commit_message?: string;
  diff?: string;
  author?: string;
  tests_run?: number;
}

export interface CveIntelRow {
  id?: number;
  cve_id: string;
  published?: string;
  modified?: string;
  severity?: string;
  cvss_score?: number;
  description?: string;
  affected_products?: string;  // JSON
  cve_references?: string;     // JSON
  synced_at?: string;
}

export interface CveProjectMatchRow {
  id?: number;
  cve_id: string;
  project_id: number;
  match_reason?: string;       // dependency | pattern | manual
  dependency_name?: string;
  dependency_version?: string;
  confidence?: number;
  matched_at?: string;
}

// ── Exploit Development (Theme 2) types ──────────────────────────────────

export interface ExploitRow {
  id?: number;
  finding_id?: number;
  title: string;
  language?: string;
  code?: string;
  tier?: string;                 // pattern | manual | traced | poc | weaponized
  notes?: string;
  template?: string;
  last_run_status?: string;
  last_run_output?: string;
  created_at?: string;
  updated_at?: string;
}

export interface ProofLadderRow {
  id?: number;
  finding_id: number;
  current_tier?: string;
  pattern_at?: string;
  manual_at?: string;
  traced_at?: string;
  poc_at?: string;
  weaponized_at?: string;
  notes?: string;
  updated_at?: string;
}

// ── Disclosure & Bounty Ops (Theme 5) types ───────────────────────────────

export interface VendorRow {
  id?: number;
  name: string;
  security_email?: string;
  disclosure_policy_url?: string;
  platform?: string;              // 'hackerone' | 'bugcrowd' | 'intigriti' | 'direct'
  typical_response_days?: number;
  preferred_format?: string;      // 'email' | 'platform' | 'cve'
  notes?: string;
  created_at?: string;
}

export interface DisclosureRow {
  id?: number;
  finding_id?: number;
  vendor_id?: number;
  title: string;
  status?: string;                // draft | submitted | acknowledged | fixed | resolved | public | cancelled
  submission_date?: string;
  sla_days?: number;
  response_date?: string;
  patch_date?: string;
  public_date?: string;
  cve_id?: string;
  tracking_id?: string;
  bounty_amount?: number;
  bounty_currency?: string;
  bounty_paid_date?: string;
  notes?: string;
  created_at?: string;
  updated_at?: string;
}

export interface DisclosureEventRow {
  id?: number;
  disclosure_id: number;
  event_type: string;              // submitted | acknowledged | fix_proposed | fix_deployed | cve_assigned | public_disclosure | bounty_paid
  event_date?: string;
  actor?: string;
  description?: string;
}

// ── User Accounts (Phase 14) ──────────────────────────────────────────────

export interface UserRow {
  id?: number;
  username: string;
  password_hash: string;
  role: 'admin' | 'researcher' | 'viewer';
  display_name?: string;
  email?: string;
  active?: number;
  last_login?: string;
  created_at?: string;
}

export interface ApiTokenRow {
  id?: number;
  user_id: number;
  token: string;
  name?: string;
  expires_at?: string;
  created_at?: string;
}

// ── External Integrations ─────────────────────────────────────────────────

export interface IntegrationRow {
  id?: number;
  name: string;
  type: string;       // ticketing | messaging
  enabled?: number;
  config?: string;     // JSON
  created_at?: string;
}

export interface IntegrationTicketRow {
  id?: number;
  integration_id: number;
  finding_id?: number;
  disclosure_id?: number;
  ticket_id: string;
  ticket_url?: string;
  status?: string;
  last_synced?: string;
  created_at?: string;
}

// CR-10 helpers: integrations.config carries Slack/Jira/GitHub tokens
// + webhook URLs. Encrypt the whole JSON blob at rest, decrypt on
// read. Keeps the shape opaque at the SQLite layer so a DB leak
// doesn't hand over the tokens.

function _decryptIntegrationRow(row: IntegrationRow | null): IntegrationRow | null {
  if (!row) return row;
  try {
    return { ...row, config: row.config ? decryptSecret(row.config) : (row.config as any) };
  } catch (err: any) {
    console.warn(`[crypto] could not decrypt integrations.config for "${row.name}": ${err?.message || err}`);
    return { ...row, config: '{"__undecryptable__":true}' };
  }
}

export function getIntegrations(): IntegrationRow[] {
  const rows = execQuery('SELECT * FROM integrations ORDER BY name') as unknown as IntegrationRow[];
  return rows.map((r) => _decryptIntegrationRow(r) as IntegrationRow);
}

export function getIntegrationById(id: number): IntegrationRow | null {
  const rows = execQuery('SELECT * FROM integrations WHERE id = ?', [id]);
  return _decryptIntegrationRow(rows[0] as IntegrationRow || null);
}

export function createIntegration(i: IntegrationRow): number {
  const cipher = i.config ? encryptSecret(i.config) : encryptSecret('{}');
  return execRun(
    'INSERT INTO integrations (name, type, enabled, config) VALUES (?, ?, ?, ?)',
    [i.name, i.type, i.enabled ?? 0, cipher]
  );
}

export function updateIntegration(id: number, updates: Partial<IntegrationRow>): void {
  const fields = Object.keys(updates).filter(k => k !== 'id' && k !== 'created_at');
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => {
    // Encrypt config on the way in so every caller doesn't have to
    // remember (and so the typed-integration code path doesn't need
    // to know about crypto). All other columns pass through.
    if (f === 'config') {
      const v = (updates as any)[f];
      return v ? encryptSecret(String(v)) : v;
    }
    return (updates as any)[f];
  });
  db.run(`UPDATE integrations SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

/**
 * Boot-time migration for integrations.config rows. Same shape as
 * migrateAIProviderSecrets() - walks pre-existing plaintext rows and
 * encrypts them in place. Idempotent.
 */
export function migrateIntegrationSecrets(): void {
  try {
    const rows = execQuery('SELECT id, name, config FROM integrations WHERE config IS NOT NULL AND config != \'\'');
    let migrated = 0;
    for (const r of rows) {
      const cfg = (r as any).config as string;
      if (!isEncrypted(cfg)) {
        db.run('UPDATE integrations SET config = ? WHERE id = ?', [encryptSecret(cfg), (r as any).id]);
        migrated++;
      }
    }
    if (migrated > 0) {
      persistDb();
      console.log(`[crypto] migrated ${migrated} integrations.config rows to encrypted form`);
    }
  } catch (err: any) {
    console.warn(`[crypto] migrateIntegrationSecrets failed: ${err?.message || err}`);
  }
}

export function deleteIntegration(id: number): void {
  db.run('DELETE FROM integration_tickets WHERE integration_id = ?', [id]);
  db.run('DELETE FROM integrations WHERE id = ?', [id]);
  persistDb();
}

export function getIntegrationTickets(filters: { finding_id?: number; disclosure_id?: number; integration_id?: number } = {}): IntegrationTicketRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.finding_id !== undefined) { conds.push('finding_id = ?'); params.push(filters.finding_id); }
  if (filters.disclosure_id !== undefined) { conds.push('disclosure_id = ?'); params.push(filters.disclosure_id); }
  if (filters.integration_id !== undefined) { conds.push('integration_id = ?'); params.push(filters.integration_id); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  return execQuery(`SELECT * FROM integration_tickets ${where} ORDER BY created_at DESC`, params) as unknown as IntegrationTicketRow[];
}

export function createIntegrationTicket(t: IntegrationTicketRow): number {
  return execRun(
    'INSERT INTO integration_tickets (integration_id, finding_id, disclosure_id, ticket_id, ticket_url, status) VALUES (?, ?, ?, ?, ?, ?)',
    [t.integration_id, t.finding_id ?? null, t.disclosure_id ?? null, t.ticket_id, t.ticket_url || null, t.status || null]
  );
}

export function updateIntegrationTicket(id: number, updates: Partial<IntegrationTicketRow>): void {
  const fields = Object.keys(updates).filter(k => k !== 'id' && k !== 'created_at');
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE integration_tickets SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

// ── Teach Mode + Pattern Mining (Phase 15) ───────────────────────────────

export interface TeachExampleRow {
  id?: number;
  finding_id?: number;
  action: string;                  // confirmed | rejected | false_positive
  reasoning?: string;
  pattern_extracted?: string;
  code_context?: string;
  user_id?: number;
  created_at?: string;
}

export interface LearnedPatternRow {
  id?: number;
  name: string;
  source_finding_id?: number;
  pattern_type?: string;
  grep_pattern?: string;
  description?: string;
  confidence?: number;
  times_matched?: number;
  created_at?: string;
}

export interface AuditLogRow {
  id?: number;
  ts?: string;
  actor?: string;
  action: string;                  // create | update | delete | view | export | import
  entity_type?: string;            // vulnerability | project | disclosure | note | ...
  entity_id?: string;
  details?: string;                // JSON
}

export function getDbRoutingRules(): RoutingRuleRow[] {
  return execQuery('SELECT * FROM routing_rules ORDER BY task, priority ASC') as unknown as RoutingRuleRow[];
}

export function setDbRoutingRules(rules: Omit<RoutingRuleRow, 'id'>[]): void {
  db.run('DELETE FROM routing_rules');
  for (const r of rules) {
    db.run(
      'INSERT INTO routing_rules (task, provider, model, priority, enabled) VALUES (?, ?, ?, ?, ?)',
      [r.task, r.provider, r.model, r.priority ?? 1, r.enabled ?? 1]
    );
  }
  persistDb();
}

export function countRoutingRules(): number {
  const rows = execQuery('SELECT COUNT(*) as c FROM routing_rules');
  return (rows[0]?.c as number) || 0;
}

// ── Notes CRUD ────────────────────────────────────────────────────────────

export interface NoteFilters {
  project_id?: number;
  type?: string;
  status?: string;
  tag?: string;
  finding_id?: number;
  limit?: number;
  offset?: number;
}

export function getNotes(filters: NoteFilters = {}): NoteRow[] {
  const conds: string[] = [];
  const params: any[] = [];

  if (filters.project_id !== undefined) { conds.push('project_id = ?'); params.push(filters.project_id); }
  if (filters.type) { conds.push('type = ?'); params.push(filters.type); }
  if (filters.status) { conds.push('status = ?'); params.push(filters.status); }
  if (filters.tag) { conds.push("tags LIKE ?"); params.push(`%"${filters.tag}"%`); }
  if (filters.finding_id !== undefined) { conds.push("finding_ids LIKE ?"); params.push(`%${filters.finding_id}%`); }

  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const limit = filters.limit ? `LIMIT ${Number(filters.limit)}` : 'LIMIT 200';
  const offset = filters.offset ? `OFFSET ${Number(filters.offset)}` : '';

  return execQuery(
    `SELECT * FROM notes ${where} ORDER BY updated_at DESC ${limit} ${offset}`,
    params
  ) as unknown as NoteRow[];
}

export function getNoteById(id: number): NoteRow | null {
  const rows = execQuery('SELECT * FROM notes WHERE id = ?', [id]);
  return rows[0] as NoteRow || null;
}

export function createNote(n: NoteRow): number {
  return execRun(
    `INSERT INTO notes (provider, external_id, title, type, status, tags, project_id, finding_ids, file_refs, confidence)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      n.provider, n.external_id, n.title,
      n.type || 'note', n.status || null,
      n.tags || '[]', n.project_id ?? null,
      n.finding_ids || '[]', n.file_refs || '[]',
      n.confidence ?? null,
    ]
  );
}

export function updateNote(id: number, updates: Partial<NoteRow>): void {
  const exclude = ['id', 'created_at'];
  const fields = Object.keys(updates).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(
    `UPDATE notes SET ${setClause}, updated_at = datetime('now') WHERE id = ?`,
    [...values, id]
  );
  persistDb();
}

export function deleteNote(id: number): void {
  db.run('DELETE FROM notes WHERE id = ?', [id]);
  persistDb();
}

// ── Notes Providers CRUD ──────────────────────────────────────────────────

export function getNotesProviders(): NotesProviderRow[] {
  return execQuery('SELECT * FROM notes_providers ORDER BY is_default DESC, name ASC') as unknown as NotesProviderRow[];
}

export function getNotesProviderById(id: number): NotesProviderRow | null {
  const rows = execQuery('SELECT * FROM notes_providers WHERE id = ?', [id]);
  return rows[0] as NotesProviderRow || null;
}

export function getNotesProviderByName(name: string): NotesProviderRow | null {
  const rows = execQuery('SELECT * FROM notes_providers WHERE name = ?', [name]);
  return rows[0] as NotesProviderRow || null;
}

export function getDefaultNotesProvider(): NotesProviderRow | null {
  const rows = execQuery('SELECT * FROM notes_providers WHERE is_default = 1 AND enabled = 1 LIMIT 1');
  return rows[0] as NotesProviderRow || null;
}

export function createNotesProvider(p: NotesProviderRow): number {
  return execRun(
    `INSERT INTO notes_providers (name, type, enabled, is_default, config) VALUES (?, ?, ?, ?, ?)`,
    [p.name, p.type, p.enabled ?? 1, p.is_default ?? 0, p.config || '{}']
  );
}

export function updateNotesProvider(id: number, updates: Partial<NotesProviderRow>): void {
  const fields = Object.keys(updates).filter(k => k !== 'id');
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE notes_providers SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteNotesProvider(id: number): void {
  db.run('DELETE FROM notes_providers WHERE id = ?', [id]);
  persistDb();
}

// ── Session State CRUD ────────────────────────────────────────────────────

export function getSessionState(scope: string, scope_id: number | null, key?: string): SessionStateRow[] {
  if (key) {
    if (scope_id === null) {
      return execQuery('SELECT * FROM session_state WHERE scope = ? AND scope_id IS NULL AND key = ?', [scope, key]) as unknown as SessionStateRow[];
    }
    return execQuery('SELECT * FROM session_state WHERE scope = ? AND scope_id = ? AND key = ?', [scope, scope_id, key]) as unknown as SessionStateRow[];
  }
  if (scope_id === null) {
    return execQuery('SELECT * FROM session_state WHERE scope = ? AND scope_id IS NULL', [scope]) as unknown as SessionStateRow[];
  }
  return execQuery('SELECT * FROM session_state WHERE scope = ? AND scope_id = ?', [scope, scope_id]) as unknown as SessionStateRow[];
}

export function setSessionState(scope: string, scope_id: number | null, key: string, value: string): void {
  // Upsert via DELETE + INSERT to avoid UNIQUE constraint issues with NULL
  if (scope_id === null) {
    db.run('DELETE FROM session_state WHERE scope = ? AND scope_id IS NULL AND key = ?', [scope, key]);
    db.run(
      'INSERT INTO session_state (scope, scope_id, key, value) VALUES (?, NULL, ?, ?)',
      [scope, key, value]
    );
  } else {
    db.run('DELETE FROM session_state WHERE scope = ? AND scope_id = ? AND key = ?', [scope, scope_id, key]);
    db.run(
      'INSERT INTO session_state (scope, scope_id, key, value) VALUES (?, ?, ?, ?)',
      [scope, scope_id, key, value]
    );
  }
  persistDb();
}

// ── Runtime Jobs CRUD ─────────────────────────────────────────────────────

export interface RuntimeJobFilters {
  status?: string;
  type?: string;
  project_id?: number;
  finding_id?: number;
  limit?: number;
}

export function getRuntimeJobs(filters: RuntimeJobFilters = {}): RuntimeJobRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.status) { conds.push('status = ?'); params.push(filters.status); }
  if (filters.type) { conds.push('type = ?'); params.push(filters.type); }
  if (filters.project_id !== undefined) { conds.push('project_id = ?'); params.push(filters.project_id); }
  if (filters.finding_id !== undefined) { conds.push('finding_id = ?'); params.push(filters.finding_id); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const limit = filters.limit ? `LIMIT ${Number(filters.limit)}` : 'LIMIT 100';
  return execQuery(
    `SELECT * FROM runtime_jobs ${where} ORDER BY started_at DESC ${limit}`,
    params
  ) as unknown as RuntimeJobRow[];
}

export function getRuntimeJobById(id: string): RuntimeJobRow | null {
  const rows = execQuery('SELECT * FROM runtime_jobs WHERE id = ?', [id]);
  return rows[0] as RuntimeJobRow || null;
}

export function createRuntimeJob(j: RuntimeJobRow): string {
  db.run(
    `INSERT INTO runtime_jobs (id, project_id, finding_id, type, tool, status, config, output_dir, stats)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      j.id, j.project_id ?? null, j.finding_id ?? null,
      j.type, j.tool, j.status || 'queued',
      j.config || '{}', j.output_dir || null, j.stats || '{}',
    ]
  );
  persistDb();
  return j.id;
}

export function updateRuntimeJob(id: string, updates: Partial<RuntimeJobRow>): void {
  const exclude = ['id', 'started_at'];
  const fields = Object.keys(updates).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE runtime_jobs SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteRuntimeJob(id: string): void {
  db.run('DELETE FROM fuzz_crashes WHERE job_id = ?', [id]);
  db.run('DELETE FROM captures WHERE job_id = ?', [id]);
  db.run('DELETE FROM sandbox_snapshots WHERE job_id = ?', [id]);
  db.run('DELETE FROM runtime_jobs WHERE id = ?', [id]);
  persistDb();
}

// ── Fuzz Crashes CRUD ─────────────────────────────────────────────────────

export function getFuzzCrashes(filters: { job_id?: string; stack_hash?: string; linked_finding_id?: number } = {}): FuzzCrashRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.job_id) { conds.push('job_id = ?'); params.push(filters.job_id); }
  if (filters.stack_hash) { conds.push('stack_hash = ?'); params.push(filters.stack_hash); }
  if (filters.linked_finding_id !== undefined) { conds.push('linked_finding_id = ?'); params.push(filters.linked_finding_id); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  return execQuery(
    `SELECT * FROM fuzz_crashes ${where} ORDER BY discovered_at DESC`,
    params
  ) as unknown as FuzzCrashRow[];
}

export function getFuzzCrashById(id: number): FuzzCrashRow | null {
  const rows = execQuery('SELECT * FROM fuzz_crashes WHERE id = ?', [id]);
  return rows[0] as FuzzCrashRow || null;
}

export function createFuzzCrash(c: FuzzCrashRow): number {
  return execRun(
    `INSERT INTO fuzz_crashes (job_id, stack_hash, input_path, input_size, signal, stack_trace, exploitability, minimized, linked_finding_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      c.job_id, c.stack_hash || null, c.input_path,
      c.input_size ?? null, c.signal || null, c.stack_trace || null,
      c.exploitability || 'unknown', c.minimized ?? 0, c.linked_finding_id ?? null,
    ]
  );
}

export function updateFuzzCrash(id: number, updates: Partial<FuzzCrashRow>): void {
  const exclude = ['id', 'discovered_at'];
  const fields = Object.keys(updates).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE fuzz_crashes SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

// ── Captures CRUD ─────────────────────────────────────────────────────────

export function getCaptures(filters: { job_id?: string } = {}): CaptureRow[] {
  if (filters.job_id) {
    return execQuery('SELECT * FROM captures WHERE job_id = ? ORDER BY start_time DESC', [filters.job_id]) as unknown as CaptureRow[];
  }
  return execQuery('SELECT * FROM captures ORDER BY start_time DESC LIMIT 50') as unknown as CaptureRow[];
}

export function createCapture(c: CaptureRow): number {
  return execRun(
    `INSERT INTO captures (job_id, pcap_path, packet_count, bytes, filter, start_time, end_time)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      c.job_id, c.pcap_path,
      c.packet_count ?? 0, c.bytes ?? 0,
      c.filter || null, c.start_time || null, c.end_time || null,
    ]
  );
}

export function updateCapture(id: number, updates: Partial<CaptureRow>): void {
  const fields = Object.keys(updates).filter(k => k !== 'id');
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE captures SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

// ── Bisect Results CRUD ─────────────────────────────────────────────────

export function getBisectResults(filters: { job_id?: string } = {}): BisectResultRow[] {
  if (filters.job_id) {
    return execQuery('SELECT * FROM bisect_results WHERE job_id = ?', [filters.job_id]) as unknown as BisectResultRow[];
  }
  return execQuery('SELECT * FROM bisect_results ORDER BY id DESC LIMIT 50') as unknown as BisectResultRow[];
}

export function createBisectResult(b: BisectResultRow): number {
  return execRun(
    `INSERT INTO bisect_results (job_id, first_bad_commit, first_bad_date, commit_message, diff, author, tests_run)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [b.job_id, b.first_bad_commit || null, b.first_bad_date || null, b.commit_message || null, b.diff || null, b.author || null, b.tests_run ?? 0]
  );
}

// ── CVE Intel CRUD ──────────────────────────────────────────────────────

export function getCveIntel(filters: { severity?: string; since?: string; limit?: number } = {}): CveIntelRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.severity) { conds.push('severity = ?'); params.push(filters.severity); }
  if (filters.since) { conds.push('published >= ?'); params.push(filters.since); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const limit = filters.limit ? `LIMIT ${Number(filters.limit)}` : 'LIMIT 100';
  return execQuery(`SELECT * FROM cve_intel ${where} ORDER BY published DESC ${limit}`, params) as unknown as CveIntelRow[];
}

export function getCveIntelById(cve_id: string): CveIntelRow | null {
  const rows = execQuery('SELECT * FROM cve_intel WHERE cve_id = ?', [cve_id]);
  return rows[0] as CveIntelRow || null;
}

export function upsertCveIntel(c: CveIntelRow): void {
  const existing = getCveIntelById(c.cve_id);
  if (existing) {
    db.run(
      `UPDATE cve_intel SET published = ?, modified = ?, severity = ?, cvss_score = ?,
                            description = ?, affected_products = ?, cve_references = ?, synced_at = datetime('now')
       WHERE cve_id = ?`,
      [c.published || null, c.modified || null, c.severity || null, c.cvss_score ?? null,
       c.description || null, c.affected_products || null, c.cve_references || null, c.cve_id]
    );
  } else {
    db.run(
      `INSERT INTO cve_intel (cve_id, published, modified, severity, cvss_score, description, affected_products, cve_references)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [c.cve_id, c.published || null, c.modified || null, c.severity || null, c.cvss_score ?? null,
       c.description || null, c.affected_products || null, c.cve_references || null]
    );
  }
  persistDb();
}

// ── CVE Project Matches CRUD ────────────────────────────────────────────

export function getCveProjectMatches(filters: { project_id?: number; cve_id?: string } = {}): CveProjectMatchRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.project_id !== undefined) { conds.push('project_id = ?'); params.push(filters.project_id); }
  if (filters.cve_id) { conds.push('cve_id = ?'); params.push(filters.cve_id); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  return execQuery(`SELECT * FROM cve_project_matches ${where} ORDER BY matched_at DESC`, params) as unknown as CveProjectMatchRow[];
}

export function createCveProjectMatch(m: CveProjectMatchRow): number {
  return execRun(
    `INSERT INTO cve_project_matches (cve_id, project_id, match_reason, dependency_name, dependency_version, confidence)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [m.cve_id, m.project_id, m.match_reason || null, m.dependency_name || null, m.dependency_version || null, m.confidence ?? null]
  );
}

// ── Exploits CRUD ────────────────────────────────────────────────────────

export function getExploits(filters: { finding_id?: number; tier?: string } = {}): ExploitRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.finding_id !== undefined) { conds.push('finding_id = ?'); params.push(filters.finding_id); }
  if (filters.tier) { conds.push('tier = ?'); params.push(filters.tier); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  return execQuery(`SELECT * FROM exploits ${where} ORDER BY updated_at DESC LIMIT 200`, params) as unknown as ExploitRow[];
}

export function getExploitById(id: number): ExploitRow | null {
  const rows = execQuery('SELECT * FROM exploits WHERE id = ?', [id]);
  return rows[0] as ExploitRow || null;
}

export function createExploit(e: ExploitRow): number {
  return execRun(
    `INSERT INTO exploits (finding_id, title, language, code, tier, notes, template)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [e.finding_id ?? null, e.title, e.language || 'python', e.code || '', e.tier || 'pattern', e.notes || '', e.template || null]
  );
}

export function updateExploit(id: number, updates: Partial<ExploitRow>): void {
  const exclude = ['id', 'created_at'];
  const fields = Object.keys(updates).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(
    `UPDATE exploits SET ${setClause}, updated_at = datetime('now') WHERE id = ?`,
    [...values, id]
  );
  persistDb();
}

export function deleteExploit(id: number): void {
  db.run('DELETE FROM exploits WHERE id = ?', [id]);
  persistDb();
}

// ── Proof Ladder CRUD ────────────────────────────────────────────────────

export function getProofLadder(finding_id: number): ProofLadderRow | null {
  const rows = execQuery('SELECT * FROM proof_ladder WHERE finding_id = ?', [finding_id]);
  return rows[0] as ProofLadderRow || null;
}

export function setProofTier(finding_id: number, tier: string, notes?: string): void {
  const now = new Date().toISOString();
  const tierCol = `${tier}_at`;
  const existing = getProofLadder(finding_id);
  if (existing) {
    // Build an update that sets the current tier + the corresponding timestamp column
    const updates: string[] = ['current_tier = ?', `${tierCol} = COALESCE(${tierCol}, ?)`, "updated_at = datetime('now')"];
    const params: any[] = [tier, now];
    if (notes !== undefined) { updates.push('notes = ?'); params.push(notes); }
    params.push(finding_id);
    db.run(`UPDATE proof_ladder SET ${updates.join(', ')} WHERE finding_id = ?`, params);
  } else {
    db.run(
      `INSERT INTO proof_ladder (finding_id, current_tier, ${tierCol}, notes) VALUES (?, ?, ?, ?)`,
      [finding_id, tier, now, notes || '']
    );
  }
  persistDb();
}

export function getAllProofLadders(): ProofLadderRow[] {
  return execQuery('SELECT * FROM proof_ladder ORDER BY updated_at DESC LIMIT 500') as unknown as ProofLadderRow[];
}

// ── Vendors CRUD ────────────────────────────────────────────────────────

export function getVendors(): VendorRow[] {
  return execQuery('SELECT * FROM vendors ORDER BY name') as unknown as VendorRow[];
}

export function getVendorById(id: number): VendorRow | null {
  const rows = execQuery('SELECT * FROM vendors WHERE id = ?', [id]);
  return rows[0] as VendorRow || null;
}

export function createVendor(v: VendorRow): number {
  return execRun(
    `INSERT INTO vendors (name, security_email, disclosure_policy_url, platform, typical_response_days, preferred_format, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [v.name, v.security_email || null, v.disclosure_policy_url || null, v.platform || null,
     v.typical_response_days ?? null, v.preferred_format || null, v.notes || '']
  );
}

export function updateVendor(id: number, updates: Partial<VendorRow>): void {
  const fields = Object.keys(updates).filter(k => k !== 'id' && k !== 'created_at');
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE vendors SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteVendor(id: number): void {
  db.run('DELETE FROM vendors WHERE id = ?', [id]);
  persistDb();
}

// ── Disclosures CRUD ────────────────────────────────────────────────────

export function getDisclosures(filters: { status?: string; vendor_id?: number; finding_id?: number } = {}): DisclosureRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.status) { conds.push('status = ?'); params.push(filters.status); }
  if (filters.vendor_id !== undefined) { conds.push('vendor_id = ?'); params.push(filters.vendor_id); }
  if (filters.finding_id !== undefined) { conds.push('finding_id = ?'); params.push(filters.finding_id); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  return execQuery(
    `SELECT * FROM disclosures ${where} ORDER BY updated_at DESC LIMIT 200`,
    params
  ) as unknown as DisclosureRow[];
}

export function getDisclosureById(id: number): DisclosureRow | null {
  const rows = execQuery('SELECT * FROM disclosures WHERE id = ?', [id]);
  return rows[0] as DisclosureRow || null;
}

export function createDisclosure(d: DisclosureRow): number {
  return execRun(
    `INSERT INTO disclosures (finding_id, vendor_id, title, status, submission_date, sla_days, cve_id, tracking_id, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      d.finding_id ?? null, d.vendor_id ?? null, d.title,
      d.status || 'draft', d.submission_date || null,
      d.sla_days ?? 90, d.cve_id || null, d.tracking_id || null, d.notes || '',
    ]
  );
}

export function updateDisclosure(id: number, updates: Partial<DisclosureRow>): void {
  const exclude = ['id', 'created_at'];
  const fields = Object.keys(updates).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(
    `UPDATE disclosures SET ${setClause}, updated_at = datetime('now') WHERE id = ?`,
    [...values, id]
  );
  persistDb();
}

export function deleteDisclosure(id: number): void {
  db.run('DELETE FROM disclosure_events WHERE disclosure_id = ?', [id]);
  db.run('DELETE FROM disclosures WHERE id = ?', [id]);
  persistDb();
}

// ── Disclosure Events CRUD ──────────────────────────────────────────────

export function getDisclosureEvents(disclosure_id: number): DisclosureEventRow[] {
  return execQuery(
    'SELECT * FROM disclosure_events WHERE disclosure_id = ? ORDER BY event_date DESC',
    [disclosure_id]
  ) as unknown as DisclosureEventRow[];
}

export function createDisclosureEvent(e: DisclosureEventRow): number {
  return execRun(
    `INSERT INTO disclosure_events (disclosure_id, event_type, actor, description)
     VALUES (?, ?, ?, ?)`,
    [e.disclosure_id, e.event_type, e.actor || null, e.description || null]
  );
}

// ── Audit Log CRUD ──────────────────────────────────────────────────────

export function getAuditLog(filters: { entity_type?: string; entity_id?: string; action?: string; limit?: number } = {}): AuditLogRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.entity_type) { conds.push('entity_type = ?'); params.push(filters.entity_type); }
  if (filters.entity_id) { conds.push('entity_id = ?'); params.push(filters.entity_id); }
  if (filters.action) { conds.push('action = ?'); params.push(filters.action); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const limit = filters.limit ? Number(filters.limit) : 200;
  return execQuery(
    `SELECT * FROM audit_log ${where} ORDER BY ts DESC LIMIT ${limit}`,
    params
  ) as unknown as AuditLogRow[];
}

// ── Sandbox Snapshots CRUD ───────────────────────────────────────────────

export function getSandboxSnapshots(jobId: string): any[] {
  return execQuery('SELECT * FROM sandbox_snapshots WHERE job_id = ? ORDER BY created_at DESC', [jobId]) as any[];
}

export function createSandboxSnapshot(row: { job_id: string; name: string; type: string; size_bytes?: number; description?: string }): number {
  return execRun(
    `INSERT INTO sandbox_snapshots (job_id, name, type, size_bytes, description) VALUES (?, ?, ?, ?, ?)`,
    [row.job_id, row.name, row.type, row.size_bytes ?? 0, row.description || null]
  );
}

export function deleteSandboxSnapshot(id: number): void {
  db.run('DELETE FROM sandbox_snapshots WHERE id = ?', [id]);
  persistDb();
}

export function logAudit(entry: AuditLogRow): void {
  execRun(
    `INSERT INTO audit_log (actor, action, entity_type, entity_id, details)
     VALUES (?, ?, ?, ?, ?)`,
    [
      entry.actor || 'system',
      entry.action,
      entry.entity_type || null,
      entry.entity_id || null,
      entry.details || null,
    ]
  );
}

// ── Users CRUD ──────────────────────────────────────────────────────────

export function getUsers(): UserRow[] {
  return execQuery('SELECT id, username, role, display_name, email, active, last_login, created_at FROM users ORDER BY created_at') as unknown as UserRow[];
}

export function getUserById(id: number): UserRow | null {
  const rows = execQuery('SELECT * FROM users WHERE id = ?', [id]);
  return rows[0] as UserRow || null;
}

export function getUserByUsername(username: string): UserRow | null {
  const rows = execQuery('SELECT * FROM users WHERE username = ?', [username]);
  return rows[0] as UserRow || null;
}

export function createUser(u: UserRow): number {
  return execRun(
    'INSERT INTO users (username, password_hash, role, display_name, email, active) VALUES (?, ?, ?, ?, ?, ?)',
    [u.username, u.password_hash, u.role || 'researcher', u.display_name || null, u.email || null, u.active ?? 1]
  );
}

export function updateUser(id: number, updates: Partial<UserRow>): void {
  const exclude = ['id', 'created_at', 'password_hash'];
  const fields = Object.keys(updates).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE users SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function updateUserPassword(id: number, hash: string): void {
  db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, id]);
  persistDb();
}

export function deleteUser(id: number): void {
  db.run('DELETE FROM api_tokens WHERE user_id = ?', [id]);
  db.run('DELETE FROM users WHERE id = ?', [id]);
  persistDb();
}

export function countUsers(): number {
  const rows = execQuery('SELECT COUNT(*) as c FROM users');
  return (rows[0]?.c as number) || 0;
}

// ── API Tokens ──────────────────────────────────────────────────────────

export function getApiTokensByUser(userId: number): ApiTokenRow[] {
  return execQuery(
    'SELECT id, user_id, token, name, expires_at, created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC',
    [userId]
  ) as unknown as ApiTokenRow[];
}

export function getApiTokenByValue(token: string): (ApiTokenRow & { username: string; role: string }) | null {
  const rows = execQuery(
    'SELECT t.*, u.username, u.role FROM api_tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ? AND u.active = 1',
    [token]
  );
  return rows[0] as any || null;
}

export function createApiToken(t: ApiTokenRow): number {
  return execRun(
    'INSERT INTO api_tokens (user_id, token, name, expires_at) VALUES (?, ?, ?, ?)',
    [t.user_id, t.token, t.name || null, t.expires_at || null]
  );
}

export function deleteApiToken(id: number): void {
  db.run('DELETE FROM api_tokens WHERE id = ?', [id]);
  persistDb();
}

// ── Teach Examples CRUD ─────────────────────────────────────────────────

export function getTeachExamples(filters: { finding_id?: number; action?: string; limit?: number } = {}): TeachExampleRow[] {
  const conds: string[] = [];
  const params: any[] = [];
  if (filters.finding_id !== undefined) { conds.push('finding_id = ?'); params.push(filters.finding_id); }
  if (filters.action) { conds.push('action = ?'); params.push(filters.action); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const limit = filters.limit || 200;
  return execQuery(`SELECT * FROM teach_examples ${where} ORDER BY created_at DESC LIMIT ${limit}`, params) as unknown as TeachExampleRow[];
}

export function createTeachExample(e: TeachExampleRow): number {
  return execRun(
    'INSERT INTO teach_examples (finding_id, action, reasoning, pattern_extracted, code_context, user_id) VALUES (?, ?, ?, ?, ?, ?)',
    [e.finding_id ?? null, e.action, e.reasoning || null, e.pattern_extracted || null, e.code_context || null, e.user_id ?? null]
  );
}

// ── Learned Patterns CRUD ───────────────────────────────────────────────

export function getLearnedPatterns(): LearnedPatternRow[] {
  return execQuery('SELECT * FROM learned_patterns ORDER BY confidence DESC, times_matched DESC') as unknown as LearnedPatternRow[];
}

export function createLearnedPattern(p: LearnedPatternRow): number {
  return execRun(
    'INSERT INTO learned_patterns (name, source_finding_id, pattern_type, grep_pattern, description, confidence) VALUES (?, ?, ?, ?, ?, ?)',
    [p.name, p.source_finding_id ?? null, p.pattern_type || null, p.grep_pattern || null, p.description || null, p.confidence ?? 0.5]
  );
}

export function updateLearnedPattern(id: number, updates: Partial<LearnedPatternRow>): void {
  const fields = Object.keys(updates).filter(k => k !== 'id' && k !== 'created_at');
  if (fields.length === 0) return;
  const setClause = safeSetClause(fields);
  const values = fields.map(f => (updates as any)[f]);
  db.run(`UPDATE learned_patterns SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

export function deleteSessionState(scope: string, scope_id: number | null, key?: string): void {
  if (key) {
    if (scope_id === null) {
      db.run('DELETE FROM session_state WHERE scope = ? AND scope_id IS NULL AND key = ?', [scope, key]);
    } else {
      db.run('DELETE FROM session_state WHERE scope = ? AND scope_id = ? AND key = ?', [scope, scope_id, key]);
    }
  } else {
    if (scope_id === null) {
      db.run('DELETE FROM session_state WHERE scope = ? AND scope_id IS NULL', [scope]);
    } else {
      db.run('DELETE FROM session_state WHERE scope = ? AND scope_id = ?', [scope, scope_id]);
    }
  }
  persistDb();
}

// ── Subsystem B - Refresh tokens CRUD ──────────────────────────────────────

export interface RefreshTokenRow {
  id?: number;
  user_id: number;
  token_hash: string;
  device_id: string;
  device_name: string;
  expires_at: number;
  revoked: number;
  created_at: number;
  last_used_at: number | null;
}

export function insertRefreshToken(row: Omit<RefreshTokenRow, 'id'>): number {
  return execRun(
    `INSERT INTO refresh_tokens
       (user_id, token_hash, device_id, device_name, expires_at, revoked, created_at, last_used_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [row.user_id, row.token_hash, row.device_id, row.device_name, row.expires_at,
     row.revoked, row.created_at, row.last_used_at],
  );
}

export function getRefreshTokensForDevice(device_id: string): RefreshTokenRow[] {
  return execQuery(
    `SELECT * FROM refresh_tokens WHERE device_id = ? AND revoked = 0
     ORDER BY created_at DESC`,
    [device_id],
  ) as unknown as RefreshTokenRow[];
}

export function getRefreshTokensForUser(user_id: number): RefreshTokenRow[] {
  return execQuery(
    `SELECT * FROM refresh_tokens WHERE user_id = ? ORDER BY created_at DESC`,
    [user_id],
  ) as unknown as RefreshTokenRow[];
}

export function markRefreshTokenUsed(id: number, ts: number): void {
  db.run(`UPDATE refresh_tokens SET last_used_at = ? WHERE id = ?`, [ts, id]);
  persistDb();
}

export function revokeRefreshToken(id: number): void {
  db.run(`UPDATE refresh_tokens SET revoked = 1 WHERE id = ?`, [id]);
  persistDb();
}

export function revokeAllRefreshTokensForDevice(device_id: string): void {
  db.run(`UPDATE refresh_tokens SET revoked = 1 WHERE device_id = ?`, [device_id]);
  persistDb();
}

export function deleteExpiredRefreshTokens(now: number = Date.now()): number {
  db.run(`DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = 1`, [now]);
  persistDb();
  return 0; // row count not reliable through sql.js
}

// ── Subsystem B - Permissions ──────────────────────────────────────────────

export interface PermissionRow {
  id?: number;
  role: string;
  resource: string;
  action: string;
}

export function listPermissions(): PermissionRow[] {
  return execQuery(`SELECT * FROM permissions ORDER BY role, resource, action`) as unknown as PermissionRow[];
}

export function hasPermissionInDb(role: string, resource: string, action: string): boolean {
  const rows = execQuery(
    `SELECT 1 FROM permissions WHERE role = ? AND
       (resource = ? OR resource = '*') AND
       (action = ? OR action = '*')
     LIMIT 1`,
    [role, resource, action],
  );
  return rows.length > 0;
}

export function grantPermission(role: string, resource: string, action: string): void {
  db.run(
    `INSERT OR IGNORE INTO permissions (role, resource, action) VALUES (?, ?, ?)`,
    [role, resource, action],
  );
  persistDb();
}

export function revokePermission(role: string, resource: string, action: string): void {
  db.run(
    `DELETE FROM permissions WHERE role = ? AND resource = ? AND action = ?`,
    [role, resource, action],
  );
  persistDb();
}

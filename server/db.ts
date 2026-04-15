import { createRequire } from 'module';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DB_PATH = 'X:/vulnforge/vulnforge.db';
const WASM_PATH = 'X:/vulnforge/node_modules/sql.js/dist/sql-wasm.wasm';

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
  if (!db) throw new Error('Database not initialized — call initDb() first');
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

  migrateSchema();
  persistDb();
}

/** Add columns to existing tables without breaking existing data. */
function migrateSchema(): void {
  const migrations = [
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
  ];
  for (const sql of migrations) {
    try { db.run(sql); } catch { /* column already exists — expected */ }
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
  const setClause = fields.map(f => `${f} = ?`).join(', ');
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
  const limitClause = filters.limit ? `LIMIT ${Number(filters.limit)}` : '';
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

export function updateVulnerability(id: number, v: Partial<Vulnerability>): void {
  const exclude = ['id', 'found_at'];
  const fields = Object.keys(v).filter(k => !exclude.includes(k));
  if (fields.length === 0) return;
  const setClause = fields.map(f => `${f} = ?`).join(', ');
  const values = fields.map(f => (v as any)[f]);
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
  const setClause = fields.map(f => `${f} = ?`).join(', ');
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
    const setClause = fields.map(f => `${f} = ?`).join(', ');
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
  const setClause = fields.map(f => `${f} = ?`).join(', ');
  const values = fields.map(f => (p as any)[f]);
  db.run(`UPDATE plugins SET ${setClause} WHERE id = ?`, [...values, id]);
  persistDb();
}

// ── AI Providers CRUD ──────────────────────────────────────────────────────

export function getAllAIProviders(): AIProvider[] {
  return execQuery('SELECT * FROM ai_providers ORDER BY name') as unknown as AIProvider[];
}

export function getAIProviderById(id: number): AIProvider | null {
  const rows = execQuery('SELECT * FROM ai_providers WHERE id = ?', [id]);
  return rows[0] as AIProvider || null;
}

export function getEnabledAIProvider(): AIProvider | null {
  const rows = execQuery('SELECT * FROM ai_providers WHERE enabled = 1 LIMIT 1');
  return rows[0] as AIProvider || null;
}

export function upsertAIProvider(p: AIProvider): number {
  const existing = execQuery('SELECT * FROM ai_providers WHERE name = ?', [p.name]);
  if (existing.length > 0) {
    db.run(
      `UPDATE ai_providers SET model = ?, api_key = ?, base_url = ?, enabled = ?, config = ? WHERE name = ?`,
      [p.model || null, p.api_key || null, p.base_url || null, p.enabled ?? 0, p.config || null, p.name]
    );
    persistDb();
    return existing[0].id as number;
  }
  return execRun(
    `INSERT INTO ai_providers (name, model, api_key, base_url, enabled, config) VALUES (?, ?, ?, ?, ?, ?)`,
    [p.name, p.model || null, p.api_key || null, p.base_url || null, p.enabled ?? 0, p.config || null]
  );
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
  const setClause = fields.map(f => `${f} = ?`).join(', ');
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
  const setClause = fields.map(f => `${f} = ?`).join(', ');
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

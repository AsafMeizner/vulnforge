#!/usr/bin/env node
/**
 * One-shot importer: pull the 18 curated findings from X:/security-solver
 * into VulnForge as Triaged vulnerabilities.
 *
 * Source of truth: ALL_FINDINGS.md
 *   - Master table at the top gives (F-NN, name, project, severity, status, type)
 *   - Detailed sections (## F-NN: or ### F-NN:) give File, Trigger, Impact, Code
 *
 * Writes to /api/vulnerabilities via the running VulnForge backend.
 * Idempotent: skips rows whose title already exists.
 *
 * Usage:
 *   node scripts/import-security-solver.mjs [--dry-run] [--api http://localhost:3001/api]
 *
 * Env:
 *   VULNFORGE_API      override api base
 *   VULNFORGE_SOURCE   path to ALL_FINDINGS.md (default: X:/security-solver/ALL_FINDINGS.md)
 */
import { readFileSync, existsSync } from 'fs';
import path from 'path';
import process from 'process';

const args = new Set(process.argv.slice(2));
const DRY_RUN = args.has('--dry-run');
const API_FLAG = process.argv.indexOf('--api');
const API = API_FLAG >= 0
  ? process.argv[API_FLAG + 1]
  : (process.env.VULNFORGE_API || 'http://localhost:3001/api');
const SOURCE = process.env.VULNFORGE_SOURCE
  || 'X:/security-solver/ALL_FINDINGS.md';

// Severity normalization. The master table uses qualifiers like
// "CRITICAL (32-bit)", "HIGH (32-bit)", "PROBABLE HIGH". Strip them.
function normSeverity(raw) {
  const s = (raw || '').toUpperCase();
  if (s.includes('CRITICAL')) return 'Critical';
  if (s.includes('HIGH')) return 'High';
  if (s.includes('MEDIUM')) return 'Medium';
  if (s.includes('LOW')) return 'Low';
  return 'Medium';
}

function normStatus(_raw) {
  // Mark everything Triaged - these are post-audit findings, not raw
  // scanner output. Using a single status keeps the Findings page
  // counts honest.
  return 'Triaged';
}

/**
 * Parse the master vulnerability table at the top of the source file.
 * Returns { 'F-01': {name, project, severity, status, type, notes}, ... }.
 */
function parseMasterTable(md) {
  const out = {};
  const tableStart = md.indexOf('| # | Name');
  if (tableStart < 0) return out;
  const lines = md.slice(tableStart).split('\n');
  for (const line of lines) {
    if (!line.startsWith('|')) break;
    if (/^\|\s*#/.test(line)) continue;
    if (/^\|\s*---/.test(line)) continue;
    const cells = line.split('|').slice(1, -1).map((c) => c.trim());
    if (cells.length < 6) continue;
    const [id, name, project, severity, status, type, notes] = cells;
    const idMatch = (id || '').match(/F-\d{2,}/);
    if (!idMatch) continue;
    out[idMatch[0]] = {
      name: name.replace(/\*\*/g, '').trim(),
      project: project.trim(),
      severity: normSeverity(severity),
      status: normStatus(status),
      type: (type || '').trim(),
      notes: (notes || '').trim(),
    };
  }
  return out;
}

/**
 * Parse per-finding sections. Each starts with `## F-NN:` or `### F-NN:`
 * and runs until the next such header or end of file.
 */
function parsePerFindingSections(md) {
  const out = {};
  const headerRe = /^#{2,3}\s+(F-\d{2,})[^\n]*$/gm;
  const matches = [];
  let m;
  while ((m = headerRe.exec(md)) !== null) {
    matches.push({ id: m[1], start: m.index, headerLine: m[0] });
  }
  for (let i = 0; i < matches.length; i++) {
    const { id, start, headerLine } = matches[i];
    const end = i + 1 < matches.length ? matches[i + 1].start : md.length;
    const body = md.slice(start, end);

    let file = null;
    let lineStart = null;
    let lineEnd = null;
    const fileMatch = body.match(/\*\*File:\*\*\s*`?([^`\n]+?)`?\s*(?:\n|$)/);
    if (fileMatch) {
      const raw = fileMatch[1].trim();
      const locMatch = raw.match(/^(.+?):(\d+)(?:-(\d+))?$/);
      if (locMatch) {
        file = locMatch[1].trim();
        lineStart = Number(locMatch[2]);
        lineEnd = locMatch[3] ? Number(locMatch[3]) : lineStart;
      } else {
        file = raw;
      }
    }

    const cweMatch = body.match(/\bCWE-\d{1,4}\b/);
    const cwe = cweMatch ? cweMatch[0] : null;

    const description = body.replace(headerLine, '').trim();

    out[id] = { file, lineStart, lineEnd, cwe, description, headerLine };
  }
  return out;
}

function toVulnerabilityRow(id, master, detail) {
  if (!master) return null;
  const detailFile = detail?.file || null;
  return {
    title: master.name,
    severity: master.severity,
    status: master.status,
    file: detailFile,
    line_number: detail?.lineStart ?? null,
    line_start: detail?.lineStart ?? null,
    line_end: detail?.lineEnd ?? null,
    cwe: detail?.cwe ?? null,
    description: (detail?.description || '').slice(0, 20_000),
    method: `Manual triage (RALPH Loop v3) - ${master.type || 'static analysis'}`,
    notes: [
      `Imported from ${path.basename(SOURCE)} (${id})`,
      master.project ? `Project: ${master.project}` : null,
      master.notes ? `Audit note: ${master.notes}` : null,
    ].filter(Boolean).join('\n'),
  };
}

async function apiGet(pathname) {
  const r = await fetch(API + pathname, { headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`GET ${pathname} -> HTTP ${r.status}`);
  return r.json();
}

async function apiPost(pathname, body) {
  const r = await fetch(API + pathname, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`POST ${pathname} -> HTTP ${r.status}: ${text.slice(0, 300)}`);
  }
  return r.json();
}

async function main() {
  if (!existsSync(SOURCE)) {
    console.error(`source file not found: ${SOURCE}`);
    process.exit(2);
  }
  console.log(`[import] API=${API}  source=${SOURCE}  ${DRY_RUN ? '(DRY RUN)' : ''}`);

  const md = readFileSync(SOURCE, 'utf-8');
  const master = parseMasterTable(md);
  const detail = parsePerFindingSections(md);
  const ids = Object.keys(master).sort();
  console.log(`[import] parsed ${ids.length} master rows, ${Object.keys(detail).length} detail sections`);

  let existingTitles = new Set();
  if (!DRY_RUN) {
    try {
      const resp = await apiGet('/vulnerabilities?limit=500');
      for (const v of resp.data || []) existingTitles.add(v.title);
      console.log(`[import] ${existingTitles.size} vulnerabilities already in DB`);
    } catch (err) {
      console.warn(`[import] could not pre-fetch existing vulns (${err.message}); skipping de-dup`);
    }
  }

  let created = 0;
  let skipped = 0;
  let errored = 0;

  for (const id of ids) {
    const row = toVulnerabilityRow(id, master[id], detail[id]);
    if (!row) { errored++; continue; }

    if (existingTitles.has(row.title)) {
      console.log(`  SKIP ${id}  "${row.title.slice(0, 60)}" (already exists)`);
      skipped++;
      continue;
    }

    if (DRY_RUN) {
      console.log(`  DRY  ${id}  [${row.severity}] ${row.title} @ ${row.file || '?'}:${row.line_number || '?'}`);
      continue;
    }

    try {
      const res = await apiPost('/vulnerabilities', row);
      const newId = res?.id ?? res?.vuln?.id ?? '?';
      console.log(`  NEW  ${id}  id=${newId}  [${row.severity}] ${row.title.slice(0, 60)}`);
      created++;
    } catch (err) {
      console.warn(`  ERR  ${id}  ${err.message}`);
      errored++;
    }
  }

  console.log(`\n[import] done. created=${created} skipped=${skipped} errored=${errored}`);
}

main().catch((err) => {
  console.error('[import] fatal:', err);
  process.exit(1);
});

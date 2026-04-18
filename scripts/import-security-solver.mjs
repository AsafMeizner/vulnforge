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
// --update: when a finding with the same title already exists, PUT
// the new field values onto it instead of skipping. Useful when the
// source doc is refined and we want to refresh CVSS / impact / fix
// etc. without duplicating rows.
const UPDATE = args.has('--update');
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
 * Extract a markdown subsection by heading name. The heading can be
 * at any depth (### or ####); matching is case-insensitive. Returns
 * the body text up to the next heading of equal or shallower depth,
 * or null if the section isn't present.
 */
function extractSection(block, heading) {
  const re = new RegExp(
    `^(#{3,4})\\s+${heading}\\s*$([\\s\\S]*?)(?=^#{1,4}\\s|$)`,
    'im',
  );
  const m = block.match(re);
  return m ? m[2].trim() : null;
}

/** First fenced code block inside some text. Language hint ignored. */
function extractFirstFence(text) {
  if (!text) return null;
  const m = text.match(/```[\w-]*\s*\n([\s\S]*?)```/);
  return m ? m[1].trim() : null;
}

/** `**Label:**` value on the same line. */
function extractBoldLabel(block, label) {
  const re = new RegExp(`\\*\\*${label}:\\*\\*\\s*(.+?)(?:\\n|$)`, 'i');
  const m = block.match(re);
  return m ? m[1].trim().replace(/^`|`$/g, '') : null;
}

/**
 * Parse per-finding sections. Each starts with `## F-NN:` or `### F-NN:`
 * and runs until the next such header or end of file.
 *
 * Pulls out as many fields as the source doc exposes so the resulting
 * vulnerability row carries the same context a human reviewer would
 * want: Summary, Vulnerable Code snippet, Proposed Fix, Impact, and
 * Reproduction / Attack Chain for repro_steps.
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

    // File + line number (first "**File:**" bold label)
    let file = null;
    let lineStart = null;
    let lineEnd = null;
    const fileRaw = extractBoldLabel(body, 'File');
    if (fileRaw) {
      const locMatch = fileRaw.match(/^(.+?):(\d+)(?:-(\d+))?/);
      if (locMatch) {
        file = locMatch[1].trim();
        lineStart = Number(locMatch[2]);
        lineEnd = locMatch[3] ? Number(locMatch[3]) : lineStart;
      } else {
        file = fileRaw;
      }
    }

    const cweMatch = body.match(/\bCWE-\d{1,4}\b/);
    const cwe = cweMatch ? cweMatch[0] : null;

    // Meaningful subsections
    const summary = extractSection(body, 'Summary');
    const vulnCode = extractSection(body, 'Vulnerable Code');
    const proposedFix = extractSection(body, 'Proposed Fix')
      || extractSection(body, 'Fix');
    const impactSection = extractSection(body, 'Impact');
    const attackChain = extractSection(body, 'Attack Chain');
    const reproduction = extractSection(body, 'Reproduction');
    const exploitation = extractSection(body, 'Exploitation');

    const codeSnippet = extractFirstFence(vulnCode || '') || extractFirstFence(body);
    const fixSnippet = extractFirstFence(proposedFix || '');
    const triggerText = extractBoldLabel(body, 'Trigger');

    // Reproduction steps: prefer explicit section, then Attack Chain,
    // then the Trigger bold label if that's all we have.
    const reproSteps = reproduction
      || attackChain
      || exploitation
      || (triggerText ? `Trigger: ${triggerText}` : null);

    // Description prefers the Summary section if present, otherwise
    // the whole block minus the header (old behaviour).
    const description = summary
      ? summary
      : body.replace(headerLine, '').trim();

    out[id] = {
      file, lineStart, lineEnd, cwe,
      description,
      codeSnippet,
      proposedFix: proposedFix || fixSnippet,
      impact: impactSection,
      reproductionSteps: reproSteps,
      headerLine,
    };
  }
  return out;
}

// Approximate CVSS scores per severity bucket. Source audit doesn't
// give proper CVSS strings, so we plant a representative base-score
// that lines up roughly with the severity label. Users can tune the
// exact numbers per finding later in the Finding Detail page; this
// is just a sensible starting point so the CVSS column isn't empty.
const CVSS_BY_SEVERITY = {
  Critical: 9.5,
  High:     8.1,
  Medium:   6.1,
  Low:      3.7,
};

function toVulnerabilityRow(id, master, detail) {
  if (!master) return null;
  const detailFile = detail?.file || null;
  return {
    title: master.name,
    severity: master.severity,
    status: master.status,
    // CVSS: placeholder derived from severity so the column isn't
    // blank. Reviewers refine per finding in the UI.
    cvss: CVSS_BY_SEVERITY[master.severity] ?? null,
    cvss_vector: null,
    file: detailFile,
    // DB schema uses line_start + line_end; `line_number` was a legacy
    // alias in the TS type that never existed as a column. Sending it
    // makes updateVulnerability throw "no such column: line_number".
    line_start: detail?.lineStart ?? null,
    line_end: detail?.lineEnd ?? null,
    cwe: detail?.cwe ?? null,
    description: (detail?.description || '').slice(0, 20_000),
    // Free-form markdown preserved for each enriched field so the
    // Finding Detail page renders headings / code blocks / bullets.
    impact: detail?.impact ?? null,
    code_snippet: detail?.codeSnippet ?? null,
    suggested_fix: detail?.proposedFix ?? null,
    reproduction_steps: detail?.reproductionSteps ?? null,
    method: `Manual triage (RALPH Loop v3) - ${master.type || 'static analysis'}`,
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

async function apiPut(pathname, body) {
  const r = await fetch(API + pathname, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`PUT ${pathname} -> HTTP ${r.status}: ${text.slice(0, 300)}`);
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

  // Pre-fetch existing titles → id so we can either skip or update.
  let existingByTitle = new Map();
  if (!DRY_RUN) {
    try {
      const resp = await apiGet('/vulnerabilities?limit=500');
      for (const v of resp.data || []) existingByTitle.set(v.title, v.id);
      console.log(`[import] ${existingByTitle.size} vulnerabilities already in DB`);
    } catch (err) {
      console.warn(`[import] could not pre-fetch existing vulns (${err.message}); skipping de-dup`);
    }
  }

  let created = 0;
  let updated = 0;
  let skipped = 0;
  let errored = 0;

  for (const id of ids) {
    const row = toVulnerabilityRow(id, master[id], detail[id]);
    if (!row) { errored++; continue; }

    const existingId = existingByTitle.get(row.title);

    if (DRY_RUN) {
      const tag = existingId ? (UPDATE ? 'UPD-DRY' : 'SKIP-DRY') : 'NEW-DRY';
      const extras = [
        row.cvss != null ? `cvss=${row.cvss}` : null,
        row.code_snippet ? 'code' : null,
        row.suggested_fix ? 'fix' : null,
        row.impact ? 'impact' : null,
        row.reproduction_steps ? 'repro' : null,
      ].filter(Boolean).join(',');
      console.log(`  ${tag} ${id}  [${row.severity}] ${row.title.slice(0, 55)}  (${extras || 'no extras'})`);
      continue;
    }

    if (existingId && !UPDATE) {
      console.log(`  SKIP ${id}  "${row.title.slice(0, 55)}" (exists, use --update to refresh)`);
      skipped++;
      continue;
    }

    try {
      if (existingId) {
        await apiPut(`/vulnerabilities/${existingId}`, row);
        console.log(`  UPD  ${id}  id=${existingId}  [${row.severity}] ${row.title.slice(0, 55)}`);
        updated++;
      } else {
        const res = await apiPost('/vulnerabilities', row);
        const newId = res?.id ?? res?.vuln?.id ?? '?';
        console.log(`  NEW  ${id}  id=${newId}  [${row.severity}] ${row.title.slice(0, 55)}`);
        created++;
      }
    } catch (err) {
      console.warn(`  ERR  ${id}  ${err.message}`);
      errored++;
    }
  }

  console.log(`\n[import] done. created=${created} updated=${updated} skipped=${skipped} errored=${errored}`);
}

main().catch((err) => {
  console.error('[import] fatal:', err);
  process.exit(1);
});

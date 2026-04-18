/**
 * VulnForge populate script
 * Reads disclosure files, parses structured fields, and fills empty DB columns.
 * Run with: npx tsx populate.ts
 */

import { createRequire } from 'module';
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'fs';
import path from 'path';

const require = createRequire(import.meta.url);

const DB_PATH = 'X:/vulnforge/vulnforge.db';
const WASM_PATH = 'X:/vulnforge/node_modules/sql.js/dist/sql-wasm.wasm';
const DISC_DIR = 'X:/security-solver/disclosures';

// ── Disclosure key mapping (vuln id -> disclosure path relative to DISC_DIR) ──
// Mirrors the OLD_VULNS array from seed.ts
const DISCLOSURE_KEYS: Record<number, string> = {
  1: 'libarchive/disclosure-1-submitted.md',
  2: 'jq/disclosure-1-submitted.md',
  3: 'jq/disclosure-2-submitted.md',
  4: 'jq/disclosure-3-submitted.md',
  5: 'mongoose/disclosure-1-submitted.md',
  6: 'civetweb/disclosure-1-submitted.md',
  7: 'civetweb/disclosure-1-submitted.md',
  8: 'civetweb/disclosure-2.md',
  9: 'libssh2/disclosure-1-submitted.md',
  10: 'wolfssl/disclosure-1-submitted.md',
  11: 'gravity/disclosure-1-submitted.md',
  12: 'contiki-ng/disclosure-1-submitted.md',
  13: 'libhv/disclosure-1-submitted.md',
  14: 'redis/disclosure-1-submitted.md',
  15: 'rt-thread/disclosure-1-submitted.md',
  16: 'stb/disclosure-1-submitted.md',
  17: 'pcre2/disclosure-1-submitted.md',
  18: 'c-ares/disclosure-1-closed.md',
  19: 'libevent/disclosure-1.md',
  20: 'libyaml/disclosure-1.md',
  21: 'libexpat/disclosure-1.md',
  22: 'jansson/disclosure-1.md',
  23: 'picotls/disclosure-1.md',
  24: 'cosmopolitan/disclosure-1.md',
  25: 'libwebsockets/disclosure-1.md',
  26: 'sqlite/disclosure-1.md',
  27: 'sqlite/disclosure-1.md',
  28: 'nodejs/disclosure-1-REJECTED.md',
  29: 'openssh/disclosure-1-REJECTED.md',
  30: 'openssh/disclosure-2-REJECTED.md',
  31: 'linux-kernel/disclosure-1-REJECTED.md',
  32: 'systemd/disclosure-1-submitted.md',
  33: 'mruby/disclosure-1-OUT-OF-SCOPE.md',
  34: 'v7/disclosure-1-DEPRICATED.md',
  35: 'nghttp2/disclosure-1-submitted.md',
  36: 'node/disclosure-1.md',
};

// ── CVSS mapping by vulnerability type keywords ───────────────────────────
interface CvssRule {
  keywords: RegExp;
  vector: string;
  score: number;
}

const CVSS_RULES: CvssRule[] = [
  { keywords: /CL\.TE|request smuggling/i, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N', score: 10.0 },
  { keywords: /NUL byte.*URI|URI truncation|%00/i, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', score: 9.8 },
  { keywords: /decompression bomb/i, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H', score: 9.1 },
  { keywords: /heap.*overflow|buffer overflow|heap.*over-read/i, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', score: 9.8 },
  { keywords: /integer overflow.*alloc|overflow.*malloc|truncation.*malloc/i, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 8.8 },
  { keywords: /bytecode.*validat|VM.*bytecode|deserialization bypass/i, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', score: 8.8 },
  { keywords: /DNS.*stack overflow|DNS.*decompression/i, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H', score: 8.6 },
  { keywords: /TLS.*certificate|cert.*bypass|pathLen/i, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', score: 7.4 },
  { keywords: /signal handler.*unsafe|async-signal/i, vector: 'CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H', score: 5.9 },
  { keywords: /unbounded recursion|recursion DoS/i, vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H', score: 5.5 },
  { keywords: /operator precedence/i, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N', score: 5.3 },
];

// ── Known maintainer responses ────────────────────────────────────────────
interface KnownResponse {
  match: (v: Record<string, any>) => boolean;
  response?: string;
  rejection_reason?: string;
  sub_findings?: string;
}

const KNOWN_RESPONSES: KnownResponse[] = [
  {
    match: (v) => {
      const pn = (v.project_name || '').toLowerCase();
      return pn === 'wolfssl';
    },
    response: 'Eric Blankenhorn responded same day with PR #10187 fixing all 3 issues with tests.',
  },
  {
    match: (v) => {
      const pn = (v.project_name || '').toLowerCase();
      return pn === 'systemd';
    },
    response: 'bluca: That is not a real world reproducer. Closing since with no reproducer there is no valid security issue.',
    rejection_reason: 'Maintainer considers this acceptable design trade-off.',
  },
  {
    match: (v) => (v.title || '').includes('DNS SOA'),
    response: 'mcollina: I tried your example and I could not reproduce.',
    rejection_reason: 'ares_expand_name() validates bounds.',
  },
  {
    match: (v) => (v.title || '').includes('Compat flag'),
    response: 'Damien Miller: MON_ONCE flag prevents re-setting.',
    rejection_reason: 'Intentional design.',
  },
  {
    match: (v) => {
      const pn = (v.project_name || '').toLowerCase();
      return pn === 'linux kernel' || pn === 'linux-kernel';
    },
    response: 'Jens Axboe: locks protect the access.',
    rejection_reason: 'uring_lock/completion_lock protect the access pattern.',
  },
  {
    match: (v) => {
      const pn = (v.project_name || '').toLowerCase();
      return pn === 'c-ares';
    },
    sub_findings: 'CNAME chain DoS: Rejected\nPointer hop limit: Working on fix\nDuplicate OPT: Filed as GitHub issue',
  },
];

// ── Markdown parsing helpers ──────────────────────────────────────────────

function extractSection(content: string, ...headings: string[]): string {
  for (const heading of headings) {
    // Match ## or ### headings, case insensitive
    const escapedHeading = heading.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(
      `(?:^|\\n)#{2,3}\\s*${escapedHeading}\\s*\\n([\\s\\S]*?)(?=\\n#{2,3}\\s|$)`,
      'i'
    );
    const match = content.match(regex);
    if (match) {
      return match[1].trim();
    }
  }
  return '';
}

function extractDescription(content: string): string {
  // Try Summary, Description sections first
  const section = extractSection(content, 'Summary', 'Description');
  if (section) return section;

  // Fallback: first paragraph after the title (first # line)
  const lines = content.split('\n');
  let pastTitle = false;
  const paragraphLines: string[] = [];

  for (const line of lines) {
    if (!pastTitle) {
      if (line.startsWith('#')) {
        pastTitle = true;
      }
      continue;
    }
    if (line.trim() === '') {
      if (paragraphLines.length > 0) break;
      continue;
    }
    if (line.startsWith('#') || line.startsWith('---')) {
      if (paragraphLines.length > 0) break;
      continue;
    }
    paragraphLines.push(line);
  }

  return paragraphLines.join('\n').trim();
}

function extractImpact(content: string): string {
  // Try markdown headings
  const section = extractSection(content, 'Impact');
  if (section) return section;

  // Try == Impact == style (email-format disclosures)
  const eqMatch = content.match(/==\s*Impact\s*==\s*\n([\s\S]*?)(?:\n==\s|\n---|\n```|$)/i);
  if (eqMatch) return eqMatch[1].trim();

  return '';
}

function extractSuggestedFix(content: string): string {
  const fix = extractSection(content, 'Suggested fix', 'Suggested Fix', 'Fix');
  if (fix) return fix;

  // Some disclosures embed fixes inline -- look for diff blocks
  const diffMatch = content.match(/```diff\n([\s\S]*?)```/);
  if (diffMatch) return diffMatch[1].trim();

  // Try == Fix == style
  const eqMatch = content.match(/==\s*(?:Suggested [Ff]ix|Fix)\s*==\s*\n([\s\S]*?)(?:\n==\s|\n---|\n\n\n|$)/i);
  if (eqMatch) return eqMatch[1].trim();

  return '';
}

function extractReproductionSteps(content: string): string {
  const section = extractSection(content, 'PoC', 'Reproduction', 'Trigger', 'Reproducer', 'How to Trigger');
  if (section) return section;

  // Some files embed PoC in email format with == Trigger == or == PoC ==
  const eqMatch = content.match(/==\s*(?:PoC|Trigger|Reproduction|Reproducer)\s*==\s*\n([\s\S]*?)(?:\n==\s|\n---|\n\n\n|$)/i);
  if (eqMatch) return eqMatch[1].trim();

  return '';
}

function extractFirstCodeBlock(content: string): string {
  // Find code blocks that show vulnerable code (skip bash/diff/email blocks)
  const codeBlocks = [...content.matchAll(/```(\w*)\n([\s\S]*?)```/g)];
  for (const block of codeBlocks) {
    const lang = block[1].toLowerCase();
    // Skip bash PoC blocks, diff blocks, email subjects
    if (lang === 'bash' || lang === 'diff' || lang === 'shell') continue;
    const blockContent = block[2].trim();
    // Skip single-line title blocks
    if (!blockContent.includes('\n') && blockContent.length < 100) continue;
    // Skip blocks that look like email content
    if (blockContent.startsWith('Hi,') || blockContent.startsWith('Hi ') || blockContent.startsWith('Security:')) continue;
    return blockContent;
  }

  // Fallback: any code block with C/C++ looking content
  for (const block of codeBlocks) {
    const blockContent = block[2].trim();
    if (blockContent.includes('(') && blockContent.includes(')') && blockContent.length > 50) {
      return blockContent;
    }
  }

  return '';
}

// ── CVSS helpers ──────────────────────────────────────────────────────────

function assignCvss(title: string): { vector: string; score: number } | null {
  for (const rule of CVSS_RULES) {
    if (rule.keywords.test(title)) {
      return { vector: rule.vector, score: rule.score };
    }
  }
  return null;
}

function severityFromScore(score: number): string {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  return 'Low';
}

// ── Main ──────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('=================================================');
  console.log('  VulnForge Populate Script');
  console.log('=================================================\n');

  // Initialize sql.js
  const initSqlJs = require('sql.js');
  const wasmBinary = readFileSync(WASM_PATH);
  const SQL = await initSqlJs({ wasmBinary });

  if (!existsSync(DB_PATH)) {
    console.error('ERROR: Database not found at', DB_PATH);
    process.exit(1);
  }

  const fileBuffer = readFileSync(DB_PATH);
  const db = new SQL.Database(fileBuffer);

  // Get all vulnerabilities with their project names
  const vulns = db.exec(`
    SELECT v.*, p.name as project_name
    FROM vulnerabilities v
    LEFT JOIN projects p ON v.project_id = p.id
    ORDER BY v.id
  `);

  if (!vulns.length || !vulns[0].values.length) {
    console.log('No vulnerabilities found in database.');
    db.close();
    return;
  }

  const columns: string[] = vulns[0].columns;
  const rows = vulns[0].values;

  console.log(`Found ${rows.length} vulnerabilities in database.\n`);

  // Stats tracking
  let vulnsUpdated = 0;
  const fieldCounts: Record<string, number> = {};

  for (const row of rows) {
    // Build a keyed object from row
    const v: Record<string, any> = {};
    columns.forEach((col: string, i: number) => {
      v[col] = row[i];
    });

    const vulnId = v.id;
    const updates: Record<string, any> = {};

    console.log(`[${vulnId}] ${v.title}`);

    // ── Step 1: Find and read disclosure file ─────────────────────────
    const disclosureKey = DISCLOSURE_KEYS[vulnId];
    let disclosureContent = '';
    let howToSubmitContent = '';

    if (disclosureKey) {
      const discPath = path.join(DISC_DIR, disclosureKey);
      const projectDir = disclosureKey.split('/')[0];
      const howToPath = path.join(DISC_DIR, projectDir, 'how_to_submit.md');

      try {
        if (existsSync(discPath)) {
          disclosureContent = readFileSync(discPath, 'utf8');
        }
      } catch { /* skip */ }

      try {
        if (existsSync(howToPath)) {
          howToSubmitContent = readFileSync(howToPath, 'utf8');
        }
      } catch { /* skip */ }
    } else if (v.project_name) {
      // Fallback: try to find by project name
      const projectLower = (v.project_name as string).toLowerCase().replace(/\s+/g, '-');
      const discDir = path.join(DISC_DIR, projectLower);
      if (existsSync(discDir)) {
        try {
          const files = readdirSync(discDir).filter((f: string) => f.startsWith('disclosure-'));
          if (files.length > 0) {
            disclosureContent = readFileSync(path.join(discDir, files[0]), 'utf8');
          }
          const howToPath = path.join(discDir, 'how_to_submit.md');
          if (existsSync(howToPath)) {
            howToSubmitContent = readFileSync(howToPath, 'utf8');
          }
        } catch { /* skip */ }
      }
    }

    // ── Step 2: Parse disclosure and fill empty fields ─────────────────

    if (disclosureContent) {
      // disclosure_content
      if (!v.disclosure_content) {
        updates.disclosure_content = disclosureContent;
      }

      // description
      if (!v.description || v.description === '') {
        const desc = extractDescription(disclosureContent);
        if (desc) updates.description = desc;
      }

      // impact
      if (!v.impact) {
        const impact = extractImpact(disclosureContent);
        if (impact) updates.impact = impact;
      }

      // suggested_fix
      if (!v.suggested_fix) {
        const fix = extractSuggestedFix(disclosureContent);
        if (fix) updates.suggested_fix = fix;
      }

      // reproduction_steps
      if (!v.reproduction_steps) {
        const repro = extractReproductionSteps(disclosureContent);
        if (repro) updates.reproduction_steps = repro;
      }

      // code_snippet
      if (!v.code_snippet) {
        const code = extractFirstCodeBlock(disclosureContent);
        if (code) updates.code_snippet = code;
      }
    }

    // how_to_submit_content
    if (!v.how_to_submit_content && howToSubmitContent) {
      updates.how_to_submit_content = howToSubmitContent;
    }

    // ── Step 3: Fill missing CVSS vectors ─────────────────────────────

    if (!v.cvss_vector || v.cvss_vector === '') {
      const title = v.title as string;
      const cvss = assignCvss(title);
      if (cvss) {
        updates.cvss_vector = cvss.vector;
        if (!v.cvss || v.cvss === '') {
          updates.cvss = cvss.score.toString();
        }
        // Only upgrade severity, do not override existing non-empty values
        if (!v.severity || v.severity === '') {
          updates.severity = severityFromScore(cvss.score);
        }
      }
    } else if (v.cvss_vector && (!v.severity || v.severity === '')) {
      // Has vector but no severity -- derive from existing CVSS score
      const score = parseFloat(v.cvss as string);
      if (!isNaN(score)) {
        updates.severity = severityFromScore(score);
      }
    }

    // ── Step 4: Fill timestamps ───────────────────────────────────────

    const status = (v.status as string) || '';
    const now = new Date().toISOString().replace('T', ' ').replace(/\.\d+Z$/, '');

    if (!v.submitted_at) {
      if (['Submitted', 'Fixed', 'Responded', 'Partial', 'Closed', 'Out of Scope'].includes(status)) {
        updates.submitted_at = v.found_at || now;
      }
    }

    if (!v.resolved_at) {
      if (['Fixed', 'Rejected', 'Closed', 'Out of Scope'].includes(status)) {
        updates.resolved_at = now;
      }
    }

    // ── Step 5: Fill known responses ──────────────────────────────────

    for (const known of KNOWN_RESPONSES) {
      if (known.match(v)) {
        if (known.response && !v.response) {
          updates.response = known.response;
        }
        if (known.rejection_reason && !v.rejection_reason) {
          updates.rejection_reason = known.rejection_reason;
        }
        if (known.sub_findings && !v.sub_findings) {
          updates.sub_findings = known.sub_findings;
        }
      }
    }

    // ── Apply updates ─────────────────────────────────────────────────

    const fieldNames = Object.keys(updates);
    if (fieldNames.length === 0) {
      console.log(`  -> No updates needed`);
      continue;
    }

    const setClause = fieldNames.map(f => `${f} = ?`).join(', ');
    const values = fieldNames.map(f => updates[f]);

    try {
      db.run(
        `UPDATE vulnerabilities SET ${setClause}, updated_at = datetime('now') WHERE id = ?`,
        [...values, vulnId]
      );
      vulnsUpdated++;
      for (const f of fieldNames) {
        fieldCounts[f] = (fieldCounts[f] || 0) + 1;
      }
      console.log(`  -> Updated ${fieldNames.length} fields: ${fieldNames.join(', ')}`);
    } catch (err: any) {
      console.error(`  -> ERROR: ${err.message || err}`);
    }
  }

  // ── Save database ───────────────────────────────────────────────────
  const data = db.export();
  writeFileSync(DB_PATH, Buffer.from(data));
  db.close();

  // ── Summary ─────────────────────────────────────────────────────────
  console.log('\n=================================================');
  console.log('  Populate Summary');
  console.log('=================================================');
  console.log(`  Vulnerabilities scanned:  ${rows.length}`);
  console.log(`  Vulnerabilities updated:  ${vulnsUpdated}`);
  console.log(`  Fields filled:`);
  const sortedFields = Object.entries(fieldCounts).sort(([, a], [, b]) => b - a);
  for (const [field, count] of sortedFields) {
    console.log(`    ${field.padEnd(28)} ${count}`);
  }
  console.log('=================================================\n');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});

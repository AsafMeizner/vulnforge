/**
 * Dockerfile misconfiguration detector.
 *
 * Detects:
 *   - USER root (explicit) or no USER directive at all
 *   - ADD with URL (should be COPY + curl; or verified-hash download)
 *   - Missing HEALTHCHECK
 *   - Hardcoded secrets in ENV
 *   - :latest (or untagged) FROM
 *
 * A Dockerfile may use multi-stage builds; we only require a non-root USER
 * directive in the final stage (last FROM onwards).
 */

import { walkFiles, readText, relPath, trimEvidence } from './helpers.js';
import type { WebFinding } from './types.js';

export function runDockerDetector(projectPath: string): WebFinding[] {
  const files = walkFiles(projectPath, /(^|\/)Dockerfile(\..+)?$/, { maxDepth: 10 });
  const findings: WebFinding[] = [];
  for (const f of files) {
    const body = readText(f);
    if (!body) continue;
    const rel = relPath(projectPath, f);
    findings.push(...scanDockerfile(rel, body));
  }
  return findings;
}

function scanDockerfile(rel: string, body: string): WebFinding[] {
  const out: WebFinding[] = [];
  const rawLines = body.split(/\r?\n/);
  // Glue continuation backslashes into single logical lines for classification.
  const logical: { startLine: number; text: string }[] = [];
  let buf = '';
  let start = 0;
  for (let i = 0; i < rawLines.length; i++) {
    const t = rawLines[i].replace(/\r$/, '');
    if (buf === '') start = i + 1;
    if (t.trimEnd().endsWith('\\')) {
      buf += t.replace(/\\\s*$/, ' ');
    } else {
      buf += t;
      logical.push({ startLine: start, text: buf });
      buf = '';
    }
  }
  if (buf) logical.push({ startLine: start, text: buf });

  // Track FROM stages to locate the "final stage".
  const fromIndexes: number[] = [];
  for (let i = 0; i < logical.length; i++) {
    if (/^\s*FROM\b/i.test(logical[i].text)) fromIndexes.push(i);
  }
  const finalStageStart = fromIndexes.length === 0 ? 0 : fromIndexes[fromIndexes.length - 1];

  let sawHealthcheck = false;
  let sawUserAfterFinalFrom = false;
  let userWasRoot = false;
  let userLine = 0;

  for (let i = 0; i < logical.length; i++) {
    const L = logical[i];
    const line = L.text;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // FROM with :latest or no tag
    const fromMatch = trimmed.match(/^FROM\s+(--\S+\s+)?(\S+)/i);
    if (fromMatch) {
      const image = fromMatch[2];
      if (!image.includes('@')) {
        if (image.endsWith(':latest')) {
          out.push({
            category: 'iac',
            subcategory: 'docker',
            title: 'Base image uses :latest tag',
            severity: 'Medium',
            confidence: 'High',
            file: rel,
            line_start: L.startLine,
            resource_type: 'Dockerfile',
            evidence: trimEvidence(trimmed),
            cwe: 'CWE-1104',
            rule_id: 'IAC-DOCKER-001',
          });
        } else if (!image.includes(':')) {
          // Untagged non-local image: still resolves to :latest at build time.
          if (image.includes('/') || image.includes('.')) {
            out.push({
              category: 'iac',
              subcategory: 'docker',
              title: 'Base image not pinned (no tag)',
              severity: 'Medium',
              confidence: 'Medium',
              file: rel,
              line_start: L.startLine,
              resource_type: 'Dockerfile',
              evidence: trimEvidence(trimmed),
              cwe: 'CWE-1104',
              rule_id: 'IAC-DOCKER-001b',
            });
          }
        }
      }
    }

    // ADD with URL
    if (/^ADD\s+/i.test(trimmed)) {
      if (/\bhttps?:\/\//i.test(trimmed)) {
        out.push({
          category: 'iac',
          subcategory: 'docker',
          title: 'ADD used with remote URL',
          severity: 'Medium',
          confidence: 'High',
          file: rel,
          line_start: L.startLine,
          resource_type: 'Dockerfile',
          evidence: trimEvidence(trimmed),
          cwe: 'CWE-494',
          rule_id: 'IAC-DOCKER-002',
        });
      }
    }

    if (/^HEALTHCHECK\b/i.test(trimmed)) sawHealthcheck = true;

    // ENV with secret-ish key
    const envMatch = trimmed.match(/^ENV\s+(.+)$/i);
    if (envMatch) {
      if (hasSecretAssignment(envMatch[1])) {
        out.push({
          category: 'iac',
          subcategory: 'docker',
          title: 'Hardcoded secret in ENV',
          severity: 'High',
          confidence: 'Medium',
          file: rel,
          line_start: L.startLine,
          resource_type: 'Dockerfile',
          evidence: trimEvidence(trimmed),
          cwe: 'CWE-798',
          rule_id: 'IAC-DOCKER-003',
        });
      }
    }

    // USER after final FROM
    if (i >= finalStageStart && /^USER\s+/i.test(trimmed)) {
      sawUserAfterFinalFrom = true;
      userLine = L.startLine;
      const who = trimmed.replace(/^USER\s+/i, '').trim().split(/\s+/)[0];
      userWasRoot = who === 'root' || who === '0' || who === '0:0' || /^root:/.test(who);
    }
  }

  if (!sawHealthcheck) {
    out.push({
      category: 'iac',
      subcategory: 'docker',
      title: 'Missing HEALTHCHECK directive',
      severity: 'Low',
      confidence: 'High',
      file: rel,
      line_start: 1,
      resource_type: 'Dockerfile',
      evidence: 'No HEALTHCHECK directive found',
      cwe: 'CWE-754',
      rule_id: 'IAC-DOCKER-004',
    });
  }

  if (!sawUserAfterFinalFrom) {
    out.push({
      category: 'iac',
      subcategory: 'docker',
      title: 'No USER directive — container runs as root',
      severity: 'High',
      confidence: 'High',
      file: rel,
      line_start: 1,
      resource_type: 'Dockerfile',
      evidence: 'No USER directive after final FROM',
      cwe: 'CWE-250',
      rule_id: 'IAC-DOCKER-005',
    });
  } else if (userWasRoot) {
    out.push({
      category: 'iac',
      subcategory: 'docker',
      title: 'USER set to root',
      severity: 'High',
      confidence: 'High',
      file: rel,
      line_start: userLine,
      resource_type: 'Dockerfile',
      evidence: 'USER root',
      cwe: 'CWE-250',
      rule_id: 'IAC-DOCKER-006',
    });
  }

  return out;
}

const SECRET_KEY_RE =
  /(PASSWORD|PASSWD|PASS|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|DB_PASS|AUTH_TOKEN)/i;

/**
 * ENV can be `ENV KEY=VALUE KEY2=VALUE2` or `ENV KEY VALUE`.
 * Raise on an assignment whose VALUE looks non-empty and key matches a
 * known secret name. ARG is not scanned (intended to be parameterised).
 */
function hasSecretAssignment(rest: string): boolean {
  const pairRe = /(^|\s)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("[^"]*"|'[^']*'|\S+)/g;
  const pairs = [...rest.matchAll(pairRe)];
  let sawPair = false;
  for (const m of pairs) {
    sawPair = true;
    const k = m[2];
    const v = m[3].replace(/^["']|["']$/g, '');
    if (!v) continue;
    if (/^\$\{?[A-Z0-9_]+\}?$/.test(v)) continue;
    if (SECRET_KEY_RE.test(k)) return true;
  }
  if (!sawPair) {
    // Legacy form: ENV KEY VALUE
    const m2 = rest.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$/);
    if (m2 && SECRET_KEY_RE.test(m2[1]) && m2[2].trim() && !/^\$\{?[A-Z0-9_]+\}?$/.test(m2[2].trim())) {
      return true;
    }
  }
  return false;
}

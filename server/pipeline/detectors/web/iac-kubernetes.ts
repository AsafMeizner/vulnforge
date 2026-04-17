/**
 * Kubernetes manifest misconfiguration detector.
 *
 * Scans YAML manifests for standard hardening issues:
 *   - privileged: true
 *   - allowPrivilegeEscalation: true
 *   - hostNetwork / hostPID / hostIPC = true
 *   - Missing securityContext on Pod/containers
 *   - runAsUser: 0
 *   - capabilities.add including dangerous caps (SYS_ADMIN, NET_ADMIN, …)
 *   - Missing resources.limits
 *
 * We operate on the raw YAML text (line-based) rather than a full YAML
 * parser — K8s multi-document YAML + anchor support is too heavy to parse
 * without a dependency, and line-based detection is high-signal for these
 * specific checks.
 */

import { walkFiles, readText, relPath, trimEvidence } from './helpers.js';
import type { WebFinding } from './types.js';

const DANGEROUS_CAPS = [
  'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE',
  'SYS_RAWIO', 'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'ALL',
];

export function runKubernetesDetector(projectPath: string): WebFinding[] {
  const files = walkFiles(projectPath, /\.(ya?ml)$/i, { maxDepth: 10 });
  const findings: WebFinding[] = [];
  for (const f of files) {
    const body = readText(f);
    if (!body) continue;
    if (!looksLikeK8s(body)) continue;
    const rel = relPath(projectPath, f);
    findings.push(...scanManifest(rel, body));
  }
  return findings;
}

function looksLikeK8s(body: string): boolean {
  // kind: Deployment / Pod / etc. is the canonical marker.
  if (!/^kind\s*:\s*(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|ReplicationController)\b/m.test(body)) {
    return false;
  }
  if (!/^apiVersion\s*:/m.test(body)) return false;
  return true;
}

function scanManifest(rel: string, body: string): WebFinding[] {
  const out: WebFinding[] = [];
  const lines = body.split(/\r?\n/);

  // Per-line toggles — K8s manifests put these as leaf lines like `privileged: true`.
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.replace(/#.*$/, '').trim();

    if (/^privileged\s*:\s*true\b/.test(line)) {
      out.push(makeFinding(rel, i + 1, {
        subcategory: 'kubernetes',
        title: 'Container running as privileged: true',
        severity: 'Critical',
        evidence: trimEvidence(raw),
        cwe: 'CWE-250',
        rule_id: 'IAC-K8S-001',
      }));
    }
    if (/^allowPrivilegeEscalation\s*:\s*true\b/.test(line)) {
      out.push(makeFinding(rel, i + 1, {
        subcategory: 'kubernetes',
        title: 'allowPrivilegeEscalation: true',
        severity: 'High',
        evidence: trimEvidence(raw),
        cwe: 'CWE-250',
        rule_id: 'IAC-K8S-002',
      }));
    }
    if (/^hostNetwork\s*:\s*true\b/.test(line)) {
      out.push(makeFinding(rel, i + 1, {
        subcategory: 'kubernetes',
        title: 'Pod uses hostNetwork: true',
        severity: 'High',
        evidence: trimEvidence(raw),
        cwe: 'CWE-250',
        rule_id: 'IAC-K8S-003',
      }));
    }
    if (/^hostPID\s*:\s*true\b/.test(line)) {
      out.push(makeFinding(rel, i + 1, {
        subcategory: 'kubernetes',
        title: 'Pod uses hostPID: true',
        severity: 'High',
        evidence: trimEvidence(raw),
        cwe: 'CWE-250',
        rule_id: 'IAC-K8S-004',
      }));
    }
    if (/^hostIPC\s*:\s*true\b/.test(line)) {
      out.push(makeFinding(rel, i + 1, {
        subcategory: 'kubernetes',
        title: 'Pod uses hostIPC: true',
        severity: 'High',
        evidence: trimEvidence(raw),
        cwe: 'CWE-250',
        rule_id: 'IAC-K8S-005',
      }));
    }
    if (/^runAsUser\s*:\s*0\b/.test(line)) {
      out.push(makeFinding(rel, i + 1, {
        subcategory: 'kubernetes',
        title: 'runAsUser: 0 (root)',
        severity: 'High',
        evidence: trimEvidence(raw),
        cwe: 'CWE-250',
        rule_id: 'IAC-K8S-006',
      }));
    }
    if (/^runAsNonRoot\s*:\s*false\b/.test(line)) {
      out.push(makeFinding(rel, i + 1, {
        subcategory: 'kubernetes',
        title: 'runAsNonRoot: false',
        severity: 'High',
        evidence: trimEvidence(raw),
        cwe: 'CWE-250',
        rule_id: 'IAC-K8S-007',
      }));
    }
    if (/^readOnlyRootFilesystem\s*:\s*false\b/.test(line)) {
      out.push(makeFinding(rel, i + 1, {
        subcategory: 'kubernetes',
        title: 'readOnlyRootFilesystem: false',
        severity: 'Medium',
        evidence: trimEvidence(raw),
        cwe: 'CWE-732',
        rule_id: 'IAC-K8S-008',
      }));
    }
  }

  // Block-level: capabilities.add, containers without securityContext,
  // containers without resources.limits.
  out.push(...scanDangerousCapabilities(rel, lines));
  out.push(...scanMissingSecurityContext(rel, lines));
  out.push(...scanMissingResourceLimits(rel, lines));

  return out;
}

function makeFinding(
  rel: string,
  line: number,
  p: {
    subcategory: string;
    title: string;
    severity: WebFinding['severity'];
    evidence: string;
    cwe: string;
    rule_id: string;
  },
): WebFinding {
  return {
    category: 'iac',
    subcategory: p.subcategory,
    title: p.title,
    severity: p.severity,
    confidence: 'High',
    file: rel,
    line_start: line,
    resource_type: 'Kubernetes',
    evidence: p.evidence,
    cwe: p.cwe,
    rule_id: p.rule_id,
  };
}

function scanDangerousCapabilities(rel: string, lines: string[]): WebFinding[] {
  const out: WebFinding[] = [];
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i].trim();
    if (!/^add\s*:\s*/.test(text)) continue;
    // Handle both inline list and following lines.
    const inline = text.match(/^add\s*:\s*\[(.*)\]/);
    if (inline) {
      const items = inline[1].split(',').map(s => s.trim().replace(/["']/g, ''));
      for (const c of items) {
        if (DANGEROUS_CAPS.includes(c.toUpperCase())) {
          out.push({
            category: 'iac',
            subcategory: 'kubernetes',
            title: `capabilities.add includes dangerous capability ${c}`,
            severity: c.toUpperCase() === 'SYS_ADMIN' || c.toUpperCase() === 'ALL' ? 'Critical' : 'High',
            confidence: 'High',
            file: rel,
            line_start: i + 1,
            resource_type: 'Kubernetes',
            evidence: trimEvidence(lines[i]),
            cwe: 'CWE-250',
            rule_id: 'IAC-K8S-009',
          });
        }
      }
    } else {
      const baseIndent = (lines[i].match(/^ */)?.[0].length) ?? 0;
      for (let j = i + 1; j < lines.length; j++) {
        const raw = lines[j];
        const curIndent = (raw.match(/^ */)?.[0].length) ?? 0;
        if (raw.trim() === '' || raw.trim().startsWith('#')) continue;
        if (curIndent <= baseIndent) break;
        const m = raw.trim().match(/^-\s*["']?([A-Z_]+)["']?$/);
        if (m) {
          const cap = m[1].toUpperCase();
          if (DANGEROUS_CAPS.includes(cap)) {
            out.push({
              category: 'iac',
              subcategory: 'kubernetes',
              title: `capabilities.add includes dangerous capability ${cap}`,
              severity: cap === 'SYS_ADMIN' || cap === 'ALL' ? 'Critical' : 'High',
              confidence: 'High',
              file: rel,
              line_start: j + 1,
              resource_type: 'Kubernetes',
              evidence: trimEvidence(raw),
              cwe: 'CWE-250',
              rule_id: 'IAC-K8S-009',
            });
          }
        }
      }
    }
  }
  return out;
}

function scanMissingSecurityContext(rel: string, lines: string[]): WebFinding[] {
  // A container block begins with `- name: something` at a consistent indent
  // under a `containers:` key. We find each container block and check whether
  // it contains a `securityContext:` key as a descendant.
  const out: WebFinding[] = [];
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i];
    if (!/^(\s*)containers\s*:/m.test(t)) continue;
    const containersIndent = (t.match(/^ */)?.[0].length) ?? 0;
    const itemIndent = containersIndent + 2;
    // Walk following lines to find each `- name:` item at >= itemIndent.
    for (let j = i + 1; j < lines.length; j++) {
      const row = lines[j];
      if (row.trim() === '') continue;
      const thisIndent = (row.match(/^ */)?.[0].length) ?? 0;
      if (thisIndent <= containersIndent) break;
      const m = row.match(/^(\s*)-\s+name\s*:\s*(\S+)/);
      if (!m) continue;
      const blockIndent = (m[1].length);
      // Scan forward for siblings at blockIndent + 2 until indent returns.
      let hasSecCtx = false;
      let endIdx = j;
      for (let k = j + 1; k < lines.length; k++) {
        const kr = lines[k];
        if (kr.trim() === '') continue;
        const ki = (kr.match(/^ */)?.[0].length) ?? 0;
        if (ki <= blockIndent) break;
        endIdx = k;
        if (/^securityContext\s*:/.test(kr.trim())) hasSecCtx = true;
      }
      if (!hasSecCtx) {
        out.push({
          category: 'iac',
          subcategory: 'kubernetes',
          title: `Container "${m[2]}" has no securityContext`,
          severity: 'Medium',
          confidence: 'Medium',
          file: rel,
          line_start: j + 1,
          resource_type: 'Kubernetes',
          evidence: trimEvidence(row),
          cwe: 'CWE-250',
          rule_id: 'IAC-K8S-010',
        });
      }
      j = endIdx;
      void itemIndent;
    }
  }
  return out;
}

function scanMissingResourceLimits(rel: string, lines: string[]): WebFinding[] {
  const out: WebFinding[] = [];
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i];
    if (!/^(\s*)containers\s*:/m.test(t)) continue;
    const containersIndent = (t.match(/^ */)?.[0].length) ?? 0;
    for (let j = i + 1; j < lines.length; j++) {
      const row = lines[j];
      if (row.trim() === '') continue;
      const thisIndent = (row.match(/^ */)?.[0].length) ?? 0;
      if (thisIndent <= containersIndent) break;
      const m = row.match(/^(\s*)-\s+name\s*:\s*(\S+)/);
      if (!m) continue;
      const blockIndent = m[1].length;
      let hasLimits = false;
      let endIdx = j;
      for (let k = j + 1; k < lines.length; k++) {
        const kr = lines[k];
        if (kr.trim() === '') continue;
        const ki = (kr.match(/^ */)?.[0].length) ?? 0;
        if (ki <= blockIndent) break;
        endIdx = k;
        if (/^limits\s*:/.test(kr.trim())) hasLimits = true;
      }
      if (!hasLimits) {
        out.push({
          category: 'iac',
          subcategory: 'kubernetes',
          title: `Container "${m[2]}" has no resource limits`,
          severity: 'Low',
          confidence: 'Medium',
          file: rel,
          line_start: j + 1,
          resource_type: 'Kubernetes',
          evidence: trimEvidence(row),
          cwe: 'CWE-770',
          rule_id: 'IAC-K8S-011',
        });
      }
      j = endIdx;
    }
  }
  return out;
}

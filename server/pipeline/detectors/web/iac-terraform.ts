/**
 * Terraform misconfiguration detector.
 *
 * Scans *.tf files for a focused set of high-signal issues:
 *   - S3 buckets with acl = "public-read" / "public-read-write"
 *   - S3 buckets without a matching aws_s3_bucket_public_access_block
 *   - Security groups with 0.0.0.0/0 ingress on any port
 *   - IAM policies with "Action": "*" and/or "Resource": "*"
 *   - RDS instances with storage_encrypted = false
 *   - EBS volumes with encrypted = false
 *
 * We parse HCL line-by-line using balanced-brace tracking. Full HCL parsing
 * is not required for these pattern-based checks and avoids a heavy parser
 * dependency.
 */

import { walkFiles, readText, relPath, trimEvidence } from './helpers.js';
import type { WebFinding } from './types.js';

// ── Public API ────────────────────────────────────────────────────────────

export function runTerraformDetector(projectPath: string): WebFinding[] {
  const files = walkFiles(projectPath, /\.tf$/, { maxDepth: 10 });
  if (files.length === 0) return [];

  // Aggregate across the whole Terraform project — some checks need
  // cross-file awareness (missing public_access_block, etc.).
  const docs = files
    .map(f => ({ file: f, rel: relPath(projectPath, f), body: readText(f) ?? '' }))
    .filter(d => d.body.length > 0);

  const findings: WebFinding[] = [];
  const publicAclBuckets = new Map<string, { file: string; rel: string; line: number }>();
  const publicAccessBlocks = new Set<string>();

  for (const doc of docs) {
    findings.push(...scanSecurityGroups(doc));
    findings.push(...scanIamPolicies(doc));
    findings.push(...scanRds(doc));
    findings.push(...scanEbs(doc));
    findings.push(...scanS3Acl(doc, publicAclBuckets));
    collectPublicAccessBlocks(doc, publicAccessBlocks);
  }

  // A bucket with public ACL and no corresponding access-block is Critical.
  for (const [name, info] of publicAclBuckets) {
    if (!publicAccessBlocks.has(name)) {
      findings.push({
        category: 'iac',
        subcategory: 'terraform',
        title: `S3 bucket "${name}" exposed publicly without public_access_block`,
        severity: 'Critical',
        confidence: 'High',
        file: info.rel,
        line_start: info.line,
        resource_type: 'aws_s3_bucket',
        evidence: `bucket "${name}" has public ACL and no aws_s3_bucket_public_access_block`,
        cwe: 'CWE-284',
        rule_id: 'IAC-TF-S3-002',
      });
    }
  }

  return findings;
}

// ── S3 ────────────────────────────────────────────────────────────────────

function scanS3Acl(
  doc: { file: string; rel: string; body: string },
  publicAclBuckets: Map<string, { file: string; rel: string; line: number }>,
): WebFinding[] {
  const out: WebFinding[] = [];
  const lines = doc.body.split(/\r?\n/);
  const blocks = findResourceBlocks(doc.body, /aws_s3_bucket\b/);
  for (const block of blocks) {
    const aclMatch = /acl\s*=\s*"(public-read|public-read-write|authenticated-read)"/.exec(block.body);
    if (!aclMatch) continue;
    const aclLine = block.startLine + lineOffset(block.body, aclMatch.index);
    publicAclBuckets.set(block.name, { file: doc.file, rel: doc.rel, line: aclLine });
    out.push({
      category: 'iac',
      subcategory: 'terraform',
      title: `S3 bucket ACL set to ${aclMatch[1]}`,
      severity: aclMatch[1] === 'public-read-write' ? 'Critical' : 'High',
      confidence: 'High',
      file: doc.rel,
      line_start: aclLine,
      resource_type: 'aws_s3_bucket',
      evidence: trimEvidence(lines[aclLine - 1] ?? aclMatch[0]),
      cwe: 'CWE-284',
      rule_id: 'IAC-TF-S3-001',
    });
  }
  return out;
}

function collectPublicAccessBlocks(
  doc: { body: string },
  set: Set<string>,
): void {
  const blocks = findResourceBlocks(doc.body, /aws_s3_bucket_public_access_block\b/);
  for (const b of blocks) {
    // bucket attribute may be aws_s3_bucket.<name>.id / .bucket, or a literal.
    const ref = /bucket\s*=\s*aws_s3_bucket\.([A-Za-z0-9_]+)/.exec(b.body);
    if (ref) set.add(ref[1]);
    const lit = /bucket\s*=\s*"([^"]+)"/.exec(b.body);
    if (lit) set.add(lit[1]);
  }
}

// ── Security groups ───────────────────────────────────────────────────────

function scanSecurityGroups(doc: { rel: string; body: string }): WebFinding[] {
  const out: WebFinding[] = [];
  const lines = doc.body.split(/\r?\n/);
  const blocks = findResourceBlocks(doc.body, /aws_security_group\b/);
  for (const block of blocks) {
    const ingressRe = /ingress\s*\{[\s\S]*?\}/g;
    let m: RegExpExecArray | null;
    while ((m = ingressRe.exec(block.body)) !== null) {
      const ing = m[0];
      if (!/0\.0\.0\.0\/0/.test(ing) && !/::\/0/.test(ing)) continue;
      const offset = block.startLine + lineOffset(block.body, m.index);
      out.push({
        category: 'iac',
        subcategory: 'terraform',
        title: `Security group "${block.name}" allows ingress from 0.0.0.0/0`,
        severity: 'Critical',
        confidence: 'High',
        file: doc.rel,
        line_start: offset,
        resource_type: 'aws_security_group',
        evidence: trimEvidence(lines[offset - 1] ?? ing),
        cwe: 'CWE-284',
        rule_id: 'IAC-TF-SG-001',
      });
    }
  }
  const ruleBlocks = findResourceBlocks(doc.body, /aws_security_group_rule\b/);
  for (const block of ruleBlocks) {
    if (!/type\s*=\s*"ingress"/.test(block.body)) continue;
    if (!/0\.0\.0\.0\/0/.test(block.body) && !/::\/0/.test(block.body)) continue;
    out.push({
      category: 'iac',
      subcategory: 'terraform',
      title: `Security group rule "${block.name}" allows ingress from 0.0.0.0/0`,
      severity: 'Critical',
      confidence: 'High',
      file: doc.rel,
      line_start: block.startLine,
      resource_type: 'aws_security_group_rule',
      evidence: trimEvidence(lines[block.startLine - 1] ?? ''),
      cwe: 'CWE-284',
      rule_id: 'IAC-TF-SG-002',
    });
  }
  return out;
}

// ── IAM ──────────────────────────────────────────────────────────────────

function scanIamPolicies(doc: { rel: string; body: string }): WebFinding[] {
  const out: WebFinding[] = [];
  const lines = doc.body.split(/\r?\n/);
  const blocks = findResourceBlocks(
    doc.body,
    /aws_iam_(policy|role_policy|user_policy|group_policy)|aws_iam_policy_document/,
  );
  for (const block of blocks) {
    const bodyText = block.body;
    const wildcardAction = /"Action"\s*:\s*"\*"|\baction\s*=\s*\["\*"\]|\baction\s*=\s*"\*"/.test(bodyText);
    const wildcardResource = /"Resource"\s*:\s*"\*"|\bresources\s*=\s*\["\*"\]|\bresource\s*=\s*"\*"/.test(bodyText);
    if (!wildcardAction && !wildcardResource) continue;
    const offset =
      block.startLine + lineOffset(bodyText, Math.max(0, bodyText.search(/"Action"|"Resource"|\baction\b|\bresource\b/)));
    const severity: WebFinding['severity'] =
      wildcardAction && wildcardResource ? 'Critical' : 'High';
    const tag = wildcardAction && wildcardResource
      ? 'wildcard Action and Resource'
      : wildcardAction
        ? 'wildcard Action'
        : 'wildcard Resource';
    out.push({
      category: 'iac',
      subcategory: 'terraform',
      title: `IAM policy "${block.name}" grants ${tag}`,
      severity,
      confidence: 'High',
      file: doc.rel,
      line_start: offset,
      resource_type: 'aws_iam_policy',
      evidence: trimEvidence(lines[offset - 1] ?? bodyText.slice(0, 120)),
      cwe: 'CWE-732',
      rule_id: 'IAC-TF-IAM-001',
    });
  }
  return out;
}

// ── RDS ──────────────────────────────────────────────────────────────────

function scanRds(doc: { rel: string; body: string }): WebFinding[] {
  const out: WebFinding[] = [];
  const lines = doc.body.split(/\r?\n/);
  const blocks = findResourceBlocks(doc.body, /aws_db_instance\b/);
  for (const block of blocks) {
    const m = /storage_encrypted\s*=\s*false/.exec(block.body);
    if (!m) continue;
    const offset = block.startLine + lineOffset(block.body, m.index);
    out.push({
      category: 'iac',
      subcategory: 'terraform',
      title: `RDS instance "${block.name}" has storage_encrypted = false`,
      severity: 'High',
      confidence: 'High',
      file: doc.rel,
      line_start: offset,
      resource_type: 'aws_db_instance',
      evidence: trimEvidence(lines[offset - 1] ?? m[0]),
      cwe: 'CWE-311',
      rule_id: 'IAC-TF-RDS-001',
    });
  }
  return out;
}

// ── EBS ──────────────────────────────────────────────────────────────────

function scanEbs(doc: { rel: string; body: string }): WebFinding[] {
  const out: WebFinding[] = [];
  const lines = doc.body.split(/\r?\n/);
  const blocks = findResourceBlocks(doc.body, /aws_ebs_volume\b/);
  for (const block of blocks) {
    const m = /\bencrypted\s*=\s*false/.exec(block.body);
    if (!m) continue;
    const offset = block.startLine + lineOffset(block.body, m.index);
    out.push({
      category: 'iac',
      subcategory: 'terraform',
      title: `EBS volume "${block.name}" has encrypted = false`,
      severity: 'High',
      confidence: 'High',
      file: doc.rel,
      line_start: offset,
      resource_type: 'aws_ebs_volume',
      evidence: trimEvidence(lines[offset - 1] ?? m[0]),
      cwe: 'CWE-311',
      rule_id: 'IAC-TF-EBS-001',
    });
  }
  return out;
}

// ── HCL block walker (pattern-based) ──────────────────────────────────────

interface HclBlock {
  kind: string;   // 'resource' | 'data' | 'module' | …
  type: string;   // e.g. 'aws_s3_bucket'
  name: string;   // second label (resource name)
  body: string;   // text between { and matching }
  startLine: number; // 1-based line of the opening header
}

/**
 * Find resource / data / module blocks whose header line matches typeRe.
 * Braces are balanced naïvely ({ / } counting).
 */
function findResourceBlocks(body: string, typeRe: RegExp): HclBlock[] {
  const blocks: HclBlock[] = [];
  const lines = body.split(/\r?\n/);
  const headerRe = /^\s*(resource|data|module)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{/;
  for (let i = 0; i < lines.length; i++) {
    const h = headerRe.exec(lines[i]);
    if (!h) continue;
    if (!typeRe.test(lines[i])) continue;
    const startIdx = body.indexOf('{', sumLengths(lines, i));
    if (startIdx < 0) continue;
    let depth = 0;
    let j = startIdx;
    let ended = j;
    for (; j < body.length; j++) {
      const ch = body[j];
      if (ch === '{') depth++;
      else if (ch === '}') {
        depth--;
        if (depth === 0) {
          ended = j;
          break;
        }
      }
    }
    blocks.push({
      kind: h[1],
      type: h[2],
      name: h[3] ?? '',
      body: body.slice(startIdx + 1, ended),
      startLine: i + 1,
    });
  }
  return blocks;
}

function sumLengths(lines: string[], stopIdx: number): number {
  let n = 0;
  for (let i = 0; i < stopIdx; i++) n += lines[i].length + 1;
  return n;
}

function lineOffset(text: string, idx: number): number {
  let n = 0;
  for (let i = 0; i < idx && i < text.length; i++) {
    if (text[i] === '\n') n++;
  }
  return n;
}

/**
 * CloudFormation misconfiguration detector.
 *
 * Detects the same class of issues as the Terraform detector but in
 * CloudFormation JSON/YAML templates:
 *   - S3 buckets with AccessControl: PublicRead / PublicReadWrite
 *   - S3 buckets missing PublicAccessBlockConfiguration
 *   - SecurityGroups with CidrIp 0.0.0.0/0
 *   - IAM PolicyDocuments with Action/Resource '*'
 *   - RDS DBInstance with StorageEncrypted: false
 *   - Volume with Encrypted: false
 *
 * We use a light-touch parser: JSON via JSON.parse, YAML via a small
 * indent-based walker that covers the block-mapping subset CloudFormation
 * templates use in practice. We intentionally skip flow-style YAML because
 * real-world CFN rarely uses it, and a full YAML parser would add a runtime
 * dependency we cannot install.
 */

import { walkFiles, readText, relPath, trimEvidence } from './helpers.js';
import type { WebFinding } from './types.js';

// ── Public API ────────────────────────────────────────────────────────────

export function runCloudFormationDetector(projectPath: string): WebFinding[] {
  const files = walkFiles(projectPath, /\.(ya?ml|json|template)$/i, { maxDepth: 10 });
  const findings: WebFinding[] = [];

  for (const f of files) {
    const body = readText(f);
    if (!body) continue;
    if (!looksLikeCfn(body)) continue;

    const parsed = parseCfn(body);
    if (!parsed) continue;
    const rel = relPath(projectPath, f);
    findings.push(...scanResources(rel, body, parsed));
  }

  return findings;
}

// ── Detection heuristic ───────────────────────────────────────────────────

/**
 * Fast filter to avoid parsing every YAML/JSON file in a repo. A CloudFormation
 * template has either `AWSTemplateFormatVersion` at the top level or a
 * `Resources:` block whose children use `Type: AWS::*`.
 */
function looksLikeCfn(body: string): boolean {
  if (/AWSTemplateFormatVersion/.test(body)) return true;
  if (/^\s*"Resources"\s*:/m.test(body) && /"Type"\s*:\s*"AWS::/.test(body)) return true;
  if (/^Resources\s*:/m.test(body) && /Type\s*:\s*AWS::/m.test(body)) return true;
  return false;
}

// ── Scanning ──────────────────────────────────────────────────────────────

interface CfnResource {
  logicalId: string;
  type: string;
  line: number;
  properties: Record<string, any>;
  raw: string;
}

function scanResources(rel: string, body: string, resources: CfnResource[]): WebFinding[] {
  const out: WebFinding[] = [];
  const bucketsWithPublicAcl = new Set<string>();
  const bucketsWithBlock = new Set<string>();

  for (const r of resources) {
    switch (r.type) {
      case 'AWS::S3::Bucket': {
        const acl = String(r.properties.AccessControl ?? '');
        if (/^PublicRead(Write)?$/.test(acl)) {
          bucketsWithPublicAcl.add(r.logicalId);
          out.push({
            category: 'iac',
            subcategory: 'cloudformation',
            title: `S3 bucket "${r.logicalId}" uses AccessControl: ${acl}`,
            severity: acl === 'PublicReadWrite' ? 'Critical' : 'High',
            confidence: 'High',
            file: rel,
            line_start: r.line,
            resource_type: r.type,
            evidence: trimEvidence(`AccessControl: ${acl}`),
            cwe: 'CWE-284',
            rule_id: 'IAC-CFN-S3-001',
          });
        }
        if (r.properties.PublicAccessBlockConfiguration) {
          bucketsWithBlock.add(r.logicalId);
        }
        break;
      }
      case 'AWS::EC2::SecurityGroup': {
        const ingress = toArray(r.properties.SecurityGroupIngress);
        for (const rule of ingress) {
          if (!isOpenCidr(rule)) continue;
          out.push({
            category: 'iac',
            subcategory: 'cloudformation',
            title: `SecurityGroup "${r.logicalId}" ingress allows 0.0.0.0/0`,
            severity: 'Critical',
            confidence: 'High',
            file: rel,
            line_start: r.line,
            resource_type: r.type,
            evidence: trimEvidence(JSON.stringify(rule)),
            cwe: 'CWE-284',
            rule_id: 'IAC-CFN-SG-001',
          });
        }
        break;
      }
      case 'AWS::EC2::SecurityGroupIngress': {
        if (isOpenCidr(r.properties)) {
          out.push({
            category: 'iac',
            subcategory: 'cloudformation',
            title: `SecurityGroupIngress "${r.logicalId}" allows 0.0.0.0/0`,
            severity: 'Critical',
            confidence: 'High',
            file: rel,
            line_start: r.line,
            resource_type: r.type,
            evidence: trimEvidence(JSON.stringify(r.properties)),
            cwe: 'CWE-284',
            rule_id: 'IAC-CFN-SG-002',
          });
        }
        break;
      }
      case 'AWS::IAM::Policy':
      case 'AWS::IAM::ManagedPolicy':
      case 'AWS::IAM::Role': {
        const doc = r.properties.PolicyDocument
          ?? r.properties.Policies
          ?? r.properties.AssumeRolePolicyDocument;
        const statements = collectStatements(doc);
        for (const stmt of statements) {
          const wildcardAction = hasWildcard(stmt.Action);
          const wildcardResource = hasWildcard(stmt.Resource);
          if (!wildcardAction && !wildcardResource) continue;
          const severity: WebFinding['severity'] =
            wildcardAction && wildcardResource ? 'Critical' : 'High';
          const tag = wildcardAction && wildcardResource
            ? 'wildcard Action and Resource'
            : wildcardAction ? 'wildcard Action' : 'wildcard Resource';
          out.push({
            category: 'iac',
            subcategory: 'cloudformation',
            title: `IAM policy on "${r.logicalId}" grants ${tag}`,
            severity,
            confidence: 'High',
            file: rel,
            line_start: r.line,
            resource_type: r.type,
            evidence: trimEvidence(JSON.stringify(stmt).slice(0, 140)),
            cwe: 'CWE-732',
            rule_id: 'IAC-CFN-IAM-001',
          });
        }
        break;
      }
      case 'AWS::RDS::DBInstance': {
        const enc = r.properties.StorageEncrypted;
        if (enc === false || String(enc).toLowerCase() === 'false') {
          out.push({
            category: 'iac',
            subcategory: 'cloudformation',
            title: `RDS DBInstance "${r.logicalId}" has StorageEncrypted: false`,
            severity: 'High',
            confidence: 'High',
            file: rel,
            line_start: r.line,
            resource_type: r.type,
            evidence: 'StorageEncrypted: false',
            cwe: 'CWE-311',
            rule_id: 'IAC-CFN-RDS-001',
          });
        }
        break;
      }
      case 'AWS::EC2::Volume': {
        const enc = r.properties.Encrypted;
        if (enc === false || String(enc).toLowerCase() === 'false') {
          out.push({
            category: 'iac',
            subcategory: 'cloudformation',
            title: `EC2 Volume "${r.logicalId}" has Encrypted: false`,
            severity: 'High',
            confidence: 'High',
            file: rel,
            line_start: r.line,
            resource_type: r.type,
            evidence: 'Encrypted: false',
            cwe: 'CWE-311',
            rule_id: 'IAC-CFN-EBS-001',
          });
        }
        break;
      }
      default:
        // swallow — we don't scan other resource types
        break;
    }
  }

  // Emit the combined "public bucket, no access block" finding once per bucket.
  for (const id of bucketsWithPublicAcl) {
    if (!bucketsWithBlock.has(id)) {
      const r = resources.find(x => x.logicalId === id);
      out.push({
        category: 'iac',
        subcategory: 'cloudformation',
        title: `S3 bucket "${id}" public and missing PublicAccessBlockConfiguration`,
        severity: 'Critical',
        confidence: 'High',
        file: rel,
        line_start: r?.line ?? 1,
        resource_type: 'AWS::S3::Bucket',
        evidence: `bucket "${id}" public ACL without PublicAccessBlockConfiguration`,
        cwe: 'CWE-284',
        rule_id: 'IAC-CFN-S3-002',
      });
    }
  }

  return out;
}

function isOpenCidr(rule: any): boolean {
  if (!rule || typeof rule !== 'object') return false;
  const c4 = rule.CidrIp ?? rule.cidrIp ?? rule.cidr_ip;
  const c6 = rule.CidrIpv6 ?? rule.cidrIpv6 ?? rule.cidr_ipv6;
  return c4 === '0.0.0.0/0' || c6 === '::/0';
}

function toArray<T>(x: T | T[] | undefined): T[] {
  if (x === undefined || x === null) return [];
  return Array.isArray(x) ? x : [x];
}

function collectStatements(doc: any): any[] {
  if (!doc) return [];
  // Role: Policies: [ { PolicyDocument: {...} }, … ]
  if (Array.isArray(doc)) {
    return doc.flatMap(d => collectStatements(d?.PolicyDocument ?? d));
  }
  if (typeof doc !== 'object') return [];
  if (Array.isArray(doc.Statement)) return doc.Statement;
  if (doc.Statement && typeof doc.Statement === 'object') return [doc.Statement];
  return [];
}

function hasWildcard(v: any): boolean {
  if (v === '*') return true;
  if (Array.isArray(v)) return v.some(hasWildcard);
  return false;
}

// ── Parsers ──────────────────────────────────────────────────────────────

function parseCfn(body: string): CfnResource[] | null {
  const trimmed = body.trim();
  if (trimmed.startsWith('{')) {
    try {
      const obj = JSON.parse(body);
      return extractResources(obj, body, /* isJson */ true);
    } catch {
      return null;
    }
  }
  // YAML path: small indent-based parser, good enough for CFN idioms.
  const obj = parseBlockYaml(body);
  if (!obj) return null;
  return extractResources(obj, body, /* isJson */ false);
}

function extractResources(
  obj: any,
  body: string,
  isJson: boolean,
): CfnResource[] | null {
  if (!obj || typeof obj !== 'object' || !obj.Resources) return null;
  const lines = body.split(/\r?\n/);
  const resources = obj.Resources;
  const out: CfnResource[] = [];
  for (const logicalId of Object.keys(resources)) {
    const r = resources[logicalId];
    if (!r || typeof r !== 'object') continue;
    const line = findResourceLine(lines, logicalId, isJson);
    out.push({
      logicalId,
      type: String(r.Type ?? ''),
      line,
      properties: r.Properties ?? {},
      raw: '',
    });
  }
  return out;
}

function findResourceLine(lines: string[], id: string, isJson: boolean): number {
  const yamlPat = new RegExp('^\\s{0,4}' + escapeRe(id) + '\\s*:');
  const jsonPat = new RegExp('^\\s*"' + escapeRe(id) + '"\\s*:');
  for (let i = 0; i < lines.length; i++) {
    if ((isJson ? jsonPat : yamlPat).test(lines[i])) return i + 1;
  }
  return 1;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ── Tiny YAML block-mapping parser ────────────────────────────────────────

/**
 * Parses a narrow subset of YAML: block mappings/sequences, strings, numbers,
 * booleans, comments, null (`~` / `null`). Enough for CloudFormation
 * templates authored by hand. Unsupported: anchors, aliases, multi-line
 * strings (|, >), flow style ({}, []). Returns null on error.
 */
export function parseBlockYaml(text: string): any | null {
  const rawLines = text.split(/\r?\n/);
  // Strip comments + trailing whitespace, skip blank/empty.
  interface Line { indent: number; text: string; raw: string }
  const lines: Line[] = [];
  for (const raw of rawLines) {
    const noComment = stripComment(raw);
    if (!noComment.trim()) continue;
    const indent = noComment.match(/^ */)?.[0].length ?? 0;
    lines.push({ indent, text: noComment.trim(), raw });
  }
  if (lines.length === 0) return null;

  let i = 0;
  function parseNode(baseIndent: number): any {
    if (i >= lines.length) return null;
    const cur = lines[i];
    if (cur.indent < baseIndent) return null;
    // Sequence?
    if (cur.text.startsWith('- ') || cur.text === '-') {
      const arr: any[] = [];
      while (i < lines.length && lines[i].indent === cur.indent && (lines[i].text.startsWith('- ') || lines[i].text === '-')) {
        const item = lines[i].text === '-' ? '' : lines[i].text.slice(2);
        i++;
        if (!item) {
          // Parse nested mapping/sequence on following more-indented lines.
          const deeper = i < lines.length ? lines[i].indent : cur.indent;
          arr.push(parseNode(deeper));
        } else if (item.includes(':') && !item.startsWith('{') && !item.startsWith('[')) {
          // inline k: v starting a mapping item
          const mapBaseIndent = cur.indent + 2;
          // put the item back as a pseudo-line to re-parse as part of the map
          lines.splice(i, 0, { indent: mapBaseIndent, text: item, raw: item });
          arr.push(parseNode(mapBaseIndent));
        } else {
          arr.push(coerceScalar(item));
        }
      }
      return arr;
    }
    // Mapping
    const obj: Record<string, any> = {};
    while (i < lines.length && lines[i].indent === cur.indent) {
      const line = lines[i];
      const colon = indexOfUnquoted(line.text, ':');
      if (colon < 0) return null;
      const key = unquote(line.text.slice(0, colon).trim());
      const rest = line.text.slice(colon + 1).trim();
      i++;
      if (rest === '' || rest === '|' || rest === '>') {
        const deeper = i < lines.length ? lines[i].indent : line.indent;
        obj[key] = parseNode(deeper);
      } else {
        obj[key] = coerceScalar(rest);
      }
    }
    return obj;
  }

  try {
    return parseNode(lines[0].indent);
  } catch {
    return null;
  }
}

function stripComment(line: string): string {
  // Naïve: strip everything after ' #' outside quotes.
  let inSingle = false;
  let inDouble = false;
  for (let k = 0; k < line.length; k++) {
    const c = line[k];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === '#' && !inSingle && !inDouble && (k === 0 || /\s/.test(line[k - 1]))) {
      return line.slice(0, k);
    }
  }
  return line;
}

function indexOfUnquoted(s: string, ch: string): number {
  let inSingle = false;
  let inDouble = false;
  for (let k = 0; k < s.length; k++) {
    const c = s[k];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === ch && !inSingle && !inDouble) return k;
  }
  return -1;
}

function unquote(s: string): string {
  if (s.length >= 2) {
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
      return s.slice(1, -1);
    }
  }
  return s;
}

function coerceScalar(s: string): any {
  const t = s.trim();
  if (t === '' || t === '~' || t === 'null' || t === 'Null' || t === 'NULL') return null;
  if (t === 'true' || t === 'True' || t === 'TRUE') return true;
  if (t === 'false' || t === 'False' || t === 'FALSE') return false;
  if (/^-?\d+$/.test(t)) return Number(t);
  if (/^-?\d+\.\d+$/.test(t)) return Number(t);
  return unquote(t);
}

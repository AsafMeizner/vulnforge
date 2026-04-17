import path from 'path';
import { walkFiles, readText, relPath, trimEvidence } from './helpers.js';
import type { WebFinding } from './types.js';

/**
 * BOLA / BFLA detector.
 *
 * Heuristic: find route handlers that read `req.params.id` / `:id` and
 * persist/return the record without mentioning `req.user.id` (or equivalent)
 * anywhere in the same handler body. Also flags handlers under /admin/* or
 * /internal/* without an explicit role/permission check.
 */

const FILE_MATCH = /\.(?:js|mjs|cjs|ts|tsx|jsx|py)$/i;

const ROUTE_DEF = /(?:app|router|api)\.(?:get|post|put|patch|delete|all)\s*\(\s*["'`]([^"'`]+)["'`]/;
const PARAM_READ = /\breq\.params\.[a-z_][a-z0-9_]*\b|\breq\.params\[["'`][^"'`]+["'`]\]/i;
const OWNERSHIP_CHECK = /\breq\.user(?:\.[a-z_][a-z0-9_]*)?\b|\bctx\.user\b|\bsession\.user\b/i;
const ROLE_CHECK = /\b(?:isAdmin|hasRole|checkPermission|requireRole|authorize|permit|ability\.can)\b/i;

export function runBolaDetector(projectPath: string): WebFinding[] {
  const files = walkFiles(projectPath, FILE_MATCH);
  const findings: WebFinding[] = [];

  for (const file of files) {
    const src = readText(file);
    if (!src) continue;
    const lines = src.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const routeMatch = lines[i].match(ROUTE_DEF);
      if (!routeMatch) continue;
      const routePath = routeMatch[1];
      // Peek ahead for the handler body - 30 lines forward or until next route def
      let handlerEnd = Math.min(i + 30, lines.length);
      for (let j = i + 1; j < handlerEnd; j++) {
        if (ROUTE_DEF.test(lines[j])) { handlerEnd = j; break; }
      }
      const handlerText = lines.slice(i, handlerEnd).join('\n');
      const hasParam = PARAM_READ.test(handlerText);
      const hasOwner = OWNERSHIP_CHECK.test(handlerText);
      const hasRole = ROLE_CHECK.test(handlerText);

      if (hasParam && !hasOwner && !hasRole) {
        findings.push({
          category: 'authz',
          subcategory: 'bola',
          title: `Route reads user-supplied id "${routePath}" with no ownership check`,
          severity: 'High',
          confidence: 'Medium',
          file: relPath(projectPath, file),
          line_start: i + 1,
          evidence: trimEvidence(lines[i]),
          cwe: 'CWE-639',
          rule_id: 'AUTHZ-BOLA-001',
        });
      }
      if (/^\/(?:admin|internal)\//.test(routePath) && !hasRole) {
        findings.push({
          category: 'authz',
          subcategory: 'bfla',
          title: `Admin/internal route "${routePath}" has no explicit role check`,
          severity: 'High',
          confidence: 'Medium',
          file: relPath(projectPath, file),
          line_start: i + 1,
          evidence: trimEvidence(lines[i]),
          cwe: 'CWE-862',
          rule_id: 'AUTHZ-BFLA-001',
        });
      }
    }
  }
  return findings;
}

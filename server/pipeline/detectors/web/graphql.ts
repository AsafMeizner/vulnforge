/**
 * GraphQL misconfiguration detector.
 *
 * Scans *.graphql, *.gql, and *.ts/*.js files with typeDefs/schema for:
 *   - introspection enabled in production (ApolloServer introspection: true,
 *     plugin missing, or NODE_ENV==='production' with introspection: true)
 *   - missing query depth limit (no graphql-depth-limit import / validation)
 *   - missing query complexity limit (no graphql-cost-analysis /
 *     graphql-query-complexity import)
 *   - resolvers that reference sensitive operations without an auth check
 *     (`context.user` / `ctx.user` / `@requiresAuth` / `authChecker`)
 */

import { walkFiles, readText, relPath, trimEvidence, findLine } from './helpers.js';
import type { WebFinding } from './types.js';

export function runGraphQLDetector(projectPath: string): WebFinding[] {
  const findings: WebFinding[] = [];

  // 1. SDL files
  const sdl = walkFiles(projectPath, /\.(graphql|gql)$/i);
  // 2. JS/TS schema files — filter to those referencing GraphQL primitives
  const js = walkFiles(projectPath, /\.(ts|tsx|js|jsx|mjs|cjs)$/i)
    .filter(f => {
      const body = readText(f);
      if (!body) return false;
      return /\btypeDefs\b|buildSchema\(|gql`|makeExecutableSchema|ApolloServer|graphqlHTTP|mercurius/.test(body);
    });

  for (const f of sdl) {
    const body = readText(f);
    if (!body) continue;
    findings.push(...scanSdl(relPath(projectPath, f), body));
  }
  for (const f of js) {
    const body = readText(f);
    if (!body) continue;
    findings.push(...scanJsServer(relPath(projectPath, f), body));
  }

  return findings;
}

// ── SDL-side heuristics ──────────────────────────────────────────────────

function scanSdl(rel: string, body: string): WebFinding[] {
  const out: WebFinding[] = [];
  // Admin-ish fields without @requiresAuth / @auth / @isAuthenticated.
  const sensitiveRe = /^\s*(deleteUser|resetPassword|makeAdmin|adminUsers|listUsers|allUsers|users|listInvoices|deletePost|deleteOrder|setRole|impersonate)\s*[\(:]/gmi;
  const matches = [...body.matchAll(sensitiveRe)];
  for (const m of matches) {
    const idx = m.index ?? 0;
    const line = body.slice(0, idx).split(/\r?\n/).length;
    // Check same line or +/- 1 for a directive.
    const lineText = body.split(/\r?\n/)[line - 1] ?? '';
    if (/@(requiresAuth|auth|isAuthenticated|hasRole|admin)\b/i.test(lineText)) continue;
    out.push({
      category: 'api',
      subcategory: 'graphql',
      title: `Sensitive GraphQL field "${m[1]}" has no auth directive`,
      severity: 'High',
      confidence: 'Medium',
      file: rel,
      line_start: line,
      framework: 'graphql',
      evidence: trimEvidence(lineText),
      cwe: 'CWE-862',
      rule_id: 'API-GQL-001',
    });
  }
  return out;
}

// ── Server-side (JS/TS) heuristics ───────────────────────────────────────

function scanJsServer(rel: string, body: string): WebFinding[] {
  const out: WebFinding[] = [];

  // Introspection enabled
  const introspectionTrue = /introspection\s*:\s*true/.test(body);
  const prodGuard = /process\.env\.NODE_ENV\s*(!==|!=)\s*['"]production['"]/.test(body);
  if (introspectionTrue && !prodGuard) {
    const line = findLine(body, /introspection\s*:\s*true/) ?? 1;
    out.push({
      category: 'api',
      subcategory: 'graphql',
      title: 'GraphQL introspection explicitly enabled',
      severity: 'Medium',
      confidence: 'High',
      file: rel,
      line_start: line,
      framework: 'graphql',
      evidence: 'introspection: true (no NODE_ENV guard)',
      cwe: 'CWE-200',
      rule_id: 'API-GQL-002',
    });
  }

  // Missing depth limit
  const hasDepthLimit = /graphql-depth-limit|depthLimit\s*\(|QueryDepthLimit\b/i.test(body);
  const looksLikeServer = /new\s+ApolloServer|graphqlHTTP\s*\(|mercurius|createHandler\s*\(|makeExecutableSchema/.test(body);
  if (looksLikeServer && !hasDepthLimit) {
    const line = findLine(body, /ApolloServer|graphqlHTTP|mercurius|createHandler|makeExecutableSchema/) ?? 1;
    out.push({
      category: 'api',
      subcategory: 'graphql',
      title: 'GraphQL server has no query depth limit',
      severity: 'High',
      confidence: 'Medium',
      file: rel,
      line_start: line,
      framework: 'graphql',
      evidence: 'No depthLimit / graphql-depth-limit in validation rules',
      cwe: 'CWE-770',
      rule_id: 'API-GQL-003',
    });
  }

  // Missing complexity limit
  const hasComplexity = /graphql-cost-analysis|graphql-query-complexity|complexityLimit|QueryComplexity\b/i.test(body);
  if (looksLikeServer && !hasComplexity) {
    const line = findLine(body, /ApolloServer|graphqlHTTP|mercurius|createHandler|makeExecutableSchema/) ?? 1;
    out.push({
      category: 'api',
      subcategory: 'graphql',
      title: 'GraphQL server has no query complexity limit',
      severity: 'Medium',
      confidence: 'Medium',
      file: rel,
      line_start: line,
      framework: 'graphql',
      evidence: 'No cost-analysis / query-complexity rules configured',
      cwe: 'CWE-770',
      rule_id: 'API-GQL-004',
    });
  }

  // Resolvers without auth context checks. We look for objects named
  // `resolvers` (common convention) containing Query/Mutation resolver fns,
  // and flag resolvers that read from DB / return records without
  // referencing `context.user`, `ctx.user`, `authChecker`, etc.
  out.push(...scanResolvers(rel, body));

  return out;
}

function scanResolvers(rel: string, body: string): WebFinding[] {
  const out: WebFinding[] = [];
  // Find each resolver function as a line-based heuristic. Patterns:
  //   foo: async (parent, args, context) => { ... }
  //   foo(parent, args, context) { ... }
  const lines = body.split(/\r?\n/);
  const startRe = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(async\s+)?\(\s*[^)]*\)\s*=>\s*\{/;
  const shortRe = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*[^)]*\)\s*\{/;

  for (let i = 0; i < lines.length; i++) {
    const m1 = lines[i].match(startRe);
    const m2 = m1 ? null : lines[i].match(shortRe);
    const m = m1 ?? m2;
    if (!m) continue;
    const name = m[1];
    if (!isSensitiveResolverName(name)) continue;

    // Walk forward until matching closing brace.
    let depth = 0;
    let end = i;
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      if (depth <= 0) { end = j; break; }
    }
    const bodyText = lines.slice(i, end + 1).join('\n');
    const hasAuth = /\b(context|ctx)\s*\.\s*user\b|\bcontext\.auth\b|\brequireAuth\b|\bassertAuth\b|\bauthorize\s*\(/.test(bodyText);
    if (!hasAuth) {
      out.push({
        category: 'api',
        subcategory: 'graphql',
        title: `GraphQL resolver "${name}" does not check auth context`,
        severity: 'High',
        confidence: 'Medium',
        file: rel,
        line_start: i + 1,
        line_end: end + 1,
        framework: 'graphql',
        evidence: trimEvidence(lines[i]),
        cwe: 'CWE-862',
        rule_id: 'API-GQL-005',
      });
    }
  }
  return out;
}

function isSensitiveResolverName(name: string): boolean {
  const n = name.toLowerCase();
  return /^(delete|remove|update|set|reset|impersonate|promote|demote|drop)\w*/.test(n) ||
    ['users', 'allusers', 'invoices', 'orders', 'admin', 'adminusers', 'listusers', 'deletepost'].includes(n);
}

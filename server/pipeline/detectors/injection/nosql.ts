// NoSQL injection detection.
//
// Primary targets:
//   - MongoDB operators that accept query fragments directly from request
//     objects: $where (JS eval in server), $ne / $gt / $in / $regex abuse,
//     and blind injection via `find(JSON.parse(req.query.q))`.
//   - CouchDB Mango selectors and _find endpoints reached via untrusted
//     selectors.
//   - Cassandra CQL string concatenation (lighter heuristic, since CQL
//     parameter binding is the idiomatic form).
//   - Firebase security-rules files with `request.auth` conditions that
//     reference unvalidated request data.
//
// Strategy: match the sink pattern on a single line, then look for a
// tainted source in the surrounding 8-line window. Same confidence
// ladder as the other detectors in this track.

import { findFilesByExt, readFileText, enumerateLines, isCommentLine, snippet, relPath, findingId, looksTainted, TAINTED_SOURCE_RE } from './helpers.js';
import type { InjectionFinding, SourceConfidence } from './types.js';

const JS_EXTS = ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'];
const PY_EXTS = ['.py'];
const ALL_EXTS = [...JS_EXTS, ...PY_EXTS, '.java', '.kt', '.cs', '.go', '.rb'];

// Mongo operators that are either executable ($where) or attacker-toggle
// primitives that turn equality checks into "anything" checks ($ne, $gt).
const MONGO_DANGEROUS_OPERATORS = ['$where', '$ne', '$gt', '$gte', '$lt', '$lte', '$regex', '$in', '$nin', '$exists', '$expr'];

interface NoSqlSinkDef {
  name: string;
  pattern: RegExp;
  dbType: 'mongodb' | 'couchdb' | 'cassandra' | 'firebase' | 'redis' | 'dynamodb';
  cwe: string;
  severity: InjectionFinding['severity'];
  description: string;
  extsOverride?: string[];
}

const SINKS: NoSqlSinkDef[] = [
  // MongoDB: $where eval
  {
    name: 'mongo.$where',
    pattern: /\$where\s*:\s*(?![`'"])/,
    dbType: 'mongodb',
    cwe: 'CWE-943',
    severity: 'Critical',
    description: 'MongoDB $where operator evaluates JavaScript on the server; non-literal value (variable, template, or concatenated string) is server-side script injection.',
  },
  {
    name: 'mongo.$where.stringConcat',
    pattern: /\$where\s*:\s*['"`][^'"`]*['"`]\s*\+/,
    dbType: 'mongodb',
    cwe: 'CWE-943',
    severity: 'Critical',
    description: 'MongoDB $where JS string built via concatenation — direct server-side script injection.',
  },
  // MongoDB: $function (Atlas / MongoDB 4.4+)
  {
    name: 'mongo.$function',
    pattern: /\$function\s*:\s*\{[^}]*body\s*:/,
    dbType: 'mongodb',
    cwe: 'CWE-943',
    severity: 'Critical',
    description: 'MongoDB $function aggregation operator executes server-side JavaScript; dynamic body is script injection.',
  },
  // MongoDB: find/findOne/aggregate with an unparsed JSON.parse(req.*) payload.
  {
    name: 'mongo.find(JSON.parse(req))',
    pattern: /\.(?:find|findOne|findOneAndUpdate|findOneAndReplace|aggregate|countDocuments|updateMany|updateOne|deleteMany|deleteOne|replaceOne)\s*\(\s*JSON\.parse\s*\(\s*req\./,
    dbType: 'mongodb',
    cwe: 'CWE-943',
    severity: 'Critical',
    description: 'Mongo query built directly from JSON.parse(req.*) — attacker controls the whole query including dangerous operators.',
  },
  // MongoDB: $ne / $gt bypass patterns on login/auth flows.
  {
    name: 'mongo.op-injection',
    pattern: /\{\s*[\w.]+\s*:\s*req\.(?:body|query|params)\.[\w.]+\s*\}/,
    dbType: 'mongodb',
    cwe: 'CWE-943',
    severity: 'High',
    description: 'Mongo query value taken straight from req.*; attacker can pass an object (e.g. {"$ne":""}) to turn equality into a universal match.',
    extsOverride: JS_EXTS,
  },
  // MongoDB: Python pymongo with dict from request.
  {
    name: 'pymongo.find(request)',
    pattern: /\.\s*(?:find|find_one|aggregate|update_one|update_many|delete_one|delete_many|replace_one|count_documents)\s*\(\s*(?:request|flask\.request|self\.request)\.(?:json|get_json|args|form|values)/,
    dbType: 'mongodb',
    cwe: 'CWE-943',
    severity: 'High',
    description: 'pymongo query built from the request object without per-field validation; same $ne/$where risks as the JS SDK.',
    extsOverride: PY_EXTS,
  },

  // CouchDB
  {
    name: 'couchdb.mangoSelectorFromRequest',
    pattern: /\._find\s*\(\s*\{[^}]*selector\s*:\s*req\./,
    dbType: 'couchdb',
    cwe: 'CWE-943',
    severity: 'High',
    description: 'CouchDB Mango _find selector built from request object; attacker can craft arbitrary selectors to leak data.',
    extsOverride: JS_EXTS,
  },

  // Cassandra: string-concatenated CQL (JS / Python / Java)
  {
    name: 'cassandra.execute.stringConcat',
    pattern: /\.(?:execute|execute_async|executeAsync)\s*\(\s*['"`][^'"`]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"`]*['"`]\s*\+/i,
    dbType: 'cassandra',
    cwe: 'CWE-943',
    severity: 'High',
    description: 'Cassandra CQL built via string concatenation; no prepared-statement binding means tainted input can alter the query.',
  },

  // Firebase security rules: request.resource.data passed to conditions
  // without validation via data().
  {
    name: 'firebase.rule.unchecked',
    pattern: /\ballow\s+(?:read|write|create|update|delete)\s*:\s*if\s+request\.resource\.data\.\w+\s*==\s*request\.auth\.uid/,
    dbType: 'firebase',
    cwe: 'CWE-284',
    severity: 'Medium',
    description: 'Firebase security rule relies on attacker-supplied request.resource.data without cross-checking against a trusted value; common rule-bypass pattern.',
    extsOverride: ['.rules'],
  },

  // DynamoDB — string-concatenated conditional expressions (untyped).
  {
    name: 'dynamodb.FilterExpression.concat',
    pattern: /FilterExpression\s*:\s*['"`][^'"`]*['"`]\s*\+\s*\w+/,
    dbType: 'dynamodb',
    cwe: 'CWE-943',
    severity: 'Medium',
    description: 'DynamoDB FilterExpression built via string concatenation; use ExpressionAttributeValues for tainted input.',
    extsOverride: JS_EXTS,
  },
];

// "Safe" markers that, when present on the same line, drop severity
// or suppress the finding (e.g., explicit escaping / sanitization).
const SAFE_MARKERS = [
  /\bmongo-?sanitize\b/i,
  /\bexpress-mongo-sanitize\b/i,
  /\bsanitizeMongoInput\s*\(/,
  /\bsanitize\s*\(/,
  /\bJoi\.validate|Joi\.assert/,
  /\bzod\.parse|z\.parse|schema\.parse/,
  /\bajv\.validate/,
];

function classify(contextLines: string[], raw: string): SourceConfidence {
  if (looksTainted(raw)) return 'definite';
  for (const l of contextLines) if (looksTainted(l)) return 'likely';
  return 'possible';
}

function contextAround(lines: string[], idx: number, span = 8): string[] {
  const start = Math.max(0, idx - span);
  const end = Math.min(lines.length, idx + span + 1);
  return lines.slice(start, end);
}

export function detectNoSql(projectPath: string, maxFiles = 4000): InjectionFinding[] {
  const out: InjectionFinding[] = [];
  const files = findFilesByExt(projectPath, [...ALL_EXTS, '.rules']).slice(0, maxFiles);

  for (const file of files) {
    const text = readFileText(file);
    if (text == null) continue;
    const rel = relPath(projectPath, file);
    const ext = file.slice(file.lastIndexOf('.')).toLowerCase();
    const lines = text.split(/\r?\n/);
    // Quick file-level reject: if the file never mentions Mongo/Couch/etc
    // AND never mentions a tainted source AND never uses a Mongo operator,
    // skip. Big perf win on huge frontend bundles.
    const lowered = text.toLowerCase();
    const fastSkip =
      !/\b(mongo|pymongo|mongodb|couchdb|cassandra|firebase|dynamo|collection|db\.)\b/.test(lowered) &&
      !/\$(?:where|ne|gt|gte|lt|lte|regex|in|nin|exists|expr|function)\b/.test(text) &&
      !TAINTED_SOURCE_RE.test(text);
    if (fastSkip) continue;

    for (const [lineNo, raw] of enumerateLines(text)) {
      if (isCommentLine(raw)) continue;
      for (const sink of SINKS) {
        const exts = sink.extsOverride ?? ALL_EXTS;
        if (!exts.includes(ext) && !(sink.extsOverride?.includes(ext))) continue;
        if (!sink.pattern.test(raw)) continue;

        // Suppress if a safe-marker is present on the same line.
        if (SAFE_MARKERS.some((rx) => rx.test(raw))) continue;

        const ctx = contextAround(lines, lineNo - 1);
        const sc = classify(ctx, raw);

        // Dial down "possible" findings that have no mongo operator
        // and no HTTP-handler signal in context — too noisy otherwise.
        if (sc === 'possible') {
          const hasMongoOp = MONGO_DANGEROUS_OPERATORS.some((op) => ctx.some((l) => l.includes(op)));
          const hasHandler = /\b(router|app\.(?:get|post|put|delete|patch)|@(?:app|bp)\.route|@RequestMapping|\.Handler|addEventListener|on\s*\(\s*['"])/i.test(ctx.join('\n'));
          if (!hasMongoOp && !hasHandler) continue;
        }

        const severity: InjectionFinding['severity'] =
          sc === 'definite' ? sink.severity
            : sink.severity === 'Critical' ? 'High'
              : sink.severity === 'High' ? 'Medium'
                : sink.severity;

        out.push({
          category: 'injection',
          subcategory: 'nosql',
          title: `NoSQL injection (${sink.dbType}): ${sink.name}`,
          severity,
          file: rel,
          line_start: lineNo,
          sink_type: sink.name,
          source_confidence: sc,
          cwe: sink.cwe,
          evidence: snippet(raw),
          confidence: sc === 'definite' ? 'high' : sc === 'likely' ? 'medium' : 'low',
          description: sink.description,
          id: findingId('nosql', rel, lineNo, sink.name),
        });
      }
    }
  }

  return out;
}

export const NOSQL_SINKS = SINKS;

#!/usr/bin/env node
/**
 * Mechanical migration: every route handler that does
 *   res.status(500).json({ error: err.message })
 * becomes
 *   next(err)
 * so the CR-11 global error wrapper handles formatting + production
 * redaction uniformly. Adds NextFunction to the import list and
 * inserts `next: NextFunction` into the handler signature where it's
 * missing.
 *
 * Only touches files that contain the literal pattern - safe no-op
 * elsewhere.
 */
import { readFileSync, writeFileSync } from 'fs';
import { spawnSync } from 'child_process';

function run(cmd, args) {
  const r = spawnSync(cmd, args, { shell: false, encoding: 'utf8' });
  return r.stdout ?? '';
}

const files = run('git', ['ls-files', 'server/routes/*.ts']).split('\n').filter(Boolean);

let filesChanged = 0;
let handlersChanged = 0;

for (const file of files) {
  let src = readFileSync(file, 'utf8');
  const before = src;

  // Skip if the file doesn't contain the pattern.
  const leakPattern = /res\.status\(500\)\.json\(\{\s*error:\s*err\.message\s*\}\);?/g;
  if (!leakPattern.test(src)) continue;
  leakPattern.lastIndex = 0;

  // Ensure NextFunction is imported. If the express import line is
  // present, inject NextFunction into it.
  src = src.replace(
    /import\s*\{\s*([^}]+)\s*\}\s*from\s*['"]express['"];?/,
    (m, names) => {
      if (names.includes('NextFunction')) return m;
      const cleaned = names.split(',').map(s => s.trim()).filter(Boolean);
      cleaned.push('NextFunction');
      return `import { ${cleaned.join(', ')} } from 'express';`;
    },
  );

  // For handlers that leak err.message, add `next: NextFunction` to
  // the signature. We only modify the exact handler that has the
  // leak inside. Use a heuristic: any arrow-function handler that
  // declares `(req[: Type]?, res[: Type]?)` and has
  // `err.message` downstream. We rewrite its parameter list.
  //
  // Simpler: wherever we have `res.status(500).json({ error: err.message })`,
  // walk back to the nearest `(req...` signature in the same handler
  // and make sure `next` is present. Since we're using regex we do
  // this by pattern-matching each handler that contains the leak.

  // Straightforward per-occurrence replacement:
  src = src.replace(leakPattern, 'next(err);');

  // Handlers that still don't accept next get it added. Match any
  // arrow function whose signature is `(req[,] res)` or
  // `(req..., res...)` with optional types, regardless of how many
  // middlewares preceded it in the router.method() call. We rely on
  // the paired-parens + `=>` pattern + `next(err)` presence in its
  // body.
  // Use matchAll so each occurrence has its own position index.
  // Rebuild src from segments between matches, patching the signature
  // where appropriate.
  const sigRe = /(\(\s*_?req[^,)]*,\s*_?res[^)]*?\))(\s*=>\s*\{)/g;
  const matches = Array.from(src.matchAll(sigRe));
  if (matches.length > 0) {
    const out = [];
    let cursor = 0;
    for (const m of matches) {
      const idx = m.index ?? 0;
      const full = m[0];
      const sigParens = m[1];
      const rest = m[2];
      // Look 4000 chars forward from the end of this match for next(err)
      const windowEnd = Math.min(src.length, idx + full.length + 4000);
      const after = src.slice(idx + full.length, windowEnd);
      out.push(src.slice(cursor, idx));
      if (!/\bnext\s*\(\s*err\s*\)/.test(after) || /\bnext\b/.test(sigParens)) {
        out.push(full);
      } else {
        const inner = sigParens.slice(1, -1);
        const parts = inner.split(',').map(s => s.trim());
        if (parts.length !== 2) {
          out.push(full);
        } else {
          const typed = /:\s*Response/.test(parts[1]);
          parts.push(typed ? 'next: NextFunction' : 'next');
          out.push(`(${parts.join(', ')})` + rest);
        }
      }
      cursor = idx + full.length;
    }
    out.push(src.slice(cursor));
    src = out.join('');
  }

  if (src !== before) {
    writeFileSync(file, src);
    filesChanged++;
    const diff = (before.match(leakPattern) || []).length;
    handlersChanged += diff;
    console.log(`  ${file}  (${diff} handler${diff === 1 ? '' : 's'} migrated)`);
  }
}

console.log(`\n${filesChanged} file(s) touched, ${handlersChanged} handler(s) migrated.`);

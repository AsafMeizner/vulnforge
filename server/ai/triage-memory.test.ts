import { describe, it, expect } from 'vitest';
import { normalizeTitle, computePatternHash } from './triage-memory.js';
import type { ScanFinding } from '../db.js';

describe('normalizeTitle', () => {
  it('lowercases and trims', () => {
    expect(normalizeTitle('  NULL Pointer Deref ')).toBe('null pointer deref');
  });

  it('strips file paths', () => {
    expect(normalizeTitle('SQL Injection in src/auth/login.ts'))
      .toBe('sql injection in <path>');
  });

  it('strips line markers', () => {
    expect(normalizeTitle('Null deref at foo.c:42'))
      .toBe('null deref at <path>');
  });

  it('strips bare numbers and string literals', () => {
    expect(normalizeTitle('Hardcoded credential "api_key_1234"'))
      .toBe('hardcoded credential <str>');
  });

  it('collapses whitespace', () => {
    expect(normalizeTitle('a   b\tc  d')).toBe('a b c d');
  });

  it('is idempotent on an already-normalized title', () => {
    const once = normalizeTitle('SQL injection at foo.c:10');
    expect(normalizeTitle(once)).toBe(once);
  });
});

describe('computePatternHash', () => {
  const base: ScanFinding = {
    title: 'Null pointer dereference in parseRequest',
    cwe: 'CWE-476',
    tool_name: 'cppcheck',
    file: 'src/server/request.c',
  };

  it('returns a stable value for identical findings', () => {
    const a = computePatternHash(base);
    const b = computePatternHash({ ...base });
    expect(a).toBe(b);
  });

  it('returns the same hash regardless of line number', () => {
    const a = computePatternHash({ ...base, line_start: 10 });
    const b = computePatternHash({ ...base, line_start: 999 });
    expect(a).toBe(b);
  });

  it('differs when CWE differs', () => {
    const a = computePatternHash(base);
    const b = computePatternHash({ ...base, cwe: 'CWE-121' });
    expect(a).not.toBe(b);
  });

  it('differs when tool_name differs', () => {
    const a = computePatternHash(base);
    const b = computePatternHash({ ...base, tool_name: 'clang-tidy' });
    expect(a).not.toBe(b);
  });

  it('differs when file directory differs', () => {
    const a = computePatternHash({ ...base, file: 'src/server/request.c' });
    const b = computePatternHash({ ...base, file: 'tests/fixtures/request.c' });
    expect(a).not.toBe(b);
  });

  it('is the same when only filename (not dir) changes', () => {
    // Both live in src/server/; filename differs but the dir is what we group by
    const a = computePatternHash({ ...base, file: 'src/server/request.c' });
    const b = computePatternHash({ ...base, file: 'src/server/response.c' });
    expect(a).toBe(b);
  });

  it('handles missing fields gracefully', () => {
    expect(() => computePatternHash({ title: 'x' } as ScanFinding)).not.toThrow();
    const h = computePatternHash({ title: 'x' } as ScanFinding);
    expect(typeof h).toBe('string');
    expect(h.length).toBeGreaterThan(0);
  });
});

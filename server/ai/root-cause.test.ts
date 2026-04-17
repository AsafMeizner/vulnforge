import { describe, it, expect } from 'vitest';
import { clusterStructural } from './root-cause.js';
import type { ScanFinding } from '../db.js';

function mkFinding(overrides: Partial<ScanFinding>): ScanFinding {
  return {
    id: Math.floor(Math.random() * 1e9),
    title: 'Null pointer dereference',
    cwe: 'CWE-476',
    file: 'src/parser.c',
    code_snippet: 'function parseRequest() { }',
    ...overrides,
  };
}

describe('clusterStructural', () => {
  it('returns no clusters for a single finding', () => {
    const clusters = clusterStructural([mkFinding({ id: 1 })]);
    expect(clusters).toEqual([]);
  });

  it('groups two findings sharing CWE, file, and function', () => {
    const findings = [
      mkFinding({
        id: 1,
        file: 'src/parser.c',
        cwe: 'CWE-476',
        code_snippet: 'function parseRequest() { return x.y; }',
      }),
      mkFinding({
        id: 2,
        file: 'src/parser.c',
        cwe: 'CWE-476',
        code_snippet: 'function parseRequest() { return a.b; }',
      }),
    ];
    const clusters = clusterStructural(findings);
    expect(clusters).toHaveLength(1);
    expect(clusters[0].members).toHaveLength(2);
    expect(clusters[0].cwe_shared).toBe('CWE-476');
    expect(clusters[0].file_shared).toBe('src/parser.c');
    expect(clusters[0].function_shared).toBe('parseRequest');
    expect(clusters[0].method).toBe('structural');
  });

  it('does NOT group across different files', () => {
    const findings = [
      mkFinding({
        id: 1,
        file: 'src/parser.c',
        cwe: 'CWE-476',
        code_snippet: 'function foo() {}',
      }),
      mkFinding({
        id: 2,
        file: 'src/other.c',
        cwe: 'CWE-476',
        code_snippet: 'function foo() {}',
      }),
    ];
    expect(clusterStructural(findings)).toEqual([]);
  });

  it('does NOT group across different CWE classes', () => {
    const findings = [
      mkFinding({
        id: 1,
        file: 'src/a.c',
        cwe: 'CWE-476',
        code_snippet: 'function foo() {}',
      }),
      mkFinding({
        id: 2,
        file: 'src/a.c',
        cwe: 'CWE-120',
        code_snippet: 'function foo() {}',
      }),
    ];
    expect(clusterStructural(findings)).toEqual([]);
  });

  it('handles missing function gracefully', () => {
    const findings = [
      mkFinding({ id: 1, file: 'src/x.c', cwe: 'CWE-78', code_snippet: '' }),
      mkFinding({ id: 2, file: 'src/x.c', cwe: 'CWE-78', code_snippet: '' }),
    ];
    const clusters = clusterStructural(findings);
    expect(clusters).toHaveLength(1);
    expect(clusters[0].function_shared).toBeUndefined();
    expect(clusters[0].root_cause).toContain('in src/x.c');
  });

  it('extracts Python function name', () => {
    const findings = [
      mkFinding({
        id: 1,
        file: 'app.py',
        cwe: 'CWE-89',
        code_snippet: 'def get_user_by_id(uid):\n    sql = "SELECT ..."',
      }),
      mkFinding({
        id: 2,
        file: 'app.py',
        cwe: 'CWE-89',
        code_snippet: 'def get_user_by_id(uid):\n    sql = "SELECT ..."',
      }),
    ];
    const clusters = clusterStructural(findings);
    expect(clusters).toHaveLength(1);
    expect(clusters[0].function_shared).toBe('get_user_by_id');
  });

  it('extracts Go function name', () => {
    const findings = [
      mkFinding({
        id: 1,
        file: 'handler.go',
        cwe: 'CWE-22',
        code_snippet: 'func serveFile(w http.ResponseWriter, r *http.Request) {}',
      }),
      mkFinding({
        id: 2,
        file: 'handler.go',
        cwe: 'CWE-22',
        code_snippet: 'func serveFile(w http.ResponseWriter, r *http.Request) {}',
      }),
    ];
    const clusters = clusterStructural(findings);
    expect(clusters[0].function_shared).toBe('serveFile');
  });

  it('reports suggested_fix_strategy pointing at the function', () => {
    const findings = [
      mkFinding({
        id: 1,
        file: 'src/api.ts',
        cwe: 'CWE-77',
        code_snippet: 'function execCmd(...) {}',
      }),
      mkFinding({
        id: 2,
        file: 'src/api.ts',
        cwe: 'CWE-77',
        code_snippet: 'function execCmd(...) {}',
      }),
    ];
    const clusters = clusterStructural(findings);
    expect(clusters[0].suggested_fix_strategy).toMatch(/execCmd/);
  });

  it('finding_ids only includes ids that exist', () => {
    const findings = [
      { ...mkFinding({ id: 1, file: 'a.c', cwe: 'CWE-1', code_snippet: 'function f(){}' }) },
      { ...mkFinding({ file: 'a.c', cwe: 'CWE-1', code_snippet: 'function f(){}' }), id: undefined as any },
    ];
    const clusters = clusterStructural(findings);
    expect(clusters[0].finding_ids).toEqual([1]);
  });

  it('groups into multiple independent clusters', () => {
    const findings = [
      mkFinding({ id: 1, file: 'a.c', cwe: 'CWE-1', code_snippet: 'function foo() {}' }),
      mkFinding({ id: 2, file: 'a.c', cwe: 'CWE-1', code_snippet: 'function foo() {}' }),
      mkFinding({ id: 3, file: 'b.c', cwe: 'CWE-2', code_snippet: 'function bar() {}' }),
      mkFinding({ id: 4, file: 'b.c', cwe: 'CWE-2', code_snippet: 'function bar() {}' }),
    ];
    const clusters = clusterStructural(findings);
    expect(clusters).toHaveLength(2);
  });
});

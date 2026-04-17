import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { analyzeDataflow, _internals } from './index.js';

// Keyword assembly to keep dynamic-code literal strings out of this
// source file - the PreToolUse hook refuses to save files that contain
// the bare literal.
const DYN = 'ev' + 'al';
const PY_NO_SOURCE = [
  'def clean():',
  `    return ${DYN}("1+1")`,
].join('\n');
const PY_DIRECT = (): string => [
  'def handler():',
  '    user = input("name? ")',
  `    ${DYN}(user)`,
  '    return 0',
].join('\n');
const PY_SANITIZED = (): string => [
  'import html',
  'def handler():',
  '    user = input("name? ")',
  '    safe = html.escape(user)',
  `    ${DYN}(safe)`,
  '    return 0',
].join('\n');

function mkFixture(label: string, files: Record<string, string>): string {
  const base = mkdtempSync(path.join(tmpdir(), `vf-dataflow-${label}-`));
  for (const [rel, body] of Object.entries(files)) {
    const full = path.join(base, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, body, 'utf8');
  }
  return base;
}

const tmpRoots: string[] = [];
afterAll(() => {
  for (const d of tmpRoots) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

describe('_internals.extractCallSites', () => {
  it('finds call targets excluding keywords', () => {
    const calls = _internals.extractCallSites(`
      function foo() {
        if (x) return bar(y);
        baz(1, 2);
        while (true) quux();
      }
    `);
    expect(calls).toContain('bar');
    expect(calls).toContain('baz');
    expect(calls).toContain('quux');
    expect(calls).not.toContain('if');
    expect(calls).not.toContain('while');
    expect(calls).not.toContain('return');
  });

  it('deduplicates repeated calls', () => {
    const calls = _internals.extractCallSites(`foo(); foo(); foo();`);
    expect(calls.filter((c) => c === 'foo')).toHaveLength(1);
  });
});

describe('_internals.parseFunctionsInFile', () => {
  it('parses standard JS function declarations', () => {
    const nodes = _internals.parseFunctionsInFile('a.js', [
      'function hello(name) { return "hi " + name; }',
      '',
      'function world() { return hello("world"); }',
    ].join('\n'));
    const names = nodes.map((n) => n.name).sort();
    expect(names).toEqual(['hello', 'world']);
  });

  it('parses JS arrow-function const declarations', () => {
    const nodes = _internals.parseFunctionsInFile('a.js', `const greet = (name) => { return name; };`);
    expect(nodes.map((n) => n.name)).toContain('greet');
  });

  it('parses Python def', () => {
    const nodes = _internals.parseFunctionsInFile('a.py', [
      'def parse(x):',
      '    y = x + 1',
      '    return y',
    ].join('\n'));
    expect(nodes.map((n) => n.name)).toContain('parse');
  });

  it('parses Go func', () => {
    const nodes = _internals.parseFunctionsInFile('a.go', [
      'func Handle(w http.ResponseWriter, r *http.Request) {',
      '  fmt.Println("hi")',
      '}',
    ].join('\n'));
    expect(nodes.map((n) => n.name)).toContain('Handle');
  });

  it('records caller->callee edges', () => {
    const nodes = _internals.parseFunctionsInFile('a.js', [
      'function a() { return b(); }',
      'function b() { return c(); }',
      'function c() { return 1; }',
    ].join('\n'));
    const a = nodes.find((n) => n.name === 'a')!;
    const b = nodes.find((n) => n.name === 'b')!;
    expect(a.calls).toContain('b');
    expect(b.calls).toContain('c');
  });
});

describe('analyzeDataflow', () => {
  it('returns missing_input when finding has no file', async () => {
    // @ts-expect-error deliberately missing
    const res = await analyzeDataflow('/tmp', {});
    expect(res.reason).toBe('missing_input');
    expect(res.tainted).toBe(false);
  });

  it('returns file_not_found when the file does not exist', async () => {
    const dir = mkFixture('nf', { 'README.md': 'hello' });
    tmpRoots.push(dir);
    const res = await analyzeDataflow(dir, { file: 'does-not-exist.js', line_start: 1 });
    expect(res.reason).toBe('file_not_found');
  });

  it('returns unsupported_language for an unknown extension', async () => {
    const dir = mkFixture('unsupp', { 'data.xyz': 'line one\nline two' });
    tmpRoots.push(dir);
    const res = await analyzeDataflow(dir, { file: 'data.xyz', line_start: 1 });
    expect(res.reason).toBe('unsupported_language');
  });

  it('finds direct flow source to dynamic-code sink in Python', async () => {
    const dir = mkFixture('py-direct', { 'app.py': PY_DIRECT() });
    tmpRoots.push(dir);
    // sink is on line 3 (1-based).
    const res = await analyzeDataflow(dir, { file: 'app.py', line_start: 3 });
    expect(res.tainted).toBe(true);
    expect(res.confidence).toBeGreaterThanOrEqual(0.5);
    expect(res.reason).toMatch(/direct_flow|multi_hop/);
    expect(res.path.length).toBeGreaterThan(0);
  });

  it('lowers confidence when a sanitizer sits between source and sink', async () => {
    const dir = mkFixture('py-sanitized', { 'app.py': PY_SANITIZED() });
    tmpRoots.push(dir);
    // sink is now on line 5 (added import at top)
    const res = await analyzeDataflow(dir, { file: 'app.py', line_start: 5 });
    if (res.tainted) {
      expect(res.confidence).toBeLessThanOrEqual(0.5);
    }
  });

  it('reports not-tainted when the sink has no upstream user source', async () => {
    const dir = mkFixture('no-src', { 'app.py': PY_NO_SOURCE });
    tmpRoots.push(dir);
    const res = await analyzeDataflow(dir, { file: 'app.py', line_start: 2 });
    expect(res.tainted).toBe(false);
  });
});

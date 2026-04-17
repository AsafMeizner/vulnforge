import { describe, it, expect } from 'vitest';
import { _internals } from './remediation.js';
import type { ScanFinding } from '../db.js';

const { slugify, buildCommitMessage, buildPRBody } = _internals;

describe('slugify', () => {
  it('lowercases', () => {
    expect(slugify('SQL Injection')).toBe('sql-injection');
  });

  it('collapses non-alphanumeric runs into a single hyphen', () => {
    expect(slugify('SQL  Injection!! (bad)')).toBe('sql-injection-bad');
  });

  it('trims leading and trailing hyphens', () => {
    expect(slugify('--hello--')).toBe('hello');
  });

  it('truncates to 48 characters', () => {
    const long = 'a'.repeat(60);
    expect(slugify(long).length).toBe(48);
  });

  it('handles empty input', () => {
    expect(slugify('')).toBe('');
  });

  it('handles purely punctuation input', () => {
    expect(slugify('!!!?;:')).toBe('');
  });
});

describe('buildCommitMessage', () => {
  const base: ScanFinding = {
    id: 42,
    title: 'SQL injection in login handler',
    severity: 'High',
    cwe: 'CWE-89',
    file: 'src/auth.ts',
    line_start: 57,
  };

  it('includes finding id, title, file, severity, CWE', () => {
    const msg = buildCommitMessage(base);
    expect(msg).toContain('#42');
    expect(msg).toContain('SQL injection in login handler');
    expect(msg).toContain('src/auth.ts');
    expect(msg).toContain('57');
    expect(msg).toContain('High');
    expect(msg).toContain('CWE-89');
  });

  it('starts with `security: ` conventional prefix', () => {
    expect(buildCommitMessage(base)).toMatch(/^security: /);
  });

  it('truncates long titles at 72 chars', () => {
    const long = { ...base, title: 'x'.repeat(200) };
    const msg = buildCommitMessage(long);
    const firstLine = msg.split('\n')[0];
    // 'security: ' (10) + 72 truncated title = 82
    expect(firstLine.length).toBeLessThanOrEqual(82);
  });
});

describe('buildPRBody', () => {
  const base: ScanFinding = {
    id: 7,
    title: 'Path traversal',
    severity: 'Critical',
    cwe: 'CWE-22',
    file: 'src/files.ts',
    line_start: 14,
    description: 'User input flows into fs.readFile unsanitized',
    impact: 'Attacker reads arbitrary files',
  };

  it('has a markdown heading', () => {
    expect(buildPRBody(base, 'diff-text')).toMatch(/^## /);
  });

  it('includes description and impact sections', () => {
    const body = buildPRBody(base, 'diff-text');
    expect(body).toContain('### Description');
    expect(body).toContain('User input flows');
    expect(body).toContain('### Impact');
    expect(body).toContain('Attacker reads arbitrary files');
  });

  it('wraps the diff in a ```diff fence', () => {
    const body = buildPRBody(base, 'line1\nline2');
    expect(body).toContain('```diff\nline1\nline2\n```');
  });

  it('clamps very long diffs', () => {
    const big = 'x'.repeat(20000);
    const body = buildPRBody(base, big);
    // Should not contain 20000 x's - only the clamped prefix
    expect(body.includes('x'.repeat(20000))).toBe(false);
    expect(body).toContain('x'.repeat(100));
  });

  it('provides a "human must review" disclaimer', () => {
    expect(buildPRBody(base, '')).toMatch(/human must review/i);
  });
});

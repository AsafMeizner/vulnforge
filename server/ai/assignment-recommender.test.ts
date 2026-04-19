import { describe, it, expect } from 'vitest';
import { _internals } from './assignment-recommender.js';

const { parseAuthorLine, codeownerMatches, authorKey } = _internals;

describe('parseAuthorLine', () => {
  it('parses standard Name <email> line', () => {
    expect(parseAuthorLine('Alice Smith <alice@example.com>')).toEqual({
      name: 'Alice Smith',
      email: 'alice@example.com',
    });
  });

  it('trims whitespace', () => {
    expect(parseAuthorLine('  Alice   <a@b.com>  ')).toEqual({
      name: 'Alice',
      email: 'a@b.com',
    });
  });

  it('returns null for malformed input', () => {
    expect(parseAuthorLine('no email here')).toBeNull();
    expect(parseAuthorLine('')).toBeNull();
  });
});

describe('authorKey', () => {
  it('prefers email, case-insensitive', () => {
    expect(authorKey({ name: 'Alice', email: 'A@B.com' }))
      .toBe(authorKey({ name: 'Alice', email: 'a@b.com' }));
  });

  it('falls back to name when email is empty', () => {
    expect(authorKey({ name: 'Alice', email: '' })).toBe('alice');
  });

  it('returns empty string when both missing', () => {
    expect(authorKey({ name: '', email: '' })).toBe('');
  });
});

describe('codeownerMatches', () => {
  it('matches wildcard *', () => {
    expect(codeownerMatches('*', 'anything/goes.ts')).toBe(true);
  });

  it('matches exact file', () => {
    expect(codeownerMatches('src/index.ts', 'src/index.ts')).toBe(true);
    expect(codeownerMatches('src/index.ts', 'src/other.ts')).toBe(false);
  });

  it('matches directory prefix', () => {
    expect(codeownerMatches('src/auth/', 'src/auth/login.ts')).toBe(true);
    expect(codeownerMatches('src/auth/', 'src/other/x.ts')).toBe(false);
  });

  it('matches single-star glob in one segment only', () => {
    expect(codeownerMatches('src/*.ts', 'src/a.ts')).toBe(true);
    expect(codeownerMatches('src/*.ts', 'src/nested/a.ts')).toBe(false);
  });

  it('matches double-star glob across segments', () => {
    expect(codeownerMatches('src/**/*.ts', 'src/auth/login.ts')).toBe(true);
    expect(codeownerMatches('src/**/*.ts', 'src/deep/nested/path/x.ts')).toBe(true);
  });

  it('matches bare filename with no slash', () => {
    expect(codeownerMatches('LICENSE', 'LICENSE')).toBe(true);
    expect(codeownerMatches('LICENSE', 'docs/LICENSE')).toBe(true);
  });

  it('normalizes backslashes on Windows-style paths', () => {
    expect(codeownerMatches('src/a.ts', 'src\\a.ts')).toBe(true);
  });
});

import { describe, it, expect } from 'vitest';
import { _internals } from './change-impact.js';

const { rangesContainLine, normalize } = _internals;

describe('rangesContainLine', () => {
  it('returns false on empty ranges', () => {
    expect(rangesContainLine([], 10)).toBe(false);
  });

  it('matches within a single range', () => {
    expect(rangesContainLine([{ start: 10, end: 20 }], 15)).toBe(true);
  });

  it('matches at inclusive boundaries', () => {
    expect(rangesContainLine([{ start: 10, end: 20 }], 10)).toBe(true);
    expect(rangesContainLine([{ start: 10, end: 20 }], 20)).toBe(true);
  });

  it('rejects lines outside any range', () => {
    expect(rangesContainLine([{ start: 10, end: 20 }], 9)).toBe(false);
    expect(rangesContainLine([{ start: 10, end: 20 }], 21)).toBe(false);
  });

  it('matches when any of multiple ranges covers the line', () => {
    const ranges = [
      { start: 10, end: 20 },
      { start: 40, end: 50 },
      { start: 80, end: 100 },
    ];
    expect(rangesContainLine(ranges, 45)).toBe(true);
    expect(rangesContainLine(ranges, 90)).toBe(true);
    expect(rangesContainLine(ranges, 60)).toBe(false);
  });
});

describe('normalize', () => {
  it('normalizes backslashes to forward slashes', () => {
    expect(normalize('src\\auth\\login.ts')).toBe('src/auth/login.ts');
  });

  it('strips leading ./', () => {
    expect(normalize('./src/foo.ts')).toBe('src/foo.ts');
  });

  it('leaves already-normalized paths alone', () => {
    expect(normalize('src/foo.ts')).toBe('src/foo.ts');
  });

  it('handles empty string', () => {
    expect(normalize('')).toBe('');
  });

  it('only strips leading ./, not mid-path .', () => {
    expect(normalize('./a/./b.ts')).toBe('a/./b.ts');
  });
});

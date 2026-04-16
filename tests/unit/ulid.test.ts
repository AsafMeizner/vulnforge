import { describe, it, expect } from 'vitest';
import { ulid, ulidTime, isUlid } from '../../server/utils/ulid';

describe('ulid', () => {
  it('produces 26-char Crockford base32', () => {
    const id = ulid();
    expect(id).toHaveLength(26);
    expect(id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it('preserves monotonic order within the same millisecond', () => {
    const now = Date.now();
    const ids = Array.from({ length: 20 }, () => ulid(now));
    const sorted = [...ids].sort();
    expect(ids).toEqual(sorted);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('preserves chronological order across milliseconds', () => {
    const a = ulid(1_000_000);
    const b = ulid(2_000_000);
    const c = ulid(3_000_000);
    expect(a < b).toBe(true);
    expect(b < c).toBe(true);
  });

  it('ulidTime round-trips the embedded timestamp', () => {
    const t = 1_700_000_000_000;
    const id = ulid(t);
    expect(ulidTime(id)).toBe(t);
  });

  it('ulidTime returns NaN for malformed input', () => {
    expect(ulidTime('')).toBeNaN();
    expect(ulidTime('not-a-ulid')).toBeNaN();
  });

  it('isUlid accepts valid ULIDs, rejects others', () => {
    expect(isUlid(ulid())).toBe(true);
    expect(isUlid('short')).toBe(false);
    expect(isUlid(null)).toBe(false);
    expect(isUlid(12345)).toBe(false);
  });

  it('rejects timestamps exceeding 48 bits', () => {
    expect(() => ulid(Number.MAX_SAFE_INTEGER)).toThrow(/48 bits/);
  });
});

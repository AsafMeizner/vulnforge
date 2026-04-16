import { describe, it, expect } from 'vitest';
import {
  mintRefreshToken,
  mintDeviceId,
  hashRefreshToken,
  verifyRefreshToken,
  evaluateRefreshRow,
  REFRESH_TTL_MS,
  type RefreshTokenRow,
} from '../../server/auth/refresh';

describe('mintRefreshToken', () => {
  it('produces a reasonably-sized random token with future expiry', () => {
    const { raw, expires_at } = mintRefreshToken();
    expect(typeof raw).toBe('string');
    expect(raw.length).toBeGreaterThanOrEqual(40);
    expect(expires_at).toBeGreaterThan(Date.now());
    expect(expires_at - Date.now()).toBeLessThanOrEqual(REFRESH_TTL_MS + 1000);
  });

  it('mints unique tokens', () => {
    const tokens = new Set(Array.from({ length: 50 }, () => mintRefreshToken().raw));
    expect(tokens.size).toBe(50);
  });
});

describe('mintDeviceId', () => {
  it('returns a ULID', () => {
    const id = mintDeviceId();
    expect(id).toHaveLength(26);
  });
});

describe('hashRefreshToken + verifyRefreshToken', () => {
  it('verifies good raw', async () => {
    const { raw } = mintRefreshToken();
    const hash = await hashRefreshToken(raw);
    expect(await verifyRefreshToken(raw, hash)).toBe(true);
  });

  it('rejects wrong raw', async () => {
    const a = await hashRefreshToken('aaaa');
    expect(await verifyRefreshToken('bbbb', a)).toBe(false);
  });

  it('rejects empty inputs', async () => {
    expect(await verifyRefreshToken('', 'whatever')).toBe(false);
    expect(await verifyRefreshToken('x', '')).toBe(false);
  });
});

describe('evaluateRefreshRow', () => {
  const ok: RefreshTokenRow = {
    user_id: 1,
    token_hash: 'x',
    device_id: 'd',
    device_name: '',
    expires_at: Date.now() + 60_000,
    revoked: 0,
    created_at: 0,
    last_used_at: null,
  };

  it('returns null (ok) for healthy row', () => {
    expect(evaluateRefreshRow(ok)).toBeNull();
  });

  it('reports not-found for null', () => {
    expect(evaluateRefreshRow(null)).toBe('not-found');
  });

  it('reports revoked', () => {
    expect(evaluateRefreshRow({ ...ok, revoked: 1 })).toBe('revoked');
  });

  it('reports expired', () => {
    expect(evaluateRefreshRow({ ...ok, expires_at: Date.now() - 1 })).toBe('expired');
  });
});

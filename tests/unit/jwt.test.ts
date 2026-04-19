import { describe, it, expect, beforeAll } from 'vitest';
import { signAccessToken, verifyAccessToken, setJwtSecret, JWT_CONFIG } from '../../server/auth/jwt';
import jwt from 'jsonwebtoken';

beforeAll(() => {
  setJwtSecret('unit-test-jwt-secret-exceeding-32-char-minimum-ok');
});

describe('signAccessToken + verifyAccessToken', () => {
  it('round-trips claims', () => {
    const token = signAccessToken({ sub: 42, role: 'admin', device_id: 'dev-abc' });
    const result = verifyAccessToken(token);
    expect(result.ok).toBe(true);
    expect(result.claims?.sub).toBe(42);
    expect(result.claims?.role).toBe('admin');
    expect(result.claims?.device_id).toBe('dev-abc');
  });

  it('reports invalid-signature on tampered token', () => {
    const token = signAccessToken({ sub: 1, role: 'viewer', device_id: 'x' });
    // Flip last char of signature
    const tampered = token.slice(0, -1) + (token.slice(-1) === 'A' ? 'B' : 'A');
    const result = verifyAccessToken(tampered);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid-signature');
  });

  it('reports malformed on garbage input', () => {
    const result = verifyAccessToken('not-a-token');
    expect(result.ok).toBe(false);
    expect(['invalid-signature', 'malformed', 'unknown']).toContain(result.error);
  });

  it('reports expired when token past exp', () => {
    // Manually sign a token with iat+exp in the past using same secret
    const token = jwt.sign(
      { sub: 1, role: 'admin', device_id: 'x' },
      'unit-test-jwt-secret-exceeding-32-char-minimum-ok',
      { algorithm: 'HS256', expiresIn: '-1s' },
    );
    const result = verifyAccessToken(token);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('expired');
  });

  it('exposes access-token TTL config', () => {
    expect(JWT_CONFIG.ACCESS_TOKEN_TTL_SECONDS).toBe(15 * 60);
  });

  it('rejects a token signed for a different issuer', () => {
    // Same secret, but "iss" claim pointing at a different issuer name.
    // This is the token-confusion attack: a future use-case that reuses
    // the JWT secret (invite links, refresh wrap) must not be usable as
    // a session token.
    const token = jwt.sign(
      { sub: 1, role: 'admin', device_id: 'x' },
      'unit-test-jwt-secret-exceeding-32-char-minimum-ok',
      { algorithm: 'HS256', expiresIn: '15m', issuer: 'some-other-app', audience: 'vulnforge-api' },
    );
    const result = verifyAccessToken(token);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid-signature');
  });

  it('rejects a token signed for a different audience', () => {
    const token = jwt.sign(
      { sub: 1, role: 'admin', device_id: 'x' },
      'unit-test-jwt-secret-exceeding-32-char-minimum-ok',
      { algorithm: 'HS256', expiresIn: '15m', issuer: 'vulnforge', audience: 'some-other-api' },
    );
    const result = verifyAccessToken(token);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid-signature');
  });
});

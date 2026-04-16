import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

const tmpDir = mkdtempSync(path.join(tmpdir(), 'vulnforge-test-'));
process.env.VULNFORGE_DB_PATH = path.join(tmpDir, 'auth-flow.db');
process.env.VULNFORGE_JWT_SECRET = 'integration-test-secret-at-least-32-chars-ok-now';

let initDb: any, createUser: any, getUserById: any;
let insertRefreshToken: any, getRefreshTokensForDevice: any, revokeAllRefreshTokensForDevice: any;
let hashPassword: any, verifyPasswordAny: any;
let signAccessToken: any, verifyAccessToken: any, setJwtSecret: any;
let mintRefreshToken: any, mintDeviceId: any, hashRefreshToken: any, verifyRefreshToken: any, evaluateRefreshRow: any;

beforeAll(async () => {
  const db = await import('../../server/db');
  const pw = await import('../../server/auth/passwords');
  const jwtMod = await import('../../server/auth/jwt');
  const ref = await import('../../server/auth/refresh');
  initDb = db.initDb;
  createUser = db.createUser;
  getUserById = db.getUserById;
  insertRefreshToken = db.insertRefreshToken;
  getRefreshTokensForDevice = db.getRefreshTokensForDevice;
  revokeAllRefreshTokensForDevice = db.revokeAllRefreshTokensForDevice;
  hashPassword = pw.hashPassword;
  verifyPasswordAny = pw.verifyPasswordAny;
  signAccessToken = jwtMod.signAccessToken;
  verifyAccessToken = jwtMod.verifyAccessToken;
  setJwtSecret = jwtMod.setJwtSecret;
  mintRefreshToken = ref.mintRefreshToken;
  mintDeviceId = ref.mintDeviceId;
  hashRefreshToken = ref.hashRefreshToken;
  verifyRefreshToken = ref.verifyRefreshToken;
  evaluateRefreshRow = ref.evaluateRefreshRow;

  setJwtSecret(process.env.VULNFORGE_JWT_SECRET!);
  await initDb();
});

afterAll(() => {
  try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('auth flow integration', () => {
  let userId: number;
  let deviceId: string;
  let accessToken: string;
  let refreshRaw: string;
  let refreshRowId: number;

  it('creates a user with bcrypt hash', async () => {
    const hash = await hashPassword('integration-test-password');
    userId = createUser({
      username: 'alice@test.local',
      password_hash: hash,
      role: 'researcher',
      email: 'alice@test.local',
      display_name: 'Alice',
      active: 1,
    });
    expect(userId).toBeGreaterThan(0);
    const user = getUserById(userId);
    expect(user?.username).toBe('alice@test.local');
    expect(user?.role).toBe('researcher');
  });

  it('login step: verify password + mint tokens + persist refresh row', async () => {
    const user = getUserById(userId);
    const v = await verifyPasswordAny('integration-test-password', user.password_hash);
    expect(v.ok).toBe(true);

    deviceId = mintDeviceId();
    const minted = mintRefreshToken();
    refreshRaw = minted.raw;
    const token_hash = await hashRefreshToken(refreshRaw);
    refreshRowId = insertRefreshToken({
      user_id: userId,
      token_hash,
      device_id: deviceId,
      device_name: 'vitest',
      expires_at: minted.expires_at,
      revoked: 0,
      created_at: Date.now(),
      last_used_at: null,
    });

    accessToken = signAccessToken({ sub: userId, role: 'researcher', device_id: deviceId });
    const claims = verifyAccessToken(accessToken);
    expect(claims.ok).toBe(true);
    expect(claims.claims?.sub).toBe(userId);
    expect(claims.claims?.device_id).toBe(deviceId);
  });

  it('rejects wrong password on same user', async () => {
    const user = getUserById(userId);
    const v = await verifyPasswordAny('wrong-password', user.password_hash);
    expect(v.ok).toBe(false);
  });

  it('refresh token resolves to an ok row', async () => {
    const rows = getRefreshTokensForDevice(deviceId);
    expect(rows.length).toBeGreaterThan(0);
    let matched = null;
    for (const r of rows) {
      if (await verifyRefreshToken(refreshRaw, r.token_hash)) { matched = r; break; }
    }
    expect(matched).toBeTruthy();
    expect(evaluateRefreshRow(matched)).toBeNull();
  });

  it('logout revokes all refresh tokens for the device', () => {
    revokeAllRefreshTokensForDevice(deviceId);
    const rows = getRefreshTokensForDevice(deviceId);
    // getRefreshTokensForDevice filters revoked=0, so after revoke it returns empty
    expect(rows.length).toBe(0);
  });

  it('replayed refresh against revoked device returns nothing', async () => {
    // Even the raw token that was valid pre-logout should no longer match
    // because rows returned by getRefreshTokensForDevice are filtered.
    const rows = getRefreshTokensForDevice(deviceId);
    expect(rows.length).toBe(0);
  });

  it('rotate simulation: new login → new device_id → new token pair', async () => {
    const newDevice = mintDeviceId();
    expect(newDevice).not.toBe(deviceId);
    const minted = mintRefreshToken();
    expect(minted.raw).not.toBe(refreshRaw);
    const newAccess = signAccessToken({ sub: userId, role: 'researcher', device_id: newDevice });
    expect(newAccess).not.toBe(accessToken);
    const claims = verifyAccessToken(newAccess);
    expect(claims.ok).toBe(true);
    expect(claims.claims?.device_id).toBe(newDevice);
  });
});

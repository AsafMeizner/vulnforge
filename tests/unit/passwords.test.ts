import { describe, it, expect } from 'vitest';
import {
  hashPassword,
  verifyPassword,
  isBcryptHash,
  isScryptHash,
  verifyPasswordAny,
} from '../../server/auth/passwords';
import { scrypt, randomBytes } from 'crypto';
import { promisify } from 'util';

const scryptAsync = promisify(scrypt);

async function makeLegacyScrypt(plain: string): Promise<string> {
  const salt = randomBytes(32).toString('hex');
  const key = (await scryptAsync(plain, salt, 64)) as Buffer;
  return `${salt}:${key.toString('hex')}`;
}

describe('bcrypt hash + verify', () => {
  it('round-trips a correct password', async () => {
    const hash = await hashPassword('correct-horse-battery-staple');
    expect(hash).toMatch(/^\$2[aby]\$\d{2}\$/);
    expect(await verifyPassword('correct-horse-battery-staple', hash)).toBe(true);
  });

  it('rejects wrong password', async () => {
    const hash = await hashPassword('correct-pass-long');
    expect(await verifyPassword('wrong-pass-long', hash)).toBe(false);
  });

  it('refuses empty or too-short passwords at hash time', async () => {
    await expect(hashPassword('')).rejects.toThrow();
    await expect(hashPassword('short')).rejects.toThrow();
  });

  it('verifyPassword safely returns false for non-bcrypt hashes', async () => {
    expect(await verifyPassword('x', 'plain-not-a-hash')).toBe(false);
    expect(await verifyPassword('x', '')).toBe(false);
  });
});

describe('isBcryptHash / isScryptHash', () => {
  it('identifies bcrypt hashes', async () => {
    const h = await hashPassword('long-enough-password');
    expect(isBcryptHash(h)).toBe(true);
    expect(isBcryptHash('plain')).toBe(false);
    expect(isBcryptHash(null)).toBe(false);
  });

  it('identifies scrypt legacy format', async () => {
    const legacy = await makeLegacyScrypt('legacy-pass');
    expect(isScryptHash(legacy)).toBe(true);
    expect(isScryptHash('not:hex')).toBe(false);
    expect(isScryptHash('noseparator')).toBe(false);
  });
});

describe('verifyPasswordAny dual-format', () => {
  it('verifies bcrypt with needs_upgrade=false', async () => {
    const h = await hashPassword('bcrypt-pass-long');
    const r = await verifyPasswordAny('bcrypt-pass-long', h);
    expect(r.ok).toBe(true);
    expect(r.needs_upgrade).toBe(false);
  });

  it('verifies scrypt legacy with needs_upgrade=true', async () => {
    const legacy = await makeLegacyScrypt('scrypt-secret-long');
    const r = await verifyPasswordAny('scrypt-secret-long', legacy);
    expect(r.ok).toBe(true);
    expect(r.needs_upgrade).toBe(true);
  });

  it('rejects wrong password on legacy format', async () => {
    const legacy = await makeLegacyScrypt('correct-scrypt');
    const r = await verifyPasswordAny('wrong-scrypt', legacy);
    expect(r.ok).toBe(false);
    expect(r.needs_upgrade).toBe(false);
  });

  it('returns ok=false, needs_upgrade=false for unknown formats', async () => {
    const r = await verifyPasswordAny('anything', 'garbage-not-a-hash');
    expect(r.ok).toBe(false);
    expect(r.needs_upgrade).toBe(false);
  });
});

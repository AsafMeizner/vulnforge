/**
 * Password hashing — bcrypt with cost 12.
 *
 * Cost 12 is a sensible 2026 default: ~300ms to hash on modern hardware,
 * making brute-force attack by an adversary with a leaked hash dump
 * computationally prohibitive while staying fast enough for interactive
 * login flow.
 *
 * We use bcryptjs (pure JS) not the native bcrypt binding to avoid
 * forcing node-gyp + platform-specific binaries for a cross-platform
 * desktop app. Performance difference is negligible for login-scale
 * traffic (a few hashes per second, not thousands).
 */
import bcrypt from 'bcryptjs';

const COST = 12;

export async function hashPassword(plain: string): Promise<string> {
  if (typeof plain !== 'string' || plain.length === 0) {
    throw new Error('hashPassword: empty password');
  }
  if (plain.length < 8) {
    throw new Error('hashPassword: password must be at least 8 chars');
  }
  return bcrypt.hash(plain, COST);
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  if (typeof plain !== 'string' || typeof hash !== 'string') return false;
  if (!hash.startsWith('$2')) return false; // not a bcrypt hash
  try {
    return await bcrypt.compare(plain, hash);
  } catch {
    return false;
  }
}

/** Cheap check — does a stored value look like a bcrypt hash? */
export function isBcryptHash(value: unknown): value is string {
  return typeof value === 'string' && /^\$2[aby]\$\d{2}\$/.test(value);
}

/** Looks like the legacy scrypt format `hex_salt:hex_hash` used by server/auth/auth.ts. */
export function isScryptHash(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parts = value.split(':');
  if (parts.length !== 2) return false;
  return /^[0-9a-f]+$/i.test(parts[0]) && /^[0-9a-f]+$/i.test(parts[1]);
}

/**
 * Unified verify — handles both bcrypt (new) and scrypt (legacy) hashes.
 * Used during the migration window so existing phase-14/15 users can
 * still log in via the new JWT session flow.
 *
 * Returns { ok, needs_upgrade } — if the stored hash is scrypt and verify
 * passed, caller should re-hash with bcrypt and persist.
 */
export async function verifyPasswordAny(
  plain: string,
  stored: string,
): Promise<{ ok: boolean; needs_upgrade: boolean }> {
  if (isBcryptHash(stored)) {
    return { ok: await verifyPassword(plain, stored), needs_upgrade: false };
  }
  if (isScryptHash(stored)) {
    // Delegate to legacy verifier without importing auth.ts to avoid cycles.
    const crypto = await import('crypto');
    const [salt, hash] = stored.split(':');
    const ok = await new Promise<boolean>((resolve) => {
      crypto.scrypt(plain, salt, 64, (err, derivedKey) => {
        if (err) { resolve(false); return; }
        resolve(derivedKey.toString('hex') === hash);
      });
    });
    return { ok, needs_upgrade: ok };
  }
  return { ok: false, needs_upgrade: false };
}

/**
 * At-rest encryption for sensitive columns (AI API keys, OIDC client
 * secrets, integration credentials).
 *
 * Addresses CR-08 / CR-09 / CR-10 from the security audit: secrets
 * were stored plaintext in SQLite so anyone who could read the DB
 * file (local compromise, backup leak, cloud-synced %APPDATA%)
 * harvested every provider key.
 *
 * Design:
 *  - AES-256-GCM. The industry default for authenticated encryption;
 *    built into Node's `crypto` module so no external deps.
 *  - Master key resolution order:
 *      1. VULNFORGE_DATA_KEY env var (64 hex chars, = 32 raw bytes).
 *         Required in server mode (NODE_ENV=production).
 *      2. <data dir>/master.key - auto-created on first boot, chmod
 *         600. Suitable for single-user desktop installs.
 *    Electron's `safeStorage` (Keychain/DPAPI/libsecret) hookup is
 *    intentionally deferred: it lives in the main process and our
 *    db.ts runs before we hand off. The file-on-disk approach works
 *    on every platform today; operators who want OS-keystore-backed
 *    keys set VULNFORGE_DATA_KEY and manage it themselves.
 *
 * Ciphertext format (string-form, so it round-trips through SQLite TEXT):
 *     "vf1:" + base64(12B iv || 16B tag || N-byte ciphertext)
 *
 * The `vf1:` prefix is how callers detect "is this already
 * encrypted?". It's also how the boot-time migration skips rows it
 * already processed. Future key-rotation schemes can bump to `vf2:`
 * etc. without breaking readers.
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'fs';
import path from 'path';

const PREFIX = 'vf1:';
const ALGO = 'aes-256-gcm';
const KEY_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;

let _masterKey: Buffer | null = null;

/**
 * Resolve the master key from env / filesystem. Cached after first
 * call. Throws if we're in server mode (NODE_ENV=production) and no
 * env-var key was provided - we never want to silently fall back to
 * a generated file-key on a public-facing deployment without letting
 * the operator know.
 */
function getMasterKey(): Buffer {
  if (_masterKey) return _masterKey;

  // 1. Env var - preferred for server deployments.
  const envKey = process.env.VULNFORGE_DATA_KEY;
  if (envKey && /^[0-9a-fA-F]{64}$/.test(envKey)) {
    _masterKey = Buffer.from(envKey, 'hex');
    return _masterKey;
  }
  if (envKey) {
    throw new Error(
      'VULNFORGE_DATA_KEY is set but not a 64-char hex string (32 raw bytes).',
    );
  }

  // 2. File - auto-generate on first boot for desktop/dev installs.
  const isProd = process.env.NODE_ENV === 'production'
    && process.env.VULNFORGE_MODE === 'server';
  if (isProd) {
    throw new Error(
      'Server-mode production requires VULNFORGE_DATA_KEY (hex-encoded 32 bytes). ' +
      'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
    );
  }

  const dataDir = process.env.VULNFORGE_DATA_DIR
    || path.join(process.cwd(), 'data');
  const keyFile = path.join(dataDir, 'master.key');
  if (existsSync(keyFile)) {
    const hex = readFileSync(keyFile, 'utf8').trim();
    if (/^[0-9a-fA-F]{64}$/.test(hex)) {
      _masterKey = Buffer.from(hex, 'hex');
      return _masterKey;
    }
    console.warn('[crypto] master.key exists but is not valid hex - regenerating');
  }

  mkdirSync(dataDir, { recursive: true });
  const fresh = randomBytes(KEY_LEN);
  writeFileSync(keyFile, fresh.toString('hex') + '\n', 'utf8');
  try { chmodSync(keyFile, 0o600); } catch { /* Windows ignores */ }
  console.log(`[crypto] generated new master.key at ${keyFile}`);
  _masterKey = fresh;
  return _masterKey;
}

/**
 * Test-only reset. Lets unit tests force a fresh key resolution.
 */
export function __resetMasterKeyCache(): void {
  _masterKey = null;
}

/**
 * Encrypt a plaintext string. Returns the `vf1:` marker string ready
 * to write to SQLite. Null / empty inputs pass through unchanged so
 * callers don't need to special-case "no secret set".
 */
export function encryptSecret(plaintext: string | null | undefined): string {
  if (plaintext === null || plaintext === undefined || plaintext === '') {
    return '';
  }
  if (isEncrypted(plaintext)) return plaintext;  // idempotent
  const key = getMasterKey();
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const packed = Buffer.concat([iv, tag, ct]);
  return PREFIX + packed.toString('base64');
}

/**
 * Decrypt a value read from storage. If the input doesn't start with
 * the marker it's assumed to be plaintext (legacy, pre-migration
 * rows) and returned verbatim. Empty / null inputs return ''.
 */
export function decryptSecret(stored: string | null | undefined): string {
  if (!stored) return '';
  if (!isEncrypted(stored)) return stored;  // legacy plaintext
  try {
    const key = getMasterKey();
    const packed = Buffer.from(stored.slice(PREFIX.length), 'base64');
    if (packed.length < IV_LEN + TAG_LEN) throw new Error('truncated ciphertext');
    const iv = packed.subarray(0, IV_LEN);
    const tag = packed.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ct = packed.subarray(IV_LEN + TAG_LEN);
    const decipher = createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString('utf8');
  } catch (err: any) {
    // Don't leak which part of the crypto path failed. The most
    // common cause is a master-key mismatch (operator rotated
    // VULNFORGE_DATA_KEY without running a re-encrypt migration).
    throw new Error('Failed to decrypt stored secret. The master key may have changed.');
  }
}

export function isEncrypted(value: string): boolean {
  return typeof value === 'string' && value.startsWith(PREFIX);
}

/**
 * Optional: derive a passphrase-protected wrapping key. Not wired in
 * by default - reserved for the "lock with a password" Settings
 * toggle. The master key stays on disk; the passphrase wraps THAT
 * key so losing the passphrase loses the data.
 */
export function deriveKeyFromPassphrase(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, KEY_LEN);
}

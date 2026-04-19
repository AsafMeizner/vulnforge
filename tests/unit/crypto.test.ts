/**
 * server/lib/crypto.ts unit tests.
 *
 * The audit flagged this as a "must-have direct unit test" module
 * because a regression in the envelope-encrypt path fails silently
 * (secrets encrypt OK, decrypt "works", just reads back as garbage)
 * and the idempotency check (vf1: prefix) is the only thing
 * between a re-run migration and double-encrypted unreadable rows.
 *
 * We exercise:
 *   - round-trip encrypt → decrypt returns the original plaintext
 *   - encrypt(encrypt(x)) is a no-op (idempotency)
 *   - decrypt() on a legacy plaintext string is passthrough
 *   - isEncrypted() prefix detection
 *   - tamper detection (flip a byte of ciphertext, decrypt throws)
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';

// The module reads VULNFORGE_DATA_KEY at first use. Force a fresh
// test key before importing so every test run is deterministic.
const ORIG_KEY = process.env.VULNFORGE_DATA_KEY;
// crypto.ts expects a 64-char hex string (32 raw bytes).
const TEST_KEY = randomBytes(32).toString('hex');

beforeAll(() => {
  process.env.VULNFORGE_DATA_KEY = TEST_KEY;
});

afterAll(() => {
  if (ORIG_KEY === undefined) delete process.env.VULNFORGE_DATA_KEY;
  else process.env.VULNFORGE_DATA_KEY = ORIG_KEY;
});

// Import AFTER env is set.
let crypto: typeof import('../../server/lib/crypto');
beforeAll(async () => {
  crypto = await import('../../server/lib/crypto');
});

describe('encryptSecret / decryptSecret roundtrip', () => {
  it('roundtrips ASCII', () => {
    const plain = 'sk-live-abcdef1234567890';
    const envelope = crypto.encryptSecret(plain);
    expect(envelope.startsWith('vf1:')).toBe(true);
    expect(crypto.decryptSecret(envelope)).toBe(plain);
  });

  it('roundtrips unicode + long payloads', () => {
    const plain = '🔐 token with emoji and a lot of bytes '.repeat(50);
    expect(crypto.decryptSecret(crypto.encryptSecret(plain))).toBe(plain);
  });

  it('roundtrips JSON blobs (integration config case)', () => {
    const plain = JSON.stringify({
      webhook_url: 'https://hooks.slack.com/services/T1/B2/xyz',
      key: 'abcd1234',
      token: 'secret-token',
    });
    expect(crypto.decryptSecret(crypto.encryptSecret(plain))).toBe(plain);
  });

  it('every call emits a different ciphertext (fresh IV)', () => {
    const plain = 'same-input';
    const a = crypto.encryptSecret(plain);
    const b = crypto.encryptSecret(plain);
    expect(a).not.toBe(b);
    expect(crypto.decryptSecret(a)).toBe(plain);
    expect(crypto.decryptSecret(b)).toBe(plain);
  });
});

describe('isEncrypted prefix detection', () => {
  it('recognises vf1: envelopes', () => {
    const env = crypto.encryptSecret('payload');
    expect(crypto.isEncrypted(env)).toBe(true);
  });

  it('returns false for plaintext', () => {
    expect(crypto.isEncrypted('just a plain api key')).toBe(false);
    expect(crypto.isEncrypted('')).toBe(false);
  });

  it('returns false for non-string input', () => {
    // @ts-expect-error - testing non-string input guard
    expect(crypto.isEncrypted(null)).toBe(false);
    // @ts-expect-error
    expect(crypto.isEncrypted(undefined)).toBe(false);
  });
});

describe('idempotency (re-encrypting an envelope is a no-op)', () => {
  it('encryptSecret(encryptSecret(x)) === encryptSecret(x)', () => {
    const first = crypto.encryptSecret('plaintext');
    const second = crypto.encryptSecret(first);
    expect(second).toBe(first);
  });
});

describe('decryptSecret passthrough on unprefixed legacy values', () => {
  it('returns the input unchanged if it has no vf1: prefix', () => {
    // Legacy rows that haven't been migrated yet still come out
    // readable so the app keeps working during a progressive
    // migration.
    expect(crypto.decryptSecret('legacy-plaintext')).toBe('legacy-plaintext');
  });
});

describe('tamper detection', () => {
  it('throws on a modified ciphertext body', () => {
    const envelope = crypto.encryptSecret('original');
    // Flip a byte in the middle of the base64 payload.
    const [prefix, body] = envelope.split(':', 2);
    const mid = Math.floor(body.length / 2);
    const flipped = body[mid] === 'A' ? 'B' : 'A';
    const tampered = `${prefix}:${body.slice(0, mid)}${flipped}${body.slice(mid + 1)}`;
    expect(() => crypto.decryptSecret(tampered)).toThrow();
  });

  it('throws on truncated ciphertext (shorter than iv + tag)', () => {
    expect(() => crypto.decryptSecret('vf1:AAAA')).toThrow();
  });
});

/**
 * ULID - Universally Unique Lexicographically Sortable Identifier.
 *
 * 26-char Crockford Base32 string. First 10 chars encode a 48-bit ms-precision
 * timestamp (sortable by generation time), last 16 chars are cryptographically
 * random.
 *
 * Monotonic variant: if called twice in the same ms, increments the random
 * portion instead of regenerating, preserving strict ordering.
 *
 * Used as `sync_id` column on every syncable row so two offline desktops
 * never mint colliding IDs.
 */
import { randomBytes } from 'crypto';

const ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford - no I, L, O, U
const ENCODING_LEN = ENCODING.length;
const TIME_LEN = 10;
const RANDOM_LEN = 16;

let lastTime = 0;
let lastRandom: number[] = new Array(RANDOM_LEN).fill(0);

function encodeTime(now: number): string {
  if (now > 281474976710655) throw new Error('ULID: timestamp exceeds 48 bits');
  const chars: string[] = new Array(TIME_LEN);
  let t = now;
  for (let i = TIME_LEN - 1; i >= 0; i--) {
    chars[i] = ENCODING[t % ENCODING_LEN];
    t = Math.floor(t / ENCODING_LEN);
  }
  return chars.join('');
}

function incrementBase32(arr: number[]): number[] {
  const next = arr.slice();
  for (let i = RANDOM_LEN - 1; i >= 0; i--) {
    if (next[i] < ENCODING_LEN - 1) {
      next[i]++;
      return next;
    }
    next[i] = 0;
  }
  throw new Error('ULID: monotonic overflow within same ms');
}

function freshRandom(): number[] {
  const buf = randomBytes(RANDOM_LEN);
  const out = new Array(RANDOM_LEN);
  for (let i = 0; i < RANDOM_LEN; i++) out[i] = buf[i] % ENCODING_LEN;
  return out;
}

/** Mint a new monotonic ULID. Safe across rapid successive calls. */
export function ulid(now?: number): string {
  const t = now ?? Date.now();
  let randomPart: number[];
  if (t === lastTime) {
    randomPart = incrementBase32(lastRandom);
  } else {
    randomPart = freshRandom();
  }
  lastTime = t;
  lastRandom = randomPart;
  const randomChars = randomPart.map(n => ENCODING[n]).join('');
  return encodeTime(t) + randomChars;
}

/** Extract the ms-precision timestamp from a ULID. Returns NaN if malformed. */
export function ulidTime(id: string): number {
  if (typeof id !== 'string' || id.length !== TIME_LEN + RANDOM_LEN) return NaN;
  let t = 0;
  for (let i = 0; i < TIME_LEN; i++) {
    const v = ENCODING.indexOf(id[i].toUpperCase());
    if (v === -1) return NaN;
    t = t * ENCODING_LEN + v;
  }
  return t;
}

/** Validate ULID shape without extracting. */
export function isUlid(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== TIME_LEN + RANDOM_LEN) return false;
  for (let i = 0; i < value.length; i++) {
    if (ENCODING.indexOf(value[i].toUpperCase()) === -1) return false;
  }
  return true;
}

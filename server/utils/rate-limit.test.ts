import { describe, it, expect } from 'vitest';
import { createMemoryStore } from './rate-limit.js';

describe('MemoryStore', () => {
  it('counts hits within a window', () => {
    const store = createMemoryStore();
    expect(store.hit('a', 1000)).toBe(1);
    expect(store.hit('a', 1000)).toBe(2);
    expect(store.hit('a', 1000)).toBe(3);
  });

  it('keeps counters separate per key', () => {
    const store = createMemoryStore();
    expect(store.hit('a', 1000)).toBe(1);
    expect(store.hit('b', 1000)).toBe(1);
    expect(store.hit('a', 1000)).toBe(2);
    expect(store.hit('b', 1000)).toBe(2);
  });

  it('prunes hits older than the window', async () => {
    const store = createMemoryStore();
    store.hit('a', 50);
    store.hit('a', 50);
    expect(store.hit('a', 50)).toBe(3);
    await new Promise((r) => setTimeout(r, 80));
    // Now old entries are outside the 50ms window
    expect(store.hit('a', 50)).toBe(1);
  });

  it('caps per-key history to bounded memory', () => {
    const store = createMemoryStore();
    // Pump 10_500 hits in a single window; internal cap is 10_000
    for (let i = 0; i < 10_500; i++) store.hit('a', 1_000_000);
    // Final count must not exceed the cap
    const last = store.hit('a', 1_000_000);
    expect(last).toBeLessThanOrEqual(10_001);
  });
});

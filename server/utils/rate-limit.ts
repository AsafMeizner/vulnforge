/**
 * Minimal in-memory rate-limit middleware for Express.
 *
 * No external dependency. Sliding window: each client is allowed at most
 * `max` requests per `windowMs`. Clients are keyed by `req.ip` unless
 * `keyFn` overrides.
 *
 * Use cases:
 *   - AI-workflow endpoints that call out to LLM providers and therefore
 *     cost real money per request.
 *   - Autonomous remediation endpoints that can mutate git repos.
 *
 * Not suitable for distributed deployments (each replica has its own
 * bucket). For those, bolt on a redis-backed limiter later - the
 * `RateLimitStore` abstraction below is the seam.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';

export interface RateLimitStore {
  /** Record a request for `key`; return the number of hits in the window. */
  hit(key: string, windowMs: number): number;
}

class MemoryStore implements RateLimitStore {
  private hits = new Map<string, number[]>();

  hit(key: string, windowMs: number): number {
    const now = Date.now();
    const cutoff = now - windowMs;
    let arr = this.hits.get(key);
    if (!arr) {
      arr = [];
      this.hits.set(key, arr);
    }
    // Prune timestamps older than window
    while (arr.length > 0 && arr[0] <= cutoff) arr.shift();
    arr.push(now);
    // Prevent unbounded growth per key
    if (arr.length > 10_000) arr.splice(0, arr.length - 10_000);
    return arr.length;
  }

  /** For tests: reset all counters. */
  reset(): void {
    this.hits.clear();
  }
}

export interface RateLimitOptions {
  /** Window in ms. Default 60_000 (1 minute). */
  windowMs?: number;
  /** Max requests per window. Default 30. */
  max?: number;
  /** How to key requests. Defaults to req.ip. */
  keyFn?: (req: Request) => string;
  /** Returned message on block. */
  message?: string;
  /** Shared store (e.g. for linking multiple limiters). */
  store?: RateLimitStore;
}

export function rateLimit(opts: RateLimitOptions = {}): RequestHandler {
  const windowMs = opts.windowMs ?? 60_000;
  const max = opts.max ?? 30;
  const keyFn = opts.keyFn ?? ((req: Request) => req.ip || 'anon');
  const message =
    opts.message ?? `Too many requests. Limit is ${max} per ${Math.round(windowMs / 1000)}s.`;
  const store = opts.store ?? new MemoryStore();

  return (req: Request, res: Response, next: NextFunction) => {
    const key = keyFn(req);
    const count = store.hit(key, windowMs);
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, max - count)));
    if (count > max) {
      res.setHeader('Retry-After', String(Math.ceil(windowMs / 1000)));
      res.status(429).json({ error: message, retry_after_ms: windowMs });
      return;
    }
    next();
  };
}

/** Helper for tests to get a fresh memory store. */
export function createMemoryStore(): MemoryStore {
  return new MemoryStore();
}

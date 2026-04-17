/**
 * Tests for J2 — self-consistency voting.
 *
 * `routeAI` is mocked via vi.mock(); each test controls how many votes are
 * cast and what each one returns.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock routeAI — must happen before importing the module under test.
vi.mock('../router.js', () => ({
  routeAI: vi.fn(),
}));

import { routeAI } from '../router.js';
import {
  verifyWithConsistency,
  aggregateVotes,
  averageResults,
  parseCvssScore,
  mode,
} from './self-consistency.js';
import type { VerifyVote } from './types.js';

const mockedRouteAI = routeAI as unknown as ReturnType<typeof vi.fn>;

function verifiedJSON(opts: {
  verified: boolean;
  cvss?: string;
  cwe?: string;
  severity?: string;
  tier?: string;
  confidence?: string;
}): string {
  return JSON.stringify({
    verified: opts.verified,
    confidence: opts.confidence || 'High',
    verification_reason: 'test',
    exploitability: 'High',
    data_flow_reachable: true,
    error_handling_present: false,
    enriched_title: 'Test vulnerability',
    enriched_description: 'desc',
    enriched_impact: 'impact',
    enriched_fix: 'fix',
    severity: opts.severity || 'High',
    cvss_score: opts.cvss || '7.5',
    cvss_vector: 'CVSS:3.1/AV:N/AC:L',
    cwe: opts.cwe || 'CWE-89',
    tier: opts.tier || 'A',
  });
}

describe('self-consistency helpers', () => {
  describe('parseCvssScore', () => {
    it('parses plain numbers', () => {
      expect(parseCvssScore('7.5')).toBe(7.5);
      expect(parseCvssScore('10')).toBe(10);
      expect(parseCvssScore('0')).toBe(0);
    });

    it('extracts score from a CVSS vector', () => {
      expect(parseCvssScore('CVSS:3.1/AV:N 7.5')).toBeCloseTo(3.1);
    });

    it('returns null for unparseable input', () => {
      expect(parseCvssScore('')).toBeNull();
      expect(parseCvssScore(undefined)).toBeNull();
      expect(parseCvssScore('abc')).toBeNull();
    });

    it('clamps out-of-range values to null', () => {
      expect(parseCvssScore('99')).toBeNull();
    });
  });

  describe('mode', () => {
    it('picks the most common value', () => {
      expect(mode(['High', 'High', 'Low'])).toBe('High');
    });
    it('returns null for empty input', () => {
      expect(mode<string>([])).toBeNull();
    });
    it('prefers first occurrence on tie', () => {
      expect(mode(['A', 'B'])).toBe('A');
    });
  });

  describe('averageResults', () => {
    it('averages CVSS scores from agreeing votes', () => {
      const result = averageResults([
        { verified: true, cvss_score: '7.0' } as any,
        { verified: true, cvss_score: '8.0' } as any,
        { verified: true, cvss_score: '6.0' } as any,
      ]);
      expect(result?.cvss_score).toBe('7.0');
    });

    it('takes mode severity', () => {
      const result = averageResults([
        { verified: true, severity: 'High' } as any,
        { verified: true, severity: 'High' } as any,
        { verified: true, severity: 'Medium' } as any,
      ]);
      expect(result?.severity).toBe('High');
    });

    it('picks longest non-empty string field', () => {
      const result = averageResults([
        { verified: true, enriched_description: 'short' } as any,
        { verified: true, enriched_description: 'a much longer description here' } as any,
      ]);
      expect(result?.enriched_description).toBe('a much longer description here');
    });

    it('returns single result when only one vote agrees', () => {
      const r = { verified: true, cvss_score: '9.1' } as any;
      expect(averageResults([r])).toBe(r);
    });

    it('returns null for empty input', () => {
      expect(averageResults([])).toBeNull();
    });
  });
});

describe('aggregateVotes', () => {
  it('returns no_parseable_votes when all votes failed to parse', () => {
    const votes: VerifyVote[] = [
      { temperature: 0.1, result: null, error: 'parse fail' },
      { temperature: 0.3, result: null, error: 'parse fail' },
    ];
    const agg = aggregateVotes(votes, 0.5, 2);
    expect(agg.verified).toBe(false);
    expect(agg.reason).toBe('no_parseable_votes');
    expect(agg.confidence).toBe(0);
  });

  it('calls majority_verified on 3-0 agreement', () => {
    const votes: VerifyVote[] = [
      { temperature: 0.1, result: { verified: true } as any },
      { temperature: 0.3, result: { verified: true } as any },
      { temperature: 0.5, result: { verified: true } as any },
    ];
    const agg = aggregateVotes(votes, 0.5, 3);
    expect(agg.verified).toBe(true);
    expect(agg.reason).toBe('majority_verified');
    expect(agg.confidence).toBeCloseTo(1.0);
  });

  it('calls majority_rejected on 3-0 no agreement', () => {
    const votes: VerifyVote[] = [
      { temperature: 0.1, result: { verified: false } as any },
      { temperature: 0.3, result: { verified: false } as any },
      { temperature: 0.5, result: { verified: false } as any },
    ];
    const agg = aggregateVotes(votes, 0.5, 3);
    expect(agg.verified).toBe(false);
    expect(agg.reason).toBe('majority_rejected');
    expect(agg.confidence).toBeCloseTo(1.0);
  });

  it('reports inconsistent on a 1-1 tie (N=2)', () => {
    const votes: VerifyVote[] = [
      { temperature: 0.1, result: { verified: true } as any },
      { temperature: 0.5, result: { verified: false } as any },
    ];
    const agg = aggregateVotes(votes, 0.5, 2);
    expect(agg.verified).toBe(false);
    expect(agg.reason).toBe('inconsistent');
    expect(agg.confidence).toBe(0.5);
  });

  it('reports inconsistent on 2-2 tie (N=4)', () => {
    const votes: VerifyVote[] = [
      { temperature: 0.1, result: { verified: true } as any },
      { temperature: 0.25, result: { verified: true } as any },
      { temperature: 0.4, result: { verified: false } as any },
      { temperature: 0.6, result: { verified: false } as any },
    ];
    const agg = aggregateVotes(votes, 0.5, 4);
    expect(agg.verified).toBe(false);
    expect(agg.reason).toBe('inconsistent');
    expect(agg.confidence).toBe(0.5);
  });

  it('confidence drops when one vote fails to parse', () => {
    const votes: VerifyVote[] = [
      { temperature: 0.1, result: { verified: true } as any },
      { temperature: 0.3, result: { verified: true } as any },
      { temperature: 0.5, result: null, error: 'fail' },
    ];
    const agg = aggregateVotes(votes, 0.5, 3);
    expect(agg.verified).toBe(true);
    expect(agg.confidence).toBeCloseTo(2 / 3);
  });

  it('respects threshold — rejects 1-of-3 majority if threshold=0.5', () => {
    // 1 yes, 0 no, 2 null → majorityCount=1, confidence=1/3 < 0.5
    const votes: VerifyVote[] = [
      { temperature: 0.1, result: { verified: true } as any },
      { temperature: 0.3, result: null },
      { temperature: 0.5, result: null },
    ];
    const agg = aggregateVotes(votes, 0.5, 3);
    expect(agg.verified).toBe(false);
    expect(agg.reason).toBe('inconsistent');
  });
});

describe('verifyWithConsistency (integration with mocked routeAI)', () => {
  beforeEach(() => {
    mockedRouteAI.mockReset();
  });

  it('calls routeAI exactly N times with varied temperatures', async () => {
    mockedRouteAI.mockResolvedValue({
      content: verifiedJSON({ verified: true }),
      model: 'mock',
      provider: 'mock',
    });
    await verifyWithConsistency(
      { title: 'SQL injection', file: 'a.py', code_snippet: 'bad()' },
      { n: 3, threshold: 0.5 },
    );
    expect(mockedRouteAI).toHaveBeenCalledTimes(3);
    const temps = mockedRouteAI.mock.calls.map(c => c[0].temperature);
    expect(temps).toEqual([0.1, 0.3, 0.5]);
  });

  it('returns majority verified when 3/3 agree', async () => {
    mockedRouteAI.mockResolvedValue({
      content: verifiedJSON({ verified: true, cvss: '7.5' }),
      model: 'mock',
      provider: 'mock',
    });
    const agg = await verifyWithConsistency(
      { title: 'XSS', code_snippet: 'echo $x' },
      { n: 3, threshold: 0.5 },
    );
    expect(agg.verified).toBe(true);
    expect(agg.reason).toBe('majority_verified');
    expect(agg.confidence).toBeCloseTo(1.0);
    expect(agg.result?.verified).toBe(true);
  });

  it('returns majority rejected when 3/3 reject', async () => {
    mockedRouteAI.mockResolvedValue({
      content: verifiedJSON({ verified: false }),
      model: 'mock',
      provider: 'mock',
    });
    const agg = await verifyWithConsistency(
      { title: 'suspect' },
      { n: 3, threshold: 0.5 },
    );
    expect(agg.verified).toBe(false);
    expect(agg.reason).toBe('majority_rejected');
  });

  it('averages CVSS scores across agreeing votes', async () => {
    mockedRouteAI
      .mockResolvedValueOnce({
        content: verifiedJSON({ verified: true, cvss: '6.0' }),
        model: 'm', provider: 'p',
      })
      .mockResolvedValueOnce({
        content: verifiedJSON({ verified: true, cvss: '8.0' }),
        model: 'm', provider: 'p',
      })
      .mockResolvedValueOnce({
        content: verifiedJSON({ verified: true, cvss: '7.0' }),
        model: 'm', provider: 'p',
      });
    const agg = await verifyWithConsistency(
      { title: 'foo' },
      { n: 3, threshold: 0.5 },
    );
    expect(agg.result?.cvss_score).toBe('7.0');
  });

  it('handles 2-1 split as majority with confidence 2/3', async () => {
    mockedRouteAI
      .mockResolvedValueOnce({
        content: verifiedJSON({ verified: true }),
        model: 'm', provider: 'p',
      })
      .mockResolvedValueOnce({
        content: verifiedJSON({ verified: true }),
        model: 'm', provider: 'p',
      })
      .mockResolvedValueOnce({
        content: verifiedJSON({ verified: false }),
        model: 'm', provider: 'p',
      });
    const agg = await verifyWithConsistency(
      { title: 'foo' },
      { n: 3, threshold: 0.5 },
    );
    expect(agg.verified).toBe(true);
    expect(agg.confidence).toBeCloseTo(2 / 3);
    expect(agg.reason).toBe('majority_verified');
  });

  it('marks inconsistent when 2-of-4 / 2-of-4 tie', async () => {
    // N=4 → temps [0.1, 0.25, 0.4, 0.6]
    mockedRouteAI
      .mockResolvedValueOnce({ content: verifiedJSON({ verified: true }), model: 'm', provider: 'p' })
      .mockResolvedValueOnce({ content: verifiedJSON({ verified: true }), model: 'm', provider: 'p' })
      .mockResolvedValueOnce({ content: verifiedJSON({ verified: false }), model: 'm', provider: 'p' })
      .mockResolvedValueOnce({ content: verifiedJSON({ verified: false }), model: 'm', provider: 'p' });
    const agg = await verifyWithConsistency(
      { title: 'foo' },
      { n: 4, threshold: 0.5 },
    );
    expect(agg.verified).toBe(false);
    expect(agg.reason).toBe('inconsistent');
  });

  it('gracefully records route errors as failed votes', async () => {
    mockedRouteAI
      .mockResolvedValueOnce({ content: verifiedJSON({ verified: true }), model: 'm', provider: 'p' })
      .mockRejectedValueOnce(new Error('provider down'))
      .mockResolvedValueOnce({ content: verifiedJSON({ verified: true }), model: 'm', provider: 'p' });
    const agg = await verifyWithConsistency(
      { title: 'foo' },
      { n: 3, threshold: 0.5 },
    );
    expect(agg.votes.length).toBe(3);
    expect(agg.votes[1].error).toContain('provider down');
    // 2 yes votes out of 3 → verified, confidence 2/3
    expect(agg.verified).toBe(true);
    expect(agg.confidence).toBeCloseTo(2 / 3);
  });
});

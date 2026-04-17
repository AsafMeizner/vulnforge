/**
 * Track G - Injection-class detectors barrel.
 *
 * Public entry: runInjectionDetectors(projectPath, languages, deps)
 * Aggregates all sub-detectors and returns a flat InjectionFinding[].
 */

import { detectDeserialization } from './deserialization.js';
import { detectNoSql } from './nosql.js';
import { detectSsti } from './ssti.js';
import { detectLdap } from './ldap.js';
import { detectXpath } from './xpath.js';
import { detectPromptInjection } from './prompt-injection.js';
import { detectPrototypePollution } from './prototype-pollution.js';
import type { InjectionFinding } from './types.js';

export type { InjectionFinding } from './types.js';

export async function runInjectionDetectors(
  projectPath: string,
  _languages: string[] = [],
  _deps: string[] = []
): Promise<InjectionFinding[]> {
  const findings: InjectionFinding[] = [];
  const safe = <T>(name: string, fn: () => T[]): T[] => {
    try {
      return fn();
    } catch (e) {
      console.warn(`[detectors/injection] ${name} errored:`, (e as Error).message);
      return [];
    }
  };

  findings.push(...safe('deserialization', () => detectDeserialization(projectPath)));
  findings.push(...safe('nosql', () => detectNoSql(projectPath)));
  findings.push(...safe('ssti', () => detectSsti(projectPath)));
  findings.push(...safe('ldap', () => detectLdap(projectPath)));
  findings.push(...safe('xpath', () => detectXpath(projectPath)));
  findings.push(...safe('prompt-injection', () => detectPromptInjection(projectPath)));
  findings.push(...safe('prototype-pollution', () => detectPrototypePollution(projectPath)));

  return findings;
}

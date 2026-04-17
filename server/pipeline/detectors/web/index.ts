/**
 * Track H - Web / API / IaC misconfig detectors barrel.
 *
 * Public entry: runWebDetectors(projectPath, languages, deps)
 */

import { runGraphQLDetector } from './graphql.js';
import { runCloudFormationDetector } from './iac-cloudformation.js';
import { runDockerDetector } from './iac-docker.js';
import { runKubernetesDetector } from './iac-kubernetes.js';
import { runTerraformDetector } from './iac-terraform.js';
import { runBolaDetector } from './authz-bola.js';
import { runRaceToctouDetector } from './race-toctou.js';
import { runMassAssignmentDetector } from './mass-assignment.js';
import { runCorsMisconfigDetector } from './cors-misconfig.js';
import type { WebFinding } from './types.js';

export type { WebFinding } from './types.js';

export async function runWebDetectors(
  projectPath: string,
  _languages: string[] = [],
  _deps: string[] = []
): Promise<WebFinding[]> {
  const findings: WebFinding[] = [];
  const safe = (name: string, fn: () => WebFinding[]): WebFinding[] => {
    try {
      return fn();
    } catch (e) {
      console.warn(`[detectors/web] ${name} errored:`, (e as Error).message);
      return [];
    }
  };

  findings.push(...safe('graphql', () => runGraphQLDetector(projectPath)));
  findings.push(...safe('iac-terraform', () => runTerraformDetector(projectPath)));
  findings.push(...safe('iac-cloudformation', () => runCloudFormationDetector(projectPath)));
  findings.push(...safe('iac-docker', () => runDockerDetector(projectPath)));
  findings.push(...safe('iac-kubernetes', () => runKubernetesDetector(projectPath)));
  findings.push(...safe('authz-bola', () => runBolaDetector(projectPath)));
  findings.push(...safe('race-toctou', () => runRaceToctouDetector(projectPath)));
  findings.push(...safe('mass-assignment', () => runMassAssignmentDetector(projectPath)));
  findings.push(...safe('cors-misconfig', () => runCorsMisconfigDetector(projectPath)));

  return findings;
}

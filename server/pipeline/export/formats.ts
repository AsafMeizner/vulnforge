/**
 * Export formats for findings: SARIF 2.1.0, CVE JSON 5.0, CycloneDX (partial).
 *
 * These are standardized formats that let VulnForge findings flow into
 * CI pipelines (SARIF), CVE Numbering Authorities (CVE JSON), and SBOM
 * toolchains (CycloneDX).
 */
import {
  getAllVulnerabilities,
  getProjectById,
  type Vulnerability,
} from '../../db.js';

// ── SARIF 2.1.0 ────────────────────────────────────────────────────────────

export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: 'none' | 'note' | 'warning' | 'error' };
  properties?: { tags?: string[]; precision?: string };
}

interface SarifResult {
  ruleId: string;
  level: 'none' | 'note' | 'warning' | 'error';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; endLine?: number };
    };
  }>;
}

function severityToSarifLevel(sev?: string): SarifResult['level'] {
  switch ((sev || '').toLowerCase()) {
    case 'critical':
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
    default: return 'none';
  }
}

/** Export all (or filtered) vulnerabilities as a SARIF 2.1.0 log. */
export function exportSarif(filters: { project_id?: number } = {}): SarifLog {
  const vulns = getAllVulnerabilities({ project_id: filters.project_id });

  // Build a rules catalog from unique CWEs
  const rulesMap = new Map<string, SarifRule>();
  for (const v of vulns) {
    const ruleId = v.cwe || `vulnforge-${v.tool_name || 'unknown'}`;
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: v.cwe ? `${v.cwe} weakness` : (v.tool_name || 'vulnforge'),
        shortDescription: { text: v.title || 'Vulnerability' },
        fullDescription: { text: v.description || v.title || 'Vulnerability finding' },
        defaultConfiguration: { level: severityToSarifLevel(v.severity) },
        properties: {
          tags: [v.severity || 'unknown', v.method || 'static'].filter(Boolean),
          precision: (typeof v.confidence === 'number' ? (v.confidence >= 0.8 ? 'very-high' : v.confidence >= 0.5 ? 'high' : 'medium') : 'medium'),
        },
      });
    }
  }

  const results: SarifResult[] = vulns.map(v => ({
    ruleId: v.cwe || `vulnforge-${v.tool_name || 'unknown'}`,
    level: severityToSarifLevel(v.severity),
    message: { text: v.description || v.title || '' },
    locations: v.file ? [{
      physicalLocation: {
        artifactLocation: { uri: v.file },
        region: {
          startLine: v.line_start || 1,
          endLine: v.line_end,
        },
      },
    }] : [],
  }));

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'VulnForge',
          version: '1.0.0',
          informationUri: 'https://vulnforge.local',
          rules: [...rulesMap.values()],
        },
      },
      results,
    }],
  };
}

// ── CVE JSON 5.0 ───────────────────────────────────────────────────────────

export interface CveRecord {
  dataType: 'CVE_RECORD';
  dataVersion: '5.0';
  cveMetadata: {
    cveId: string;
    assignerOrgId?: string;
    state: 'PUBLISHED' | 'REJECTED' | 'RESERVED';
  };
  containers: {
    cna: {
      title: string;
      descriptions: Array<{ lang: string; value: string }>;
      affected: Array<{
        vendor?: string;
        product?: string;
        versions?: Array<{ version: string; status: string }>;
      }>;
      references: Array<{ url: string; tags?: string[] }>;
      problemTypes?: Array<{ descriptions: Array<{ lang: string; description: string; cweId?: string }> }>;
      metrics?: Array<{
        cvssV3_1?: { baseScore: number; vectorString: string; baseSeverity: string };
      }>;
    };
  };
}

/** Export a single vulnerability as a CVE JSON 5.0 record. */
export function exportCveJson(vuln: Vulnerability): CveRecord {
  const project = vuln.project_id ? getProjectById(vuln.project_id) : null;
  const cvssBase = parseFloat(vuln.cvss || '0') || 0;
  const severity = cvssBase >= 9 ? 'CRITICAL' : cvssBase >= 7 ? 'HIGH' : cvssBase >= 4 ? 'MEDIUM' : 'LOW';

  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.0',
    cveMetadata: {
      cveId: 'CVE-PENDING',
      state: 'RESERVED',
    },
    containers: {
      cna: {
        title: vuln.title,
        descriptions: [{ lang: 'en', value: vuln.description || vuln.title }],
        affected: [{
          vendor: project?.name || 'unknown',
          product: project?.name || 'unknown',
          versions: [{ version: 'unknown', status: 'affected' }],
        }],
        references: [],
        problemTypes: vuln.cwe ? [{
          descriptions: [{
            lang: 'en',
            description: vuln.cwe,
            cweId: vuln.cwe,
          }],
        }] : undefined,
        metrics: cvssBase > 0 ? [{
          cvssV3_1: {
            baseScore: cvssBase,
            vectorString: vuln.cvss_vector || `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`,
            baseSeverity: severity,
          },
        }] : undefined,
      },
    },
  };
}

// ── Workspace backup (JSON) ────────────────────────────────────────────────

export async function exportWorkspace(): Promise<any> {
  const {
    getAllProjects,
    getAllVulnerabilities: getVulns,
    getNotes,
    getNotesProviders,
    getRuntimeJobs,
    getFuzzCrashes,
    getVendors,
    getDisclosures,
    getCveIntel,
    getAuditLog,
  } = await import('../../db.js');

  return {
    version: '1.0',
    exported_at: new Date().toISOString(),
    projects: getAllProjects(),
    vulnerabilities: getVulns({}),
    notes: getNotes({}),
    notes_providers: getNotesProviders(),
    runtime_jobs: getRuntimeJobs({}),
    fuzz_crashes: getFuzzCrashes({}),
    vendors: getVendors(),
    disclosures: getDisclosures(),
    cve_intel: getCveIntel({ limit: 1000 }),
    audit_log: getAuditLog({ limit: 500 }),
  };
}

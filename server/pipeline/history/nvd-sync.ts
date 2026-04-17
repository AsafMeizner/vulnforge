/**
 * NVD / GHSA Sync - fetch recent CVE data and cross-reference against
 * imported project dependencies.
 *
 * Uses the NVD 2.0 API (no API key required for low-rate queries).
 * Reference: https://nvd.nist.gov/developers/vulnerabilities
 */
import {
  getAllProjects,
  upsertCveIntel,
  getCveIntel,
  createCveProjectMatch,
  getCveProjectMatches,
  type Project,
} from '../../db.js';

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

export interface SyncResult {
  fetched: number;
  stored: number;
  errors: string[];
}

/** Fetch CVEs published in the last N days from NVD. Defaults to 30 days. */
export async function syncRecentCVEs(days = 30): Promise<SyncResult> {
  const result: SyncResult = { fetched: 0, stored: 0, errors: [] };
  const since = new Date(Date.now() - days * 86400 * 1000).toISOString();
  const pubStartDate = since.split('.')[0] + '.000';
  const pubEndDate = new Date().toISOString().split('.')[0] + '.000';

  const url = `${NVD_BASE}?pubStartDate=${encodeURIComponent(pubStartDate)}&pubEndDate=${encodeURIComponent(pubEndDate)}&resultsPerPage=200`;

  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'VulnForge/1.0' },
    });

    if (!res.ok) {
      result.errors.push(`NVD fetch failed: HTTP ${res.status}`);
      return result;
    }

    const data: any = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    result.fetched = vulnerabilities.length;

    for (const item of vulnerabilities) {
      try {
        const cve = item.cve;
        if (!cve?.id) continue;

        const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || '';

        // CVSS v3.1 preferred, fallback to v3.0, then v2
        const metrics = cve.metrics || {};
        const cvssNode = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0] || metrics.cvssMetricV2?.[0];
        const cvssData = cvssNode?.cvssData || {};
        const severity = cvssData.baseSeverity || cvssNode?.baseSeverity || 'UNKNOWN';
        const score = cvssData.baseScore;

        // Affected products: CPE match criteria
        const configs = cve.configurations || [];
        const products: string[] = [];
        for (const config of configs) {
          for (const node of config.nodes || []) {
            for (const match of node.cpeMatch || []) {
              if (match.criteria) products.push(match.criteria);
            }
          }
        }

        const references = (cve.references || []).map((r: any) => r.url).slice(0, 10);

        upsertCveIntel({
          cve_id: cve.id,
          published: cve.published,
          modified: cve.lastModified,
          severity,
          cvss_score: score,
          description: description.slice(0, 2000),
          affected_products: JSON.stringify(products.slice(0, 20)),
          cve_references: JSON.stringify(references),
        });
        result.stored++;
      } catch (err: any) {
        result.errors.push(`Failed to parse CVE: ${err.message}`);
      }
    }
  } catch (err: any) {
    result.errors.push(`Network error: ${err.message}`);
  }

  return result;
}

/**
 * Match CVEs against a project's dependencies.
 * The projects table stores a JSON `dependencies` column from the git.ts
 * extractor. Each dependency has an ecosystem (npm, pypi, cargo, go, maven, gem)
 * and a list of packages. We match by package name substring.
 */
export function matchProjectDependencies(project: Project): number {
  if (!project.id || !(project as any).dependencies) return 0;

  let deps: any[];
  try {
    deps = JSON.parse((project as any).dependencies);
  } catch {
    return 0;
  }

  const cves = getCveIntel({ limit: 500 });
  const existingMatches = getCveProjectMatches({ project_id: project.id });
  const existingKey = new Set(existingMatches.map(m => `${m.cve_id}:${m.dependency_name}`));

  let newMatches = 0;

  for (const depGroup of deps) {
    const ecosystem = depGroup.ecosystem;
    const packages = depGroup.packages || [];

    for (const pkg of packages) {
      const pkgName = pkg.name;
      if (!pkgName || pkgName.length < 3) continue;

      for (const cve of cves) {
        const products = (() => { try { return JSON.parse(cve.affected_products || '[]'); } catch { return []; } })();
        if (!Array.isArray(products)) continue;

        // CPE format: cpe:2.3:a:vendor:product:version:...
        const matches = products.some((cpe: string) => {
          if (typeof cpe !== 'string') return false;
          const parts = cpe.toLowerCase().split(':');
          // parts[4] is product
          return parts[4] && parts[4] === pkgName.toLowerCase();
        });

        if (matches) {
          const key = `${cve.cve_id}:${pkgName}`;
          if (existingKey.has(key)) continue;
          existingKey.add(key);

          createCveProjectMatch({
            cve_id: cve.cve_id,
            project_id: project.id,
            match_reason: 'dependency',
            dependency_name: pkgName,
            dependency_version: pkg.version || 'unknown',
            confidence: 0.7,
          });
          newMatches++;
        }
      }
    }
  }

  return newMatches;
}

/** Match dependencies for ALL projects. Used as a scheduled sync. */
export function matchAllProjects(): Record<string, number> {
  const projects = getAllProjects();
  const results: Record<string, number> = {};
  for (const p of projects) {
    try {
      const count = matchProjectDependencies(p);
      if (count > 0) results[p.name] = count;
    } catch (err: any) {
      console.warn(`[NVD Sync] matchProjectDependencies(${p.name}) failed: ${err.message}`);
    }
  }
  return results;
}

/** Combined sync: fetch NVD + match against all projects. */
export async function fullSync(days = 30): Promise<{ fetch: SyncResult; matches: Record<string, number> }> {
  const fetch = await syncRecentCVEs(days);
  const matches = matchAllProjects();
  return { fetch, matches };
}

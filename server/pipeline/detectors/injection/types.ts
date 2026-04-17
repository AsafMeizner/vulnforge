// Shared types for injection detectors.
//
// `InjectionFinding` is the common shape every sub-detector emits. It is a
// superset of the DB `ScanFinding` fields (see server/db.ts) so the
// integrator can map straight into the scan findings table, but it adds
// the taint-centric fields `sink_type` and `source_confidence`.

export type InjectionSubcategory =
  | 'ssti'
  | 'deser'
  | 'nosql'
  | 'ldap'
  | 'xpath'
  | 'prompt'
  | 'proto';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type SourceConfidence = 'definite' | 'likely' | 'possible';

export interface InjectionFinding {
  /** Always `'injection'` for this track. */
  category: 'injection';
  /** Which sub-detector produced the finding. */
  subcategory: InjectionSubcategory;
  /** One-sentence summary. Ends up as the ScanFinding title. */
  title: string;
  /** Human severity label; severity ladder follows ScanFinding convention. */
  severity: Severity;
  /** Absolute path (or project-relative forward-slash path) to the file. */
  file: string;
  /** 1-based source line number of the sink, if known. */
  line_start?: number;
  /** What kind of sink was hit (e.g. a deserializer call, template render). */
  sink_type: string;
  /**
   * How confident we are that tainted (attacker-controlled) data reaches
   * the sink:
   *  - 'definite'  — sink receives a named variable we traced to a well-known source
   *  - 'likely'    — sink called in a function that reads req/body/query/etc
   *  - 'possible'  — sink present, no obvious sanitizer, but source not confirmed
   */
  source_confidence: SourceConfidence;
  /** CWE identifier when applicable (e.g. 'CWE-94', 'CWE-502'). */
  cwe?: string;
  /** Short code-line evidence shown in the UI. */
  evidence: string;
  /**
   * Overall confidence in the finding itself (detector quality, not
   * taint-source quality). Loose parallel to ScanFinding.confidence.
   */
  confidence: 'high' | 'medium' | 'low';
  /** Free-form description shown in report body. */
  description?: string;
  /** Stable ID for deterministic dedup + chain referencing. */
  id?: string;
}

/** Optional extra context passed to runInjectionDetectors. */
export interface DetectorDeps {
  /** Declared dependency names (from package.json / requirements.txt / etc). */
  dependencies?: string[];
  /** Map of dependency name to version string (e.g. "lodash": "4.17.15"). */
  dependencyVersions?: Record<string, string>;
  /** Cap on number of files per language. Defaults to 4000. */
  maxFiles?: number;
}

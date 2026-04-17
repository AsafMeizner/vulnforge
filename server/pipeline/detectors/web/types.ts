/**
 * Shared types for the Web / API / IaC misconfig detectors.
 *
 * WebFinding intentionally does NOT import the DB `ScanFinding` type — these
 * detectors emit a lightweight, normalised shape that the orchestrator maps
 * into DB rows. Fields mirror what the integrator will need to persist.
 */

export type FindingCategory = 'web' | 'iac' | 'authz' | 'api';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type Confidence = 'High' | 'Medium' | 'Low';

/**
 * Canonical finding shape returned by every web/iac/authz/api detector.
 *
 * `subcategory` is the detector sub-class (e.g. 'terraform', 'graphql',
 * 'bola', 'cors'). It is stable across runs and used by the chain-detector
 * integration.
 */
export interface WebFinding {
  category: FindingCategory;
  subcategory: string;

  title: string;
  severity: Severity;
  confidence: Confidence;

  /** Path relative to the project root. */
  file: string;
  line_start?: number;
  line_end?: number;

  /** Optional framework hint (express, django, rails, …). */
  framework?: string;

  /** Optional IaC resource type (aws_s3_bucket, Deployment, …). */
  resource_type?: string;

  /** One-line evidence snippet (trimmed, ≤160 chars). */
  evidence: string;

  /** CWE id like 'CWE-639' if known. */
  cwe?: string;

  /** Optional stable rule id for dedupe (`IAC-TF-001`, etc.). */
  rule_id?: string;
}

/**
 * Input descriptor the entry point accepts. Mirrors the spec signature.
 */
export interface WebDetectorInput {
  projectPath: string;
  languages: string[];
  deps: string[];
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type VulnStatus = 'New' | 'Triaged' | 'Submitted' | 'Fixed' | 'Rejected' | 'Wont Fix';

export interface Stats {
  total: number;
  totalVulns?: number;
  critical: number;
  high: number;
  medium?: number;
  low?: number;
  submitted?: number;
  verified?: number;
  projects: number;
  totalProjects?: number;
  tools: number;
  totalTools?: number;
  recentScans: any[];
  recentVulns?: any[];
  bySeverity?: Array<{ severity: string; count: number }>;
  byStatus?: Array<{ status: string; count: number }>;
}

export interface Vulnerability {
  id: number;
  project: string;
  title: string;
  severity: Severity;
  cvss: number | null;
  cvss_vector: string | null;
  status: VulnStatus;
  method: string | null;
  cwe: string | null;
  description: string | null;
  impact: string | null;
  file: string | null;
  line_number: number | null;
  line_start?: number | null;
  line_end?: number | null;
  code_snippet: string | null;
  suggested_fix: string | null;
  fix_diff?: string | null;
  disclosure_content: string | null;
  how_to_submit_content: string | null;
  advisory_url: string | null;
  ai_triage: string | null;
  ai_summary?: string | null;
  // Human-authored triage notes. Always editable by the user and
  // independent of ai_triage - a user can triage a finding manually
  // without ever running an AI call.
  manual_triage?: string | null;
  tool_name?: string | null;
  confidence?: number | null;
  verified?: number;
  false_positive?: number;
  reproduction_steps?: string | null;
  submit_email?: string | null;
  issue_url?: string | null;
  email_chain_url?: string | null;
  response?: string | null;
  rejection_reason?: string | null;
  notes?: string | null;
  submitted_at?: string | null;
  resolved_at?: string | null;
  found_at: string;
  updated_at: string;
}

export interface Project {
  id: number;
  name: string;
  path: string;
  language: string | null;
  last_scanned: string | null;
  vuln_count?: number;
  // Optional fields populated when the project was imported from a git URL.
  // Preserved on the Projects page card and round-tripped through
  // import/export JSON so users can move a workspace between machines.
  repo_url?: string | null;
  branch?: string | null;
}

export interface Scan {
  id: number;
  project_id: number;
  project_name?: string;
  tool_name: string;
  status: 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at: string | null;
  findings_count: number | null;
  output: string | null;
}

export interface Tool {
  // DB primary-key id is INTEGER. src/pages/Tools.tsx also mints synthetic
  // ids in the 10000+ / 20000+ range for plugin-derived entries.
  id: number;
  name: string;
  category: string;
  description: string;
  docs: string | null;
  track_record: string | null;
  // SQLite stores boolean as 0/1 - the API surfaces it numerically.
  // Treat as truthy everywhere (0 = false, non-zero = true).
  enabled: number | boolean;
  file_path?: string;
  config_schema?: string;
}

export interface ModelInfo {
  id: string;
  name: string;
  tier: 'premium' | 'standard' | 'fast' | 'reasoning' | 'local' | 'cli';
  context: number;
}

export interface AIProvider {
  id: string;
  name: string;
  model: string;
  api_key: string | null;
  enabled: boolean;
  base_url?: string | null;
}

export type RoutingTask =
  | 'triage'
  | 'suggest-fix'
  | 'deep-analyze'
  | 'report'
  | 'chat'
  | 'simple'
  | 'verify'
  | 'batch-filter';

export interface RoutingRule {
  task: RoutingTask;
  provider: string;
  model: string;
  priority: number;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface AITriageResult {
  analysis: string;
  severity_assessment: string;
  exploitability: string;
  recommendations: string[];
}

export interface Report {
  id: number;
  vuln_id: number | null;
  type: string | null;
  format: string | null;
  content: string | null;
  generated_by: string | null;
  created_at: string;
}

export interface AgentStep {
  thought: string;
  action: string;
  params: Record<string, any>;
  result?: string;
}

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
  id: string;
  name: string;
  category: string;
  description: string;
  docs: string | null;
  track_record: string | null;
  enabled: boolean;
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

export interface RoutingRule {
  task: 'triage' | 'suggest-fix' | 'deep-analyze' | 'report' | 'chat' | 'simple';
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

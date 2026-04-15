import type {
  Stats,
  Vulnerability,
  Project,
  Scan,
  Tool,
  AIProvider,
  ChatMessage,
  Report,
  AgentStep,
} from './types';

const BASE = '/api';

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// Stats
export const getStats = () => request<Stats>('/stats');

// Vulnerabilities
export interface VulnQuery {
  severity?: string;
  status?: string;
  search?: string;
  sort?: string;
  order?: 'asc' | 'desc';
  limit?: number;
  offset?: number;
}

export const getVulnerabilities = (q: VulnQuery = {}) => {
  const params = new URLSearchParams();
  if (q.severity) params.set('severity', q.severity);
  if (q.status) params.set('status', q.status);
  if (q.search) params.set('search', q.search);
  if (q.sort) params.set('sort', q.sort);
  if (q.order) params.set('order', q.order);
  if (q.limit !== undefined) params.set('limit', String(q.limit));
  if (q.offset !== undefined) params.set('offset', String(q.offset));
  const qs = params.toString();
  return request<{ data: Vulnerability[]; total: number }>(`/vulnerabilities${qs ? '?' + qs : ''}`);
};

// Scan Findings (staging area)
export interface ScanFinding {
  id: number;
  scan_id: number | null;
  project_id: number | null;
  pipeline_id: string;
  title: string;
  severity: string;
  cvss: string;
  cwe: string;
  file: string;
  line_start: number | null;
  line_end: number | null;
  code_snippet: string;
  description: string;
  impact: string;
  tool_name: string;
  confidence: string;
  status: 'pending' | 'accepted' | 'rejected' | 'auto_rejected';
  rejection_reason: string;
  merged_tools: string;
  ai_filter_reason: string;
  ai_verification: string;
  suggested_fix: string;
  created_at: string;
}

export interface ScanFindingCounts {
  pending: number;
  accepted: number;
  rejected: number;
  auto_rejected: number;
}

export const getScanFindings = (params: { scan_id?: number; project_id?: number; status?: string } = {}) => {
  const qs = new URLSearchParams();
  if (params.scan_id !== undefined) qs.set('scan_id', String(params.scan_id));
  if (params.project_id !== undefined) qs.set('project_id', String(params.project_id));
  if (params.status) qs.set('status', params.status);
  return request<{ data: ScanFinding[]; counts: ScanFindingCounts; total: number }>(
    `/scan-findings${qs.toString() ? '?' + qs.toString() : ''}`
  );
};

export const acceptScanFinding = (id: number) =>
  request<{ success: boolean; vuln_id: number }>(`/scan-findings/${id}/accept`, { method: 'PUT' });

export const rejectScanFinding = (id: number, reason?: string) =>
  request<{ success: boolean }>(`/scan-findings/${id}/reject`, {
    method: 'PUT',
    body: JSON.stringify({ reason }),
  });

export const bulkAcceptScanFindings = (ids: number[]) =>
  request<{ accepted: number; vuln_ids: number[] }>('/scan-findings/bulk-accept', {
    method: 'POST',
    body: JSON.stringify({ ids }),
  });

export const bulkRejectScanFindings = (ids: number[], reason?: string) =>
  request<{ rejected: number }>('/scan-findings/bulk-reject', {
    method: 'POST',
    body: JSON.stringify({ ids, reason }),
  });

export const acceptAllScanFindings = (scan_id?: number) => {
  const qs = scan_id !== undefined ? `?scan_id=${scan_id}` : '';
  return request<{ accepted: number; vuln_ids: number[] }>(`/scan-findings/accept-all${qs}`, { method: 'POST' });
};

export const aiReviewScanFindings = (scan_id?: number) => {
  const qs = scan_id !== undefined ? `?scan_id=${scan_id}` : '';
  return request<{ accepted: number; rejected: number; reviews: any[] }>(`/scan-findings/ai-review${qs}`, { method: 'POST' });
};

export const getVulnerability = (id: number) =>
  request<Vulnerability>(`/vulnerabilities/${id}`);

export const updateVulnerability = (id: number, data: Partial<Vulnerability>) =>
  request<Vulnerability>(`/vulnerabilities/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });

export const createVulnerability = (data: Partial<Vulnerability>) =>
  request<Vulnerability>('/vulnerabilities', {
    method: 'POST',
    body: JSON.stringify(data),
  });

export const deleteVulnerability = (id: number) =>
  request<{ deleted: boolean }>(`/vulnerabilities/${id}`, { method: 'DELETE' });

// Projects
export const getProjects = () => request<{ data: Project[]; total: number }>('/projects').then(r => r.data);

export const importProject = (path: string) =>
  request<Project>('/projects', {
    method: 'POST',
    body: JSON.stringify({ path }),
  });

// Scans
export const getScans = () => request<{ data: Scan[]; total: number }>('/scans').then(r => r.data);

export const startScan = (project_id: number, tool_name: string) =>
  request<Scan>('/scans', {
    method: 'POST',
    body: JSON.stringify({ project_id, tool_name }),
  });

// Tools
export const getTools = () => request<{ data: Tool[]; total: number }>('/tools').then(r => r.data);

export const getTool = (id: string) => request<Tool>(`/tools/${id}`);

// Plugins
export interface InstalledPlugin {
  id: number;
  name: string;
  type: string | null;
  source_url: string | null;
  install_path: string | null;
  version: string | null;
  manifest: string | null;
  enabled: number;
  installed_at: string | null;
}

export const getPlugins = () =>
  request<{ data: { installed: InstalledPlugin[]; catalog: any[] }; total_installed: number }>('/plugins')
    .then(r => r.data);

export const installPlugin = (name: string) =>
  request<InstalledPlugin>('/plugins/install', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });

export const runPlugin = (id: number, target: string, options?: Record<string, any>) =>
  request<{ message: string; pluginId: number; target: string }>(`/plugins/${id}/run`, {
    method: 'POST',
    body: JSON.stringify({ target, options }),
  });

export const getPluginModules = (id: number) =>
  request<{ plugin: string; modules: string[]; total: number }>(`/plugins/${id}/modules`);

export const getPluginStatus = (id: number) =>
  request<{ status: string; message?: string; requirements?: { met: boolean; missing: string[] } }>(
    `/plugins/${id}/status`
  );

// AI
export const getAIProviders = () => request<any>('/ai/providers').then(r => Array.isArray(r) ? r : (r.data ?? []));

export const updateAIProvider = (id: string, data: Partial<AIProvider>) =>
  request<AIProvider>(`/ai/providers/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });

export const triggerAITriage = (vuln_id: number) =>
  request<{ id: number; message: string }>(`/ai/triage/${vuln_id}`, {
    method: 'POST',
  });

// Reports
export const generateReport = (vuln_id: number, type: string) =>
  request<Report>('/reports/generate', {
    method: 'POST',
    body: JSON.stringify({ vuln_id, type }),
  });

export const getReports = () =>
  request<{ data: Report[]; total: number }>('/reports').then(r => r.data);

export const getReport = (id: number) => request<Report>(`/reports/${id}`);

// Agent
export const runAgent = (goal: string, max_steps?: number) =>
  request<{ goal: string; steps: AgentStep[] }>('/ai/agent', {
    method: 'POST',
    body: JSON.stringify({ goal, max_steps }),
  });

export const sendAIChat = (messages: ChatMessage[]) =>
  request<{ response: string }>('/ai/chat', {
    method: 'POST',
    body: JSON.stringify({ messages }),
  });

// Quick status toggles
export const verifyVulnerability = (id: number) =>
  request<Vulnerability>(`/vulnerabilities/${id}/verify`, { method: 'PUT' });

export const markFalsePositive = (id: number) =>
  request<Vulnerability>(`/vulnerabilities/${id}/false-positive`, { method: 'PUT' });

// AI model registry
export const getAIModels = () => request<Record<string, { models: Array<{ id: string; name: string; tier: string; context: number }> }>>('/ai/models');

// AI routing rules
export const getAIRouting = () => request<Array<{ task: string; provider: string; model: string; priority: number }>>('/ai/routing');

export const updateAIRouting = (rules: Array<{ task: string; provider: string; model: string; priority: number }>) =>
  request<{ success: boolean; count: number }>('/ai/routing', {
    method: 'PUT',
    body: JSON.stringify(rules),
  });

// Pipeline
export interface PipelineRun {
  id: string;
  project_id: number;
  status: string;
  current_stage: string;
  progress: number;
  scan_job_ids: string;
  findings_total: number;
  findings_after_filter: number;
  findings_after_verify: number;
  config: string;
  error?: string;
  started_at: string;
  completed_at?: string;
}

export const startPipeline = (params: { url?: string; path?: string; project_id?: number; branch?: string; depth?: number }) =>
  request<{ pipelineId: string; projectId: number; status: string }>('/pipeline/start', {
    method: 'POST',
    body: JSON.stringify(params),
  });

export const startBatchPipeline = (targets: Array<{ url?: string; path?: string; project_id?: number }>) =>
  request<{ pipelines: Array<{ pipelineId: string; projectId?: number; error?: string }> }>('/pipeline/batch', {
    method: 'POST',
    body: JSON.stringify({ targets }),
  });

export const getPipelineStatus = (id: string) =>
  request<PipelineRun>(`/pipeline/${id}`);

export const getPipelines = (activeOnly = false) =>
  request<{ data: PipelineRun[]; total: number }>(`/pipeline${activeOnly ? '?active=true' : ''}`);

export const cancelPipeline = (id: string) =>
  request<{ message: string }>(`/pipeline/${id}`, { method: 'DELETE' });

export const pausePipeline = (id: string) =>
  request<{ message: string; pipelineId: string }>(`/pipeline/${id}/pause`, { method: 'POST' });

export const resumePipeline = (id: string) =>
  request<{ message: string; pipelineId: string }>(`/pipeline/${id}/resume`, { method: 'POST' });

export const importProjectFromUrl = (url: string, branch?: string, depth?: number) =>
  request<{ id: number; name: string; status: string }>('/projects/import-url', {
    method: 'POST',
    body: JSON.stringify({ url, branch, depth }),
  });

export const getPipelineFindings = (pipelineId: string, status?: string) => {
  const qs = new URLSearchParams();
  qs.set('pipeline_id', pipelineId);
  if (status) qs.set('status', status);
  return request<{ data: ScanFinding[]; counts: ScanFindingCounts; total: number }>(
    `/scan-findings?${qs.toString()}`
  );
};

// AI suggest-fix
export const suggestFix = (vuln_id: number) =>
  request<{ suggested_fix: string; fix_diff: string }>('/ai/suggest-fix', {
    method: 'POST',
    body: JSON.stringify({ vuln_id }),
  });

// AI deep-analyze
export const deepAnalyze = (vuln_id: number) =>
  request<{ analysis: string }>('/ai/deep-analyze', {
    method: 'POST',
    body: JSON.stringify({ vuln_id }),
  });

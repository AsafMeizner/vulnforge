import { useState, useEffect, useRef, useCallback } from 'react';
import { getProjects, getTools, getScans, getPlugins, resolveWsBase, apiFetch } from '@/lib/api';
import type { InstalledPlugin } from '@/lib/api';
import type { Project, Tool, Scan, Vulnerability } from '@/lib/types';
import { SeverityBadge, CvssScore } from '@/components/Badge';
import { useToast } from '@/components/Toast';
import ScanReview from './ScanReview';

function relativeTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

interface ScanJobState {
  jobId: string;
  toolName: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  findings?: number;
}

interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  newFindings: Vulnerability[];
}

interface ScannerProps {
  initialTool?: string;
  onNavigateToFinding?: (id: number) => void;
}

export default function Scanner({ initialTool, onNavigateToFinding }: ScannerProps) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [tools, setTools] = useState<Tool[]>([]);
  const [plugins, setPlugins] = useState<InstalledPlugin[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedProject, setSelectedProject] = useState<number | ''>('');
  const [selectedTools, setSelectedTools] = useState<Set<string>>(new Set(initialTool ? [initialTool] : []));
  const [selectedPlugins, setSelectedPlugins] = useState<Set<number>>(new Set());
  const [fullScan, setFullScan] = useState(false);
  const [autoTriage, setAutoTriage] = useState(false);
  const [running, setRunning] = useState(false);
  const [activeJobs, setActiveJobs] = useState<ScanJobState[]>([]);
  const [output, setOutput] = useState<string[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
  const [scanStartTime, setScanStartTime] = useState<number | null>(null);
  const [estimatedEnd, setEstimatedEnd] = useState<number | null>(null);
  const [reviewScanDbId, setReviewScanDbId] = useState<number | null>(null);
  const [showReview, setShowReview] = useState(false);
  const outputRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const { toast } = useToast();

  const loadScans = useCallback(async () => {
    try {
      const s = await getScans();
      setScans(s);
    } catch { /* non-fatal */ }
  }, []);

  const load = useCallback(async () => {
    try {
      const [p, t, s, plugData] = await Promise.all([
        getProjects(),
        getTools(),
        getScans(),
        getPlugins().catch(() => ({ installed: [], catalog: [] })),
      ]);
      setProjects(p);
      setTools(t);
      setScans(s);
      setPlugins((plugData.installed ?? []).filter((pl) => pl.enabled));
    } catch (err) {
      toast(`Load error: ${err instanceof Error ? err.message : err}`, 'error');
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  // Pre-select tool if passed via props
  useEffect(() => {
    if (initialTool) setSelectedTools(new Set([initialTool]));
  }, [initialTool]);

  // Auto-scroll terminal output
  useEffect(() => {
    const el = outputRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [output]);

  // Estimated time update
  useEffect(() => {
    if (!running || !scanStartTime || activeJobs.length === 0) return;
    const doneJobs = activeJobs.filter(j => j.status === 'completed' || j.status === 'failed').length;
    if (doneJobs > 0) {
      const elapsed = Date.now() - scanStartTime;
      const perJob = elapsed / doneJobs;
      const remaining = (activeJobs.length - doneJobs) * perJob;
      setEstimatedEnd(Date.now() + remaining);
    }
  }, [activeJobs, running, scanStartTime]);

  // WebSocket
  useEffect(() => {
    // resolveWsBase (imported at top) handles Electron file:// (no
    // location.host), vite proxy (5180 -> 3010), and same-origin modes.
    const url = resolveWsBase();
    let ws: WebSocket;
    let retryTimer: ReturnType<typeof setTimeout>;

    const connect = () => {
      ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsConnected(true);
        setOutput(prev => [...prev, '[ws] Connected to scan server']);
      };

      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string) as Record<string, any>;

          switch (msg.type) {
            case 'scan:start':
              setOutput(prev => [...prev, `[start] Tool "${msg.toolName}" started (job ${msg.jobId?.slice(0, 8)})`]);
              setActiveJobs(prev => prev.map(j =>
                j.jobId === msg.jobId ? { ...j, status: 'running' } : j
              ));
              break;

            case 'scan:output':
              if (msg.data) setOutput(prev => [...prev, msg.data as string]);
              break;

            case 'scan:complete': {
              const findings = msg.findings ?? 0;
              setOutput(prev => [...prev,
                `[done] Job ${(msg.jobId as string)?.slice(0, 8)} completed - ${findings} finding(s) staged for review`
              ]);
              // Capture first scan DB id for the review modal
              if (msg.scanDbId) {
                setReviewScanDbId((prev) => prev ?? (msg.scanDbId as number));
              }
              setActiveJobs(prev => {
                const updated = prev.map(j =>
                  j.jobId === msg.jobId ? { ...j, status: 'completed' as const, findings } : j
                );
                const allDone = updated.every(j => j.status === 'completed' || j.status === 'failed');
                if (allDone && updated.length > 0) {
                  const totalFindings = updated.reduce((acc, j) => acc + (j.findings ?? 0), 0);
                  toast(`Scan complete - ${totalFindings} finding(s) staged for review`, 'success');
                  setRunning(false);
                  setEstimatedEnd(null);
                  loadScans();
                  // Build summary from staged counts (no actual vulns added yet)
                  const summary: ScanSummary = {
                    total: totalFindings,
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    newFindings: [],
                  };
                  setScanSummary(summary);
                }
                return updated;
              });
              break;
            }

            case 'scan:error':
              setOutput(prev => [...prev, `[error] Job ${(msg.jobId as string)?.slice(0, 8)}: ${msg.error}`]);
              setActiveJobs(prev => {
                const updated = prev.map(j =>
                  j.jobId === msg.jobId ? { ...j, status: 'failed' as const } : j
                );
                const allDone = updated.every(j => j.status === 'completed' || j.status === 'failed');
                if (allDone && updated.length > 0) {
                  setRunning(false);
                  setEstimatedEnd(null);
                  loadScans();
                }
                return updated;
              });
              toast(`Scan error: ${msg.error}`, 'error');
              break;

            case 'queue:drain':
              setOutput(prev => [...prev, '[ws] Queue drained - all jobs finished']);
              break;

            case 'triage:complete':
              toast(`AI triage complete for finding #${msg.vulnId}: ${msg.severity} / tier ${msg.tier}`, 'success');
              break;

            case 'triage:error':
              toast(`AI triage failed for finding #${msg.vulnId}: ${msg.error}`, 'error');
              break;

            default:
              if (msg.type === 'scan_output' && msg.data) {
                setOutput(prev => [...prev, msg.data as string]);
              } else if (msg.type === 'scan_complete') {
                setRunning(false);
                setOutput(prev => [...prev, '[ws] Scan completed.']);
                loadScans();
              }
          }
        } catch {
          setOutput(prev => [...prev, ev.data as string]);
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        retryTimer = setTimeout(connect, 4000);
      };

      ws.onerror = () => {
        setOutput(prev => [...prev, '[ws] Connection error - retrying...']);
      };
    };

    connect();
    return () => {
      clearTimeout(retryTimer);
      ws?.close();
    };
  }, [toast, loadScans]);

  const toggleTool = (id: string) => {
    setSelectedTools(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const togglePlugin = (id: number) => {
    setSelectedPlugins(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleStartScan = async () => {
    if (!selectedProject) { toast('Select a project first', 'error'); return; }
    const toolNames = fullScan
      ? tools.filter(t => t.enabled).map(t => t.name)
      : [...selectedTools];
    const pluginIds = fullScan
      ? plugins.map(p => p.id)
      : [...selectedPlugins];
    if (toolNames.length === 0 && pluginIds.length === 0) {
      toast('Select at least one tool or plugin', 'error');
      return;
    }

    setRunning(true);
    setScanSummary(null);
    setScanStartTime(Date.now());
    setEstimatedEnd(null);

    const totalCount = toolNames.length + pluginIds.length;
    setOutput([`[scan] Enqueueing ${totalCount} tool(s) on project #${selectedProject}...`]);

    // Find project path for plugin runs
    const project = projects.find(p => p.id === Number(selectedProject));

    // Dispatch built-in tools via scan queue
    const toolJobs: ScanJobState[] = [];
    if (toolNames.length > 0) {
      try {
        const res = await apiFetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            project_id: selectedProject,
            tools: toolNames,
            auto_triage: autoTriage,
          }),
        });

        if (!res.ok) {
          const body = await res.json().catch(() => ({ error: res.statusText }));
          throw new Error(body.error || res.statusText);
        }

        const data = await res.json() as { jobs: { id: string; toolName: string; status: string }[] };
        for (const j of data.jobs ?? []) {
          toolJobs.push({ jobId: j.id, toolName: j.toolName, status: 'queued' });
        }
        setOutput(prev => [...prev, `[scan] Enqueued ${toolJobs.length} built-in tool(s)`]);
      } catch (err) {
        toast(`Tool scan failed: ${err instanceof Error ? err.message : err}`, 'error');
        setRunning(false);
        setScanStartTime(null);
        return;
      }
    }

    // Dispatch plugin jobs - each plugin run is fire-and-forget (202)
    const pluginJobs: ScanJobState[] = [];
    if (pluginIds.length > 0 && project?.path) {
      for (const pluginId of pluginIds) {
        const pl = plugins.find(p => p.id === pluginId);
        if (!pl) continue;
        const jobId = `plugin-${pluginId}-${Date.now()}`;
        pluginJobs.push({ jobId, toolName: `[plugin] ${pl.name}`, status: 'queued' });
        // Fire plugin run in background; server returns 202
        apiFetch(`/api/plugins/${pluginId}/run`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: project.path, project_id: selectedProject }),
        }).then(async res => {
          if (!res.ok) {
            const body = await res.json().catch(() => ({ error: res.statusText }));
            setOutput(prev => [...prev, `[error] Plugin "${pl.name}": ${body.error}`]);
            setActiveJobs(prev => prev.map(j => j.jobId === jobId ? { ...j, status: 'failed' } : j));
          } else {
            setOutput(prev => [...prev, `[plugin] "${pl.name}" queued - findings saved to Findings page`]);
            setActiveJobs(prev => prev.map(j => j.jobId === jobId ? { ...j, status: 'completed', findings: 0 } : j));
          }
        }).catch(err => {
          setOutput(prev => [...prev, `[error] Plugin "${pl.name}": ${err.message}`]);
          setActiveJobs(prev => prev.map(j => j.jobId === jobId ? { ...j, status: 'failed' } : j));
        });
      }
      setOutput(prev => [...prev, `[scan] Dispatched ${pluginJobs.length} plugin(s)`]);
    } else if (pluginIds.length > 0 && !project?.path) {
      toast('Selected project has no path - cannot run plugins', 'error');
    }

    const allJobs = [...toolJobs, ...pluginJobs];
    setActiveJobs(allJobs);
    setOutput(prev => [...prev, `[scan] Started: ${allJobs.map(j => j.toolName).join(', ')}`]);
    toast(`Scan started - ${allJobs.length} job(s) queued`, 'success');

    // If only plugins (no tool jobs), mark running done once dispatched
    if (toolJobs.length === 0 && pluginJobs.length > 0) {
      setRunning(false);
      setScanStartTime(null);
      loadScans();
    }
  };

  // Progress
  const totalJobs = activeJobs.length;
  const doneJobs = activeJobs.filter(j => j.status === 'completed' || j.status === 'failed').length;
  const progressPct = totalJobs > 0 ? Math.round((doneJobs / totalJobs) * 100) : 0;

  const categories = [...new Set(tools.map(t => t.category))].sort();

  const statusColor: Record<string, string> = {
    running: 'var(--orange)',
    completed: 'var(--green)',
    failed: 'var(--red)',
    pending: 'var(--muted)',
  };

  const jobStatusColor: Record<ScanJobState['status'], string> = {
    queued: 'var(--muted)',
    running: 'var(--orange)',
    completed: 'var(--green)',
    failed: 'var(--red)',
  };

  // Time remaining string
  const timeRemaining = estimatedEnd
    ? (() => {
        const ms = estimatedEnd - Date.now();
        if (ms <= 0) return 'almost done';
        const secs = Math.round(ms / 1000);
        if (secs < 60) return `~${secs}s remaining`;
        return `~${Math.ceil(secs / 60)}m remaining`;
      })()
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Scanner</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>Run analysis tools on target projects</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{
            width: 7, height: 7, borderRadius: '50%',
            background: wsConnected ? 'var(--green)' : 'var(--red)',
            display: 'inline-block',
          }} />
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>{wsConnected ? 'Live' : 'Disconnected'}</span>
        </div>
      </div>

      {/* Scan summary card - shown after scan completes */}
      {scanSummary && !running && (
        <div style={{
          background: 'var(--surface)',
          border: '1px solid var(--green)',
          borderRadius: 8,
          padding: 16,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
            <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--green)' }}>
              Scan Complete - {scanSummary.total} finding(s) staged for review
            </span>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {reviewScanDbId != null && (
                <button
                  onClick={() => setShowReview(true)}
                  style={{
                    background: 'var(--blue)',
                    border: 'none',
                    borderRadius: 5,
                    padding: '5px 14px',
                    color: '#fff',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Review Findings
                </button>
              )}
              <button
                onClick={() => setScanSummary(null)}
                style={{ background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: 14 }}
              >
                x
              </button>
            </div>
          </div>

          {/* Severity summary pills */}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: scanSummary.newFindings.length > 0 ? 14 : 0 }}>
            {scanSummary.critical > 0 && (
              <span style={summaryPill('var(--red)')}>Critical: {scanSummary.critical}</span>
            )}
            {scanSummary.high > 0 && (
              <span style={summaryPill('var(--orange)')}>High: {scanSummary.high}</span>
            )}
            {scanSummary.medium > 0 && (
              <span style={summaryPill('var(--yellow)')}>Medium: {scanSummary.medium}</span>
            )}
            {scanSummary.low > 0 && (
              <span style={summaryPill('var(--muted)')}>Low: {scanSummary.low}</span>
            )}
            {scanSummary.total === 0 && (
              <span style={{ fontSize: 13, color: 'var(--muted)' }}>No vulnerabilities found - target looks clean.</span>
            )}
          </div>

          {/* Finding list */}
          {scanSummary.newFindings.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {scanSummary.newFindings.slice(0, 8).map(v => (
                <div
                  key={v.id}
                  onClick={() => onNavigateToFinding?.(v.id)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: '6px 10px',
                    background: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: 5,
                    cursor: onNavigateToFinding ? 'pointer' : 'default',
                    fontSize: 12,
                  }}
                  onMouseEnter={e => { if (onNavigateToFinding) (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--blue)'; }}
                  onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)'}
                >
                  <SeverityBadge severity={v.severity} />
                  <span style={{ flex: 1, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.title}</span>
                  <CvssScore score={v.cvss} />
                  {onNavigateToFinding && <span style={{ color: 'var(--blue)', fontSize: 11 }}>View</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Config panel */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 16 }}>
        {/* Left: project + options + start */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={panel}>
            <label style={labelStyle}>Target Project</label>
            <select
              value={selectedProject}
              onChange={e => setSelectedProject(e.target.value ? Number(e.target.value) : '')}
              style={selectStyle}
            >
              <option value="">- Select project -</option>
              {projects.map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            {projects.length === 0 && (
              <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 6 }}>
                No projects yet. Import one from the Projects page.
              </div>
            )}
          </div>

          <div style={panel}>
            <label style={labelStyle}>Scan Options</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
                <input
                  type="checkbox"
                  checked={fullScan}
                  onChange={e => { setFullScan(e.target.checked); setSelectedTools(new Set()); }}
                  style={{ accentColor: 'var(--blue)' }}
                />
                <span style={{ color: 'var(--text)' }}>Full scan (all enabled tools)</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13 }}>
                <input
                  type="checkbox"
                  checked={autoTriage}
                  onChange={e => setAutoTriage(e.target.checked)}
                  style={{ accentColor: 'var(--purple)' }}
                />
                <span style={{ color: 'var(--text)' }}>Auto-triage findings</span>
              </label>
            </div>
          </div>

          <button
            onClick={handleStartScan}
            disabled={running || !selectedProject}
            style={{
              background: running ? 'var(--surface-2)' : 'var(--blue)',
              border: 'none',
              borderRadius: 6,
              padding: '10px 0',
              color: running ? 'var(--muted)' : '#fff',
              fontSize: 14,
              fontWeight: 600,
              cursor: running || !selectedProject ? 'not-allowed' : 'pointer',
              transition: 'background 0.15s',
            }}
          >
            {running ? 'Scanning...' : 'Start Scan'}
          </button>

          {/* Progress */}
          {running && totalJobs > 0 && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--muted)', marginBottom: 4 }}>
                <span>Progress</span>
                <span>{doneJobs}/{totalJobs} ({progressPct}%){timeRemaining ? ` - ${timeRemaining}` : ''}</span>
              </div>
              <div style={{ height: 6, background: 'var(--bg)', borderRadius: 3, overflow: 'hidden', border: '1px solid var(--border)' }}>
                <div style={{
                  height: '100%',
                  width: `${progressPct}%`,
                  background: 'var(--blue)',
                  borderRadius: 3,
                  transition: 'width 0.3s ease',
                }} />
              </div>
              <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 3 }}>
                {activeJobs.map(j => (
                  <div key={j.jobId} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: jobStatusColor[j.status], flexShrink: 0 }} />
                    <span style={{ color: 'var(--muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{j.toolName}</span>
                    {j.findings != null && j.status === 'completed' && (
                      <span style={{ color: j.findings > 0 ? 'var(--orange)' : 'var(--green)', fontWeight: 600 }}>{j.findings}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right: tool + plugin selection */}
        <div style={{ ...panel, maxHeight: 340, overflowY: 'auto' }}>
          <label style={{ ...labelStyle, marginBottom: 10, display: 'block' }}>
            Tools {!fullScan && `(${selectedTools.size + selectedPlugins.size} selected)`}
          </label>

          {/* Built-in Python tools grouped by category */}
          {categories.map(cat => (
            <div key={cat} style={{ marginBottom: 10 }}>
              <div style={{
                fontSize: 10, color: 'var(--purple)', textTransform: 'uppercase',
                letterSpacing: '0.5px', marginBottom: 5, fontWeight: 600,
              }}>
                {cat}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {tools.filter(t => t.category === cat).map(t => (
                  <label
                    key={t.id}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      cursor: fullScan ? 'not-allowed' : 'pointer',
                      opacity: fullScan ? 0.4 : 1,
                      fontSize: 12,
                      padding: '3px 0',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={fullScan || selectedTools.has(String(t.id))}
                      disabled={fullScan}
                      onChange={() => toggleTool(String(t.id))}
                      style={{ accentColor: 'var(--blue)' }}
                    />
                    <span style={{ color: 'var(--text)' }}>{t.name}</span>
                    {t.track_record && (
                      <span style={{ fontSize: 10, color: 'var(--green)', marginLeft: 'auto', flexShrink: 0 }}>
                        {t.track_record}
                      </span>
                    )}
                  </label>
                ))}
              </div>
            </div>
          ))}

          {/* Installed plugins section */}
          {plugins.length > 0 && (
            <div style={{ marginTop: 6 }}>
              <div style={{
                fontSize: 10, color: 'var(--orange)', textTransform: 'uppercase',
                letterSpacing: '0.5px', marginBottom: 5, fontWeight: 600,
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
                Plugins
                <span style={{
                  fontSize: 9, color: 'var(--orange)', background: 'var(--orange)22',
                  border: '1px solid var(--orange)44', borderRadius: 3,
                  padding: '1px 5px', fontWeight: 700,
                }}>
                  {plugins.length}
                </span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {plugins.map(pl => (
                  <label
                    key={pl.id}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      cursor: fullScan ? 'not-allowed' : 'pointer',
                      opacity: fullScan ? 0.4 : 1,
                      fontSize: 12,
                      padding: '3px 0',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={fullScan || selectedPlugins.has(pl.id)}
                      disabled={fullScan}
                      onChange={() => togglePlugin(pl.id)}
                      style={{ accentColor: 'var(--orange)' }}
                    />
                    <span style={{ color: 'var(--text)' }}>{pl.name}</span>
                    <span style={{
                      fontSize: 9, color: 'var(--orange)', background: 'var(--orange)11',
                      border: '1px solid var(--orange)33', borderRadius: 3,
                      padding: '1px 5px', marginLeft: 'auto', flexShrink: 0, fontWeight: 600,
                    }}>
                      plugin
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {tools.length === 0 && plugins.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--muted)' }}>Loading tools...</div>
          )}
        </div>
      </div>

      {/* Live output terminal */}
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <div style={{
          padding: '10px 16px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>
            SCAN OUTPUT
            {running && (
              <span style={{ marginLeft: 8, color: 'var(--orange)', fontWeight: 400, fontSize: 11 }}>
                - live
              </span>
            )}
          </span>
          <button
            onClick={() => setOutput([])}
            style={{ background: 'none', border: 'none', color: 'var(--muted)', fontSize: 11, cursor: 'pointer' }}
          >
            Clear
          </button>
        </div>
        <div
          ref={outputRef}
          style={{
            height: 260,
            overflow: 'auto',
            padding: 16,
            fontFamily: 'monospace',
            fontSize: 12,
            lineHeight: 1.6,
            color: 'var(--text)',
            background: 'var(--bg)',
          }}
        >
          {output.length === 0 ? (
            <span style={{ color: 'var(--muted)' }}>No output yet. Start a scan above.</span>
          ) : (
            output.map((line, i) => (
              <div
                key={i}
                style={{
                  color: line.startsWith('[ws]') ? 'var(--blue)'
                    : line.startsWith('[start]') ? 'var(--purple)'
                    : line.startsWith('[done]') ? 'var(--green)'
                    : line.startsWith('[scan]') ? 'var(--purple)'
                    : line.startsWith('[error]') || line.toLowerCase().includes('error') ? 'var(--red)'
                    : 'var(--text)',
                }}
              >
                {line}
              </div>
            ))
          )}
          {running && (
            <div style={{ color: 'var(--orange)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ animation: 'pulse 1s infinite' }}>|</span> Running...
            </div>
          )}
        </div>
      </div>

      {/* Scan history */}
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontWeight: 600, fontSize: 14 }}>Scan History</span>
          <button
            onClick={loadScans}
            style={{ background: 'none', border: 'none', color: 'var(--muted)', fontSize: 11, cursor: 'pointer' }}
          >
            Refresh
          </button>
        </div>
        {scans.length === 0 ? (
          <div style={{ padding: 24, textAlign: 'center', fontSize: 13, color: 'var(--muted)' }}>No scans yet.</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Project', 'Tool', 'Status', 'Findings', 'Started'].map(h => (
                    <th key={h} style={{
                      padding: '8px 14px', textAlign: 'left', color: 'var(--muted)',
                      fontWeight: 500, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px',
                      whiteSpace: 'nowrap',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 20).map(s => (
                  <tr key={s.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '8px 14px', color: 'var(--text)' }}>{s.project_name ?? `#${s.project_id}`}</td>
                    <td style={{ padding: '8px 14px', color: 'var(--muted)', fontFamily: 'monospace', fontSize: 11 }}>{s.tool_name}</td>
                    <td style={{ padding: '8px 14px' }}>
                      <span style={{ color: statusColor[s.status] ?? 'var(--muted)', fontSize: 11, fontWeight: 600 }}>
                        {s.status.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '8px 14px', color: 'var(--text)' }}>{s.findings_count ?? '-'}</td>
                    <td style={{ padding: '8px 14px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>{relativeTime(s.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0} }`}</style>

      {/* Scan Review modal */}
      {showReview && reviewScanDbId != null && (
        <ScanReview
          scanId={reviewScanDbId}
          projectName={projects.find(p => p.id === Number(selectedProject))?.name}
          onClose={() => setShowReview(false)}
          onAccepted={(count) => {
            if (count > 0) toast(`${count} finding(s) added to Vulnerabilities`, 'success');
          }}
        />
      )}
    </div>
  );
}

const panel: React.CSSProperties = {
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  padding: '14px 16px',
};

const labelStyle: React.CSSProperties = {
  fontSize: 11,
  color: 'var(--muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  fontWeight: 600,
  marginBottom: 8,
  display: 'block',
};

const selectStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '8px 10px',
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
  cursor: 'pointer',
};

function summaryPill(color: string): React.CSSProperties {
  return {
    fontSize: 12,
    color,
    background: `${color}11`,
    border: `1px solid ${color}44`,
    padding: '3px 10px',
    borderRadius: 4,
    fontWeight: 600,
  };
}

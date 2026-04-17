import { useState, useEffect, useRef, useCallback } from 'react';
import { useToast } from '@/components/Toast';
import { SeverityBadge } from '@/components/Badge';
import {
  startPipeline,
  startBatchPipeline,
  getPipelineStatus,
  getPipelines,
  getProjects,
  pausePipeline as apiPause,
  resumePipeline as apiResume,
  cancelPipeline as apiCancel,
  type PipelineRun,
  type Project,
} from '@/lib/api';

interface HuntProps {
  onNavigate: (page: string, extra?: any) => void;
}

type InputMode = 'url' | 'local' | 'batch';

interface PipelineProgress {
  id: string;
  projectName?: string;
  status: string;
  stage: string;
  detail: string;
  progress: number;
  findingsTotal?: number;
  findingsAfterFilter?: number;
  findingsAfterVerify?: number;
}

export default function Hunt({ onNavigate }: HuntProps) {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [inputMode, setInputMode] = useState<InputMode>('url');
  const [url, setUrl] = useState('');
  const [localPath, setLocalPath] = useState('');
  const [batchText, setBatchText] = useState('');
  const [branch, setBranch] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [running, setRunning] = useState(false);
  const [pipelines, setPipelines] = useState<PipelineProgress[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjects, setSelectedProjects] = useState<Set<number>>(new Set());
  const [pausedHunts, setPausedHunts] = useState<PipelineRun[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Load existing projects + paused hunts
  useEffect(() => {
    getProjects().then(setProjects).catch(() => {});
    getPipelines().then(res => {
      setPausedHunts(res.data.filter(p => p.status === 'paused'));
    }).catch(() => {});
  }, [running]);

  // WebSocket connection for pipeline progress
  useEffect(() => {
    if (!running || pipelines.length === 0) return;

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws`);
    wsRef.current = ws;

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'progress' && msg.category === 'pipeline') {
          const pipelineId = msg.id;
          setPipelines(prev => prev.map(p =>
            p.id === pipelineId
              ? { ...p, stage: msg.step, detail: msg.detail || '', progress: msg.progress || p.progress, status: msg.status === 'complete' ? 'ready' : msg.status === 'error' ? 'failed' : 'running' }
              : p
          ));
          setLogs(prev => [...prev.slice(-200), `[${pipelineId.slice(0, 8)}] ${msg.step}: ${msg.detail || ''}`]);
        }
      } catch { /* ignore */ }
    };

    return () => { ws.close(); wsRef.current = null; };
  }, [running, pipelines.length]);

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  // Poll pipeline status (backup for WebSocket)
  useEffect(() => {
    if (!running || pipelines.length === 0) return;
    const interval = setInterval(async () => {
      for (const p of pipelines) {
        if (p.status === 'ready' || p.status === 'failed') continue;
        try {
          const updated = await getPipelineStatus(p.id);
          setPipelines(prev => prev.map(x =>
            x.id === p.id ? {
              ...x,
              status: updated.status,
              progress: updated.progress,
              stage: updated.current_stage,
              findingsTotal: updated.findings_total,
              findingsAfterFilter: updated.findings_after_filter,
              findingsAfterVerify: updated.findings_after_verify,
            } : x
          ));
        } catch { /* ignore */ }
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [running, pipelines]);

  // Check if all pipelines are done
  const allDone = pipelines.length > 0 && pipelines.every(p => p.status === 'ready' || p.status === 'failed');
  const anyReady = pipelines.some(p => p.status === 'ready');

  const handleStart = async () => {
    const targets: Array<{ url?: string; path?: string; project_id?: number }> = [];

    if (inputMode === 'url') {
      const trimmed = url.trim();
      if (!trimmed) { toast('error', 'Enter a Git URL'); return; }
      targets.push({ url: trimmed });
    } else if (inputMode === 'local') {
      const trimmed = localPath.trim();
      if (!trimmed) { toast('error', 'Enter a directory path'); return; }
      targets.push({ path: trimmed });
    } else {
      // Batch: combine text lines + selected projects
      const lines = batchText.split('\n').map(l => l.trim()).filter(Boolean);
      for (const line of lines) {
        if (line.startsWith('http') || line.includes('github') || line.includes('gitlab')) {
          targets.push({ url: line });
        } else {
          targets.push({ path: line });
        }
      }
      for (const pid of selectedProjects) {
        targets.push({ project_id: pid });
      }
      if (targets.length === 0) { toast('error', 'Add at least one target'); return; }
    }

    setRunning(true);
    setLogs([]);
    setPipelines([]);

    try {
      if (targets.length === 1) {
        const result = await startPipeline({ ...targets[0], branch: branch || undefined });
        setPipelines([{
          id: result.pipelineId,
          projectName: targets[0].url || targets[0].path || `Project #${targets[0].project_id}`,
          status: 'running', stage: 'Starting...', detail: '', progress: 0,
        }]);
        setLogs([`Pipeline ${result.pipelineId} started`]);
      } else {
        const result = await startBatchPipeline(targets);
        const pipelineList: PipelineProgress[] = result.pipelines.map((p, idx) => ({
          id: p.pipelineId || `error-${idx}`,
          projectName: targets[idx]?.url || targets[idx]?.path || `Target ${idx + 1}`,
          status: p.error ? 'failed' : 'running',
          stage: p.error ? 'Failed' : 'Starting...',
          detail: p.error || '', progress: 0,
        }));
        setPipelines(pipelineList);
        setLogs([`Batch started: ${pipelineList.length} pipelines`]);
      }
    } catch (err: any) {
      toast('error', err.message);
      setRunning(false);
    }
  };

  const handleReview = () => {
    const readyPipeline = pipelines.find(p => p.status === 'ready');
    if (readyPipeline) {
      onNavigate('review', { pipelineId: readyPipeline.id });
    }
  };

  const handlePausePipeline = async (pipelineId: string) => {
    try {
      await apiPause(pipelineId);
      setPipelines(prev => prev.map(p =>
        p.id === pipelineId ? { ...p, status: 'paused', stage: 'Paused' } : p
      ));
      toast('info', 'Pipeline paused - you can resume later from the Hunt page');
    } catch (err: any) {
      toast('error', `Pause failed: ${err.message}`);
    }
  };

  const handleResumePipeline = async (pipelineId: string) => {
    try {
      await apiResume(pipelineId);
      // Switch into running view, keep existing pipeline card
      const paused = pausedHunts.find(p => p.id === pipelineId);
      if (paused) {
        setPipelines([{
          id: pipelineId,
          projectName: `Project #${paused.project_id}`,
          status: 'running',
          stage: paused.current_stage || 'resuming',
          detail: 'Resuming from saved state...',
          progress: paused.progress || 0,
          findingsTotal: paused.findings_total,
          findingsAfterFilter: paused.findings_after_filter,
          findingsAfterVerify: paused.findings_after_verify,
        }]);
        setRunning(true);
        setLogs([`Resumed pipeline ${pipelineId}`]);
      }
      toast('success', 'Pipeline resumed');
    } catch (err: any) {
      toast('error', `Resume failed: ${err.message}`);
    }
  };

  const handleCancelPipeline = async (pipelineId: string) => {
    if (!confirm('Cancel this hunt? All progress will be lost. Use Pause if you want to continue later.')) return;
    try {
      await apiCancel(pipelineId);
      setPipelines(prev => prev.map(p =>
        p.id === pipelineId ? { ...p, status: 'failed', stage: 'Cancelled' } : p
      ));
      toast('info', 'Pipeline cancelled');
    } catch (err: any) {
      toast('error', `Cancel failed: ${err.message}`);
    }
  };

  // ── Input State ───────────────────────────────────────────────────────
  if (!running) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20, minHeight: '70vh', paddingTop: 40 }}>
        <div style={{
          width: '100%', maxWidth: 640, padding: 32,
          background: 'var(--surface)', borderRadius: 12, border: '1px solid var(--border)',
        }}>
          {/* Title */}
          <div style={{ textAlign: 'center', marginBottom: 28 }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
              Hunt
            </div>
            <p style={{ color: 'var(--muted)', fontSize: 14, margin: 0 }}>
              Paste a target. VulnForge clones, scans, filters, verifies, and prepares findings for your review.
            </p>
          </div>

          {/* Mode tabs */}
          <div style={{ display: 'flex', marginBottom: 20, border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
            {([['url', 'Git URL'], ['local', 'Local Path'], ['batch', 'Batch']] as const).map(([mode, label]) => (
              <button key={mode} onClick={() => setInputMode(mode)} style={{
                flex: 1, padding: '10px 0', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600,
                color: inputMode === mode ? 'var(--text)' : 'var(--muted)',
                background: inputMode === mode ? 'var(--surface-2)' : 'transparent',
              }}>
                {label}
              </button>
            ))}
          </div>

          {/* Input fields */}
          {inputMode === 'url' && (
            <input
              autoFocus
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://github.com/org/repo"
              onKeyDown={e => e.key === 'Enter' && handleStart()}
              style={inputStyle}
            />
          )}

          {inputMode === 'local' && (
            <input
              autoFocus
              value={localPath}
              onChange={e => setLocalPath(e.target.value)}
              placeholder="C:\projects\my-app  or  /home/user/code"
              onKeyDown={e => e.key === 'Enter' && handleStart()}
              style={inputStyle}
            />
          )}

          {inputMode === 'batch' && (
            <div>
              <textarea
                value={batchText}
                onChange={e => setBatchText(e.target.value)}
                placeholder="One URL or path per line..."
                rows={4}
                style={{ ...inputStyle, resize: 'vertical', fontFamily: 'monospace' }}
              />
              {projects.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ color: 'var(--muted)', fontSize: 12, marginBottom: 6 }}>
                    Or select existing projects:
                  </div>
                  <div style={{ maxHeight: 150, overflow: 'auto', border: '1px solid var(--border)', borderRadius: 6, padding: 6 }}>
                    {projects.map(p => (
                      <label key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 6px', cursor: 'pointer', fontSize: 13, color: 'var(--text)' }}>
                        <input
                          type="checkbox"
                          checked={selectedProjects.has(p.id!)}
                          onChange={e => {
                            const next = new Set(selectedProjects);
                            e.target.checked ? next.add(p.id!) : next.delete(p.id!);
                            setSelectedProjects(next);
                          }}
                        />
                        {p.name}
                        <span style={{ color: 'var(--muted)', fontSize: 11, marginLeft: 'auto' }}>{p.language}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Advanced options */}
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            style={{ background: 'none', border: 'none', color: 'var(--muted)', fontSize: 12, cursor: 'pointer', padding: '8px 0', marginTop: 4 }}
          >
            {showAdvanced ? '▾' : '▸'} Advanced options
          </button>
          {showAdvanced && (
            <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
              <div style={{ flex: 1 }}>
                <label style={{ color: 'var(--muted)', fontSize: 11 }}>Branch</label>
                <input value={branch} onChange={e => setBranch(e.target.value)}
                  placeholder="main" style={{ ...inputStyle, padding: '6px 10px', fontSize: 12 }} />
              </div>
            </div>
          )}

          {/* Start button */}
          <button onClick={handleStart} style={{
            width: '100%', padding: '14px 0', marginTop: 20,
            background: 'var(--green)', color: '#000', border: 'none',
            borderRadius: 8, fontSize: 16, fontWeight: 700, cursor: 'pointer',
            letterSpacing: 0.3,
          }}>
            Start Hunt
          </button>
        </div>

        {/* Paused Hunts - shown only if any paused hunts exist */}
        {pausedHunts.length > 0 && (
          <div style={{
            width: '100%', maxWidth: 640, padding: 20,
            background: 'var(--surface)', borderRadius: 12, border: '1px solid var(--yellow)44',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
              <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>Paused Hunts</span>
              <span style={{ fontSize: 11, color: 'var(--yellow)', background: 'var(--yellow)22', padding: '2px 8px', borderRadius: 10 }}>
                {pausedHunts.length}
              </span>
              <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--muted)' }}>
                Resume anytime from where you left off
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {pausedHunts.map(p => {
                const projectName = projects.find(pr => pr.id === p.project_id)?.name || `Project #${p.project_id}`;
                return (
                  <div key={p.id} style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: 12, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
                  }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: 'var(--text)', fontSize: 13, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {projectName}
                      </div>
                      <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 2 }}>
                        Stage: {p.current_stage || 'unknown'} · {p.progress}% · {p.findings_total} raw, {p.findings_after_filter} filtered
                      </div>
                    </div>
                    <button
                      onClick={() => handleResumePipeline(p.id)}
                      style={{
                        padding: '6px 14px', background: 'var(--green)22', color: 'var(--green)',
                        border: '1px solid var(--green)66', borderRadius: 5, fontSize: 12, fontWeight: 600, cursor: 'pointer',
                      }}
                    >
                      Resume
                    </button>
                    <button
                      onClick={() => handleCancelPipeline(p.id).then(() => {
                        setPausedHunts(prev => prev.filter(x => x.id !== p.id));
                      })}
                      style={{
                        padding: '6px 10px', background: 'transparent', color: 'var(--muted)',
                        border: '1px solid var(--border)', borderRadius: 5, fontSize: 12, cursor: 'pointer',
                      }}
                    >
                      Discard
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    );
  }

  // ── Running / Complete State ──────────────────────────────────────────
  return (
    <div style={{ padding: 20, maxWidth: 900, margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text)', marginBottom: 20, fontSize: 20 }}>
        {allDone ? 'Hunt Complete' : 'Hunt in Progress...'}
      </h2>

      {/* Pipeline cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 20 }}>
        {pipelines.map(p => (
          <div key={p.id} style={{
            border: '1px solid var(--border)', borderRadius: 8,
            background: 'var(--surface)', padding: 16,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div>
                <span style={{ color: 'var(--text)', fontWeight: 600, fontSize: 14 }}>
                  {p.projectName ? p.projectName.split('/').pop() : p.id.slice(0, 12)}
                </span>
                <span style={{
                  marginLeft: 10, fontSize: 11, fontWeight: 600,
                  color: p.status === 'ready' ? 'var(--green)' : p.status === 'failed' ? 'var(--red)' : 'var(--blue)',
                }}>
                  {p.status === 'ready' ? 'COMPLETE' : p.status === 'failed' ? 'FAILED' : p.status === 'paused' ? 'PAUSED' : 'RUNNING'}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--muted)', fontSize: 12 }}>{p.progress}%</span>
                {p.status !== 'ready' && p.status !== 'failed' && p.status !== 'paused' && (
                  <>
                    <button
                      onClick={() => handlePausePipeline(p.id)}
                      title="Pause (save progress, resume later)"
                      style={{
                        padding: '4px 10px', fontSize: 11, fontWeight: 600, cursor: 'pointer',
                        background: 'var(--yellow)22', color: 'var(--yellow)',
                        border: '1px solid var(--yellow)66', borderRadius: 4,
                      }}
                    >
                      Pause
                    </button>
                    <button
                      onClick={() => handleCancelPipeline(p.id)}
                      title="Cancel (discard progress)"
                      style={{
                        padding: '4px 10px', fontSize: 11, fontWeight: 600, cursor: 'pointer',
                        background: 'transparent', color: 'var(--muted)',
                        border: '1px solid var(--border)', borderRadius: 4,
                      }}
                    >
                      Stop
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Progress bar */}
            <div style={{ height: 4, background: 'var(--bg)', borderRadius: 2, overflow: 'hidden', marginBottom: 8 }}>
              <div style={{
                height: '100%', borderRadius: 2, transition: 'width 0.5s',
                width: `${p.progress}%`,
                background: p.status === 'failed' ? 'var(--red)' : p.status === 'ready' ? 'var(--green)' : 'var(--blue)',
              }} />
            </div>

            {/* Stage info */}
            <div style={{ color: 'var(--muted)', fontSize: 12 }}>
              {p.stage}{p.detail ? ` - ${p.detail}` : ''}
            </div>

            {/* Stats row when data available */}
            {(p.findingsTotal || 0) > 0 && (
              <div style={{ display: 'flex', gap: 16, marginTop: 8, fontSize: 12, color: 'var(--muted)' }}>
                <span>Raw: <strong style={{ color: 'var(--text)' }}>{p.findingsTotal}</strong></span>
                {p.findingsAfterFilter !== undefined && (
                  <span>After filter: <strong style={{ color: 'var(--text)' }}>{p.findingsAfterFilter}</strong></span>
                )}
                {p.findingsAfterVerify !== undefined && (
                  <span>Verified: <strong style={{ color: 'var(--green)' }}>{p.findingsAfterVerify}</strong></span>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Stage pipeline visual */}
      {pipelines.length === 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 4, marginBottom: 20 }}>
          {['cloning', 'analyzing', 'scanning', 'filtering', 'verifying', 'ready'].map(stage => {
            const p = pipelines[0];
            const stageOrder = ['cloning', 'analyzing', 'scanning', 'filtering', 'verifying', 'ready'];
            const currentIdx = stageOrder.indexOf(p.stage || p.status);
            const stageIdx = stageOrder.indexOf(stage);
            const isDone = stageIdx < currentIdx || p.status === 'ready';
            const isCurrent = stageIdx === currentIdx && p.status !== 'ready';

            return (
              <div key={stage} style={{
                padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600,
                background: isDone ? 'var(--green)22' : isCurrent ? 'var(--blue)22' : 'var(--bg)',
                color: isDone ? 'var(--green)' : isCurrent ? 'var(--blue)' : 'var(--muted)',
                border: `1px solid ${isDone ? 'var(--green)44' : isCurrent ? 'var(--blue)44' : 'var(--border)'}`,
              }}>
                {isDone ? '\u2713 ' : isCurrent ? '\u25CF ' : ''}{stage}
              </div>
            );
          })}
        </div>
      )}

      {/* Log output */}
      <div ref={logRef} style={{
        height: 200, overflow: 'auto', padding: 12, borderRadius: 8,
        background: 'var(--bg)', border: '1px solid var(--border)',
        fontFamily: 'monospace', fontSize: 11, lineHeight: 1.6, color: 'var(--muted)',
        marginBottom: 20,
      }}>
        {logs.map((line, i) => <div key={i}>{line}</div>)}
        {!allDone && <div style={{ color: 'var(--blue)' }}>&#9646; Running...</div>}
      </div>

      {/* Action buttons */}
      {allDone && (
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
          {anyReady && (
            <button onClick={handleReview} style={{
              padding: '14px 32px', background: 'var(--green)', color: '#000',
              border: 'none', borderRadius: 8, fontSize: 16, fontWeight: 700, cursor: 'pointer',
            }}>
              Review Findings
            </button>
          )}
          <button onClick={() => { setRunning(false); setPipelines([]); setLogs([]); }} style={{
            padding: '14px 32px', background: 'transparent',
            border: '1px solid var(--border)', borderRadius: 8,
            color: 'var(--text)', fontSize: 14, cursor: 'pointer',
          }}>
            New Hunt
          </button>
        </div>
      )}
    </div>
  );
}

// ── Styles ──────────────────────────────────────────────────────────────────

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '12px 14px', boxSizing: 'border-box',
  background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 8, color: 'var(--text)', fontSize: 14,
  outline: 'none',
};

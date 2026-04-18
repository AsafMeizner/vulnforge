import { useState, useEffect, useCallback, useMemo } from 'react';
import { SeverityBadge, CvssScore } from '@/components/Badge';
import { useToast } from '@/components/Toast';
import {
  getPipelineFindings,
  getPipelineStatus,
  acceptScanFinding,
  rejectScanFinding,
  bulkAcceptScanFindings,
  getToolDescriptions,
  getProjectFile,
  deepTriageBatch,
  resolveWsBase,
  type ScanFinding,
  type PipelineRun,
} from '@/lib/api';
import { CodeViewer } from '@/components/CodeViewer';
import { Markdown } from '@/components/Markdown';

interface ReviewQueueProps {
  pipelineId?: string;
  onNavigate: (page: string, extra?: any) => void;
}

export default function ReviewQueue({ pipelineId, onNavigate }: ReviewQueueProps) {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [pipeline, setPipeline] = useState<PipelineRun | null>(null);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'card' | 'table'>('card');
  const [reviewed, setReviewed] = useState<Set<number>>(new Set());
  const [activeTab, setActiveTab] = useState<'summary' | 'code' | 'fix' | 'raw'>('summary');
  // Deep-triage UI state: description map, batch progress, verified-only
  // filter, and the file-viewer modal's open state.
  const [toolDescriptions, setToolDescriptions] = useState<Record<string, string>>({});
  const [triageProgress, setTriageProgress] = useState<null | {
    batchId: string; done: number; total: number;
    verified: number; rejected: number; errored: number; completed: boolean;
  }>(null);
  const [verifiedOnly, setVerifiedOnly] = useState(false);
  const [fileViewer, setFileViewer] = useState<null | {
    projectId: number; path: string;
    lineStart: number | null; lineEnd: number | null;
  }>(null);

  // Load findings
  const loadFindings = useCallback(async () => {
    setLoading(true);
    try {
      if (pipelineId) {
        const [findingsRes, pipelineRes] = await Promise.all([
          getPipelineFindings(pipelineId, 'pending'),
          getPipelineStatus(pipelineId),
        ]);
        setFindings(findingsRes.data);
        setPipeline(pipelineRes);
      } else {
        // No specific pipeline - show ALL pending scan findings across all pipelines
        const { getScanFindings } = await import('@/lib/api');
        const res = await getScanFindings({ status: 'pending' });
        setFindings(res.data);
        setPipeline(null);
      }
    } catch (err: any) {
      toast('error', `Failed to load: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, [pipelineId]);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  // Fetch the tool_name -> description map once on mount.
  useEffect(() => {
    getToolDescriptions().then(setToolDescriptions).catch(() => { /* non-fatal */ });
  }, []);

  // Subscribe to deep-triage progress broadcasts over the WebSocket.
  // Parses the JSON-encoded `detail` field the batch worker emits.
  useEffect(() => {
    let ws: WebSocket | null = null;
    try { ws = new WebSocket(resolveWsBase()); } catch { return; }
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type !== 'progress' || msg.category !== 'deep-triage' || !msg.id) return;
        const detail = typeof msg.data?.detail === 'string' ? JSON.parse(msg.data.detail) : msg.data?.detail;
        if (!detail) return;
        setTriageProgress({
          batchId: msg.id,
          done: detail.done || 0, total: detail.total || 0,
          verified: detail.verified || 0, rejected: detail.rejected || 0,
          errored: detail.errored || 0, completed: !!detail.completed,
        });
        if (detail.completed) loadFindings();
      } catch { /* malformed - ignore */ }
    };
    return () => { try { ws?.close(); } catch { /* */ } };
  }, [loadFindings]);

  // Verified-only filter: hide findings without a verified/likely verdict.
  // Untriaged findings stay visible so the user can still review them.
  const displayFindings = useMemo(() => {
    if (!verifiedOnly) return findings;
    return findings.filter((f) => {
      if (!f.ai_verification) return false;
      try {
        const r = JSON.parse(f.ai_verification);
        return r?.verdict === 'verified' || r?.verdict === 'likely';
      } catch { return false; }
    });
  }, [findings, verifiedOnly]);

  // Keyboard navigation
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (viewMode !== 'card') return;
      if (e.key === 'ArrowRight' || e.key === 'j') {
        setCurrentIndex(i => Math.min(i + 1, findings.length - 1));
      } else if (e.key === 'ArrowLeft' || e.key === 'k') {
        setCurrentIndex(i => Math.max(i - 1, 0));
      } else if (e.key === 'a') {
        handleAccept();
      } else if (e.key === 'r') {
        handleReject();
      } else if (e.key === 's') {
        handleSkip();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [findings, currentIndex, viewMode]);

  const current = displayFindings[currentIndex] || findings[currentIndex];

  const handleDeepTriageAll = async () => {
    const pending = findings.filter((f) => f.status === 'pending');
    if (pending.length === 0) { toast('info', 'No pending findings to triage'); return; }
    const ok = window.confirm(
      `Run AI Deep Triage on ${pending.length} pending findings?\n\n` +
      'Each goes through 4 stages (verify -> test -> write -> verdict). ' +
      'Ollama-backed triage takes 10-30s per finding; you can keep reviewing while it runs.',
    );
    if (!ok) return;
    try {
      const resp = await deepTriageBatch({
        ids: pending.map((f) => f.id),
        concurrency: 3,
      });
      toast('success', `Deep-triage started (${resp.total} findings)`);
      setTriageProgress({
        batchId: resp.batchId,
        done: 0, total: resp.total,
        verified: 0, rejected: 0, errored: 0, completed: false,
      });
    } catch (err: any) {
      toast('error', `Deep-triage failed: ${err.message}`);
    }
  };

  const handleViewInFile = (f: ScanFinding) => {
    if (!f.file || !f.project_id) {
      toast('error', 'Finding has no file/project - cannot open');
      return;
    }
    setFileViewer({
      projectId: f.project_id,
      path: f.file,
      lineStart: f.line_start ?? null,
      lineEnd: f.line_end ?? null,
    });
  };

  const handleAccept = async () => {
    if (!current) return;
    try {
      await acceptScanFinding(current.id);
      toast('success', 'Finding accepted');
      setReviewed(prev => new Set(prev).add(current.id));
      setFindings(prev => prev.filter(f => f.id !== current.id));
      if (currentIndex >= findings.length - 1) setCurrentIndex(Math.max(0, currentIndex - 1));
    } catch (err: any) {
      toast('error', err.message);
    }
  };

  const handleReject = async () => {
    if (!current) return;
    try {
      await rejectScanFinding(current.id, 'Rejected during review');
      toast('info', 'Finding rejected');
      setReviewed(prev => new Set(prev).add(current.id));
      setFindings(prev => prev.filter(f => f.id !== current.id));
      if (currentIndex >= findings.length - 1) setCurrentIndex(Math.max(0, currentIndex - 1));
    } catch (err: any) {
      toast('error', err.message);
    }
  };

  const handleSkip = () => {
    setCurrentIndex(i => Math.min(i + 1, findings.length - 1));
  };

  const handleAcceptAll = async () => {
    const ids = findings.map(f => f.id);
    try {
      await bulkAcceptScanFindings(ids);
      toast('success', `Accepted ${ids.length} findings`);
      setFindings([]);
    } catch (err: any) {
      toast('error', err.message);
    }
  };

  // Removed the "No Pipeline Selected" blocker - ReviewQueue now loads all pending findings when no pipelineId is set

  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: 'center' }}>
        <div style={{ color: 'var(--muted)', fontSize: 14 }}>Loading findings...</div>
      </div>
    );
  }

  // All reviewed
  if (findings.length === 0) {
    return (
      <div style={{ padding: 40, textAlign: 'center' }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>&#x2705;</div>
        <h2 style={{ color: 'var(--text)', marginBottom: 8 }}>All Done!</h2>
        <p style={{ color: 'var(--muted)', marginBottom: 24 }}>
          {reviewed.size > 0
            ? `You reviewed ${reviewed.size} findings. Accepted ones are now on the Findings page.`
            : 'No findings to review for this pipeline.'}
        </p>
        <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
          <button onClick={() => onNavigate('findings')} style={btnStyle('var(--green)')}>View Findings</button>
          <button onClick={() => onNavigate('hunt')} style={btnStyle('var(--blue)')}>New Hunt</button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 0 }}>
      {/* ── Top Bar ──────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '12px 20px', borderBottom: '1px solid var(--border)', background: 'var(--surface)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ color: 'var(--text)', fontWeight: 600, fontSize: 16 }}>Review Queue</span>
          {pipeline && (
            <span style={{ color: 'var(--muted)', fontSize: 13 }}>
              Pipeline: {pipeline.id.slice(0, 12)}
            </span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <span style={{ color: 'var(--text)', fontSize: 13, fontWeight: 500 }}>
            {currentIndex + 1} of {displayFindings.length} remaining
          </span>
          <span style={{ color: 'var(--muted)', fontSize: 12 }}>
            ({reviewed.size} reviewed)
          </span>

          {/* Verified-only filter - only show rows whose AI verdict was verified/likely */}
          <label style={{
            display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer',
            fontSize: 12, color: verifiedOnly ? 'var(--blue)' : 'var(--muted)',
            padding: '4px 8px', border: '1px solid var(--border)', borderRadius: 6,
          }}>
            <input type="checkbox" checked={verifiedOnly}
              onChange={(e) => { setVerifiedOnly(e.target.checked); setCurrentIndex(0); }}
              style={{ margin: 0 }} />
            Verified only
          </label>

          {/* View mode toggle */}
          <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
            <button onClick={() => setViewMode('card')}
              style={{ ...toggleBtnStyle, background: viewMode === 'card' ? 'var(--surface-2)' : 'transparent' }}>
              Card
            </button>
            <button onClick={() => setViewMode('table')}
              style={{ ...toggleBtnStyle, background: viewMode === 'table' ? 'var(--surface-2)' : 'transparent' }}>
              Table
            </button>
          </div>

          <button
            onClick={handleDeepTriageAll}
            disabled={!!triageProgress && !triageProgress.completed}
            title="Run AI 4-stage triage (verify -> test -> write -> verdict) on every pending finding"
            style={{
              ...btnStyle('var(--blue)', true),
              opacity: (!!triageProgress && !triageProgress.completed) ? 0.7 : 1,
              cursor: (!!triageProgress && !triageProgress.completed) ? 'wait' : 'pointer',
            }}
          >
            {triageProgress && !triageProgress.completed
              ? `AI Triage ${triageProgress.done}/${triageProgress.total}`
              : 'AI Deep Triage'}
          </button>

          <button onClick={handleAcceptAll} style={btnStyle('var(--green)', true)}>
            Accept All ({findings.length})
          </button>
        </div>
      </div>

      {/* Deep-triage progress strip - only while a batch is in flight */}
      {triageProgress && !triageProgress.completed && (
        <div style={{
          padding: '6px 20px', borderBottom: '1px solid var(--border)',
          background: 'color-mix(in srgb, var(--blue) 10%, transparent)',
          display: 'flex', alignItems: 'center', gap: 14, fontSize: 12, color: 'var(--text)',
        }}>
          <strong>Deep triage</strong>
          <span style={{ color: 'var(--muted)' }}>{triageProgress.done}/{triageProgress.total}</span>
          <span style={{ width: 200, height: 6, background: 'var(--surface-2)', borderRadius: 3, overflow: 'hidden' }}>
            <span style={{
              display: 'block',
              width: `${triageProgress.total === 0 ? 0 : Math.round((triageProgress.done / triageProgress.total) * 100)}%`,
              height: '100%', background: 'var(--blue)', transition: 'width 0.3s ease',
            }} />
          </span>
          <span style={{ color: 'var(--green)' }}>{triageProgress.verified} verified</span>
          <span style={{ color: 'var(--muted)' }}>{triageProgress.rejected} rejected</span>
          {triageProgress.errored > 0 && <span style={{ color: 'var(--red)' }}>{triageProgress.errored} errored</span>}
        </div>
      )}

      {/* File-viewer modal - triggered by "View in file" on a finding */}
      {fileViewer && (
        <FileViewerModal
          projectId={fileViewer.projectId}
          path={fileViewer.path}
          lineStart={fileViewer.lineStart}
          lineEnd={fileViewer.lineEnd}
          onClose={() => setFileViewer(null)}
        />
      )}

      {/* ── Main Content ─────────────────────────────────────────── */}
      {viewMode === 'card' ? (
        <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
          {/* Progress sidebar */}
          <div style={{
            width: 200, borderRight: '1px solid var(--border)', overflow: 'auto',
            padding: '12px 8px', background: 'var(--bg)',
          }}>
            <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>
              Findings
            </div>
            {findings.map((f, idx) => (
              <div key={f.id} onClick={() => setCurrentIndex(idx)} style={{
                padding: '6px 8px', borderRadius: 4, cursor: 'pointer', marginBottom: 2,
                background: idx === currentIndex ? 'var(--surface-2)' : 'transparent',
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
                <span style={{
                  width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                  background: f.severity === 'Critical' ? 'var(--red)' : f.severity === 'High' ? 'var(--orange)' : f.severity === 'Medium' ? 'var(--yellow)' : 'var(--muted)',
                }} />
                <span style={{
                  fontSize: 11, color: idx === currentIndex ? 'var(--text)' : 'var(--muted)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {f.title.slice(0, 30)}
                </span>
              </div>
            ))}
          </div>

          {/* Card view */}
          <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
            {current && <FindingCard
              finding={current}
              activeTab={activeTab}
              onTabChange={setActiveTab}
              toolDescription={toolDescriptions[current.tool_name || ''] || null}
              onViewInFile={() => handleViewInFile(current)}
            />}

            {/* Action buttons */}
            <div style={{
              display: 'flex', gap: 12, marginTop: 20, justifyContent: 'center',
            }}>
              <button onClick={handleReject} style={actionBtnStyle('var(--red)')}>
                Reject (R)
              </button>
              <button onClick={handleSkip} style={actionBtnStyle('var(--muted)')}>
                Skip (S)
              </button>
              <button onClick={handleAccept} style={actionBtnStyle('var(--green)')}>
                Accept (A)
              </button>
            </div>

            {/* Navigation */}
            <div style={{ display: 'flex', justifyContent: 'center', gap: 12, marginTop: 12 }}>
              <button onClick={() => setCurrentIndex(i => Math.max(0, i - 1))}
                disabled={currentIndex === 0}
                style={{ ...navBtnStyle, opacity: currentIndex === 0 ? 0.3 : 1 }}>
                &#8592; Previous
              </button>
              <button onClick={() => setCurrentIndex(i => Math.min(i + 1, findings.length - 1))}
                disabled={currentIndex >= findings.length - 1}
                style={{ ...navBtnStyle, opacity: currentIndex >= findings.length - 1 ? 0.3 : 1 }}>
                Next &#8594;
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* ── Table View ──────────────────────────────────────────── */
        <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <th style={thStyle}>Severity</th>
                <th style={thStyle}>Title</th>
                <th style={thStyle}>File</th>
                <th style={thStyle}>Tool</th>
                <th style={thStyle}>CVSS</th>
                <th style={thStyle}>Confidence</th>
                <th style={thStyle}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {findings.map(f => (
                <tr key={f.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={tdStyle}><SeverityBadge severity={f.severity as any} /></td>
                  <td style={{ ...tdStyle, maxWidth: 300 }}>
                    <span style={{ color: 'var(--text)', fontSize: 13 }}>{f.title}</span>
                  </td>
                  <td style={tdStyle}>
                    <span style={{ color: 'var(--muted)', fontFamily: 'monospace', fontSize: 11 }}>
                      {f.file ? `${f.file}:${f.line_start || '?'}` : '-'}
                    </span>
                  </td>
                  <td style={tdStyle}>
                    <span style={{ color: 'var(--muted)', fontSize: 12 }}>
                      {f.merged_tools || f.tool_name || '-'}
                    </span>
                  </td>
                  <td style={tdStyle}><CvssScore score={f.cvss} /></td>
                  <td style={tdStyle}>
                    <span style={{
                      color: f.confidence === 'High' ? 'var(--green)' : f.confidence === 'Medium' ? 'var(--yellow)' : 'var(--red)',
                      fontSize: 12, fontWeight: 600,
                    }}>{f.confidence}</span>
                  </td>
                  <td style={tdStyle}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => acceptScanFinding(f.id).then(() => {
                        setFindings(prev => prev.filter(x => x.id !== f.id));
                        setReviewed(prev => new Set(prev).add(f.id));
                        toast('success', 'Accepted');
                      })} style={smallBtnStyle('var(--green)')}>Accept</button>
                      <button onClick={() => rejectScanFinding(f.id).then(() => {
                        setFindings(prev => prev.filter(x => x.id !== f.id));
                        setReviewed(prev => new Set(prev).add(f.id));
                        toast('info', 'Rejected');
                      })} style={smallBtnStyle('var(--red)')}>Reject</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Finding Card Component ─────────────────────────────────────────────────

function FindingCard({
  finding, activeTab, onTabChange, toolDescription, onViewInFile,
}: {
  finding: ScanFinding;
  activeTab: string;
  onTabChange: (tab: 'summary' | 'code' | 'fix' | 'raw') => void;
  /** Optional one-sentence description of what the scanner looks for. */
  toolDescription?: string | null;
  /** Invoked when the user clicks "View in file" on the code tab. */
  onViewInFile?: () => void;
}) {
  const verification = finding.ai_verification ? tryParse(finding.ai_verification) : null;

  return (
    <div style={{
      border: '1px solid var(--border)', borderRadius: 8,
      background: 'var(--surface)', overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <SeverityBadge severity={finding.severity as any} />
          <CvssScore score={finding.cvss} />
          {finding.cwe && (
            <span style={{ color: 'var(--blue)', fontSize: 12, fontFamily: 'monospace' }}>{finding.cwe}</span>
          )}
          <span style={{
            color: finding.confidence === 'High' ? 'var(--green)' : finding.confidence === 'Medium' ? 'var(--yellow)' : 'var(--muted)',
            fontSize: 11, fontWeight: 600, marginLeft: 'auto',
          }}>
            {finding.confidence} confidence
          </span>
        </div>
        <h3 style={{ color: 'var(--text)', fontSize: 18, fontWeight: 600, margin: 0 }}>
          {finding.title}
        </h3>
        <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 6, display: 'flex', gap: 16 }}>
          {finding.file && (
            <span style={{ fontFamily: 'monospace' }}>{finding.file}:{finding.line_start || '?'}</span>
          )}
          <span>Tool: {finding.merged_tools || finding.tool_name || 'unknown'}</span>
          {verification?.tier && <span>Tier: {verification.tier}</span>}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
        {(['summary', 'code', 'fix', 'raw'] as const).map(tab => (
          <button key={tab} onClick={() => onTabChange(tab)} style={{
            padding: '8px 16px', border: 'none', cursor: 'pointer', fontSize: 13,
            color: activeTab === tab ? 'var(--text)' : 'var(--muted)',
            background: activeTab === tab ? 'var(--surface-2)' : 'transparent',
            borderBottom: activeTab === tab ? '2px solid var(--blue)' : '2px solid transparent',
            fontWeight: activeTab === tab ? 600 : 400,
          }}>
            {tab === 'summary' ? 'Summary' : tab === 'code' ? 'Code' : tab === 'fix' ? 'Suggested Fix' : 'Raw Output'}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ padding: 20, minHeight: 200, maxHeight: 400, overflow: 'auto' }}>
        {activeTab === 'summary' && (
          <div>
            {toolDescription && (
              <div style={{
                marginBottom: 16, padding: '10px 12px', borderRadius: 6,
                background: 'color-mix(in srgb, var(--blue) 8%, transparent)',
                border: '1px solid color-mix(in srgb, var(--blue) 30%, var(--border))',
              }}>
                <div style={{ ...labelStyle, color: 'var(--blue)', marginBottom: 4 }}>
                  What {finding.tool_name || 'this scanner'} checks for
                </div>
                <p style={{ color: 'var(--text)', fontSize: 13, lineHeight: 1.5, margin: 0 }}>
                  {toolDescription}
                </p>
              </div>
            )}
            {(() => {
              // Deep-triage verdict block. Only render when we actually
              // have a schema-v1 result — ignores the older ai_review
              // JSON shape stored by the legacy /ai-review endpoint.
              if (!verification || verification.v !== 1) return null;
              const verdictColor = verification.verdict === 'verified' ? 'var(--green)'
                : verification.verdict === 'likely' ? 'var(--blue)'
                : verification.verdict === 'rejected' ? 'var(--muted)'
                : verification.verdict === 'needs-runtime' ? 'var(--orange)'
                : 'var(--muted)';
              return (
                <div style={{
                  marginBottom: 16, padding: 12, borderRadius: 6,
                  background: 'var(--bg)', border: `1px solid ${verdictColor}44`,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                    <div style={{ ...labelStyle, color: verdictColor, margin: 0 }}>
                      AI Deep Triage
                    </div>
                    <span style={{
                      padding: '2px 8px', borderRadius: 3, fontSize: 11, fontWeight: 700,
                      background: `${verdictColor}22`, color: verdictColor, textTransform: 'uppercase',
                    }}>{verification.verdict}</span>
                    <span style={{ color: 'var(--muted)', fontSize: 11 }}>
                      {verification.confidence}% confidence
                    </span>
                  </div>
                  <p style={{ color: 'var(--text)', fontSize: 13, margin: 0, whiteSpace: 'pre-line' }}>
                    {verification.rationale}
                  </p>
                </div>
              );
            })()}
            {finding.description && (
              <div style={{ marginBottom: 16 }}>
                <div style={labelStyle}>Description</div>
                {/* Markdown so headings/code/bullets/bold render
                    instead of collapsing into an unreadable wall. */}
                <Markdown fontSize={13}>{finding.description}</Markdown>
              </div>
            )}
            {finding.impact && (
              <div style={{ marginBottom: 16 }}>
                <div style={labelStyle}>Impact</div>
                <Markdown fontSize={13}>{finding.impact}</Markdown>
              </div>
            )}
            {verification && (
              <div style={{
                marginTop: 16, padding: 12, borderRadius: 6,
                background: 'var(--bg)', border: '1px solid var(--border)',
              }}>
                <div style={labelStyle}>AI Verification</div>
                <p style={{ color: 'var(--text)', fontSize: 13, margin: '4px 0' }}>
                  {verification.verification_reason}
                </p>
                <div style={{ display: 'flex', gap: 16, marginTop: 8, fontSize: 12 }}>
                  <span style={{ color: 'var(--muted)' }}>
                    Exploitability: <strong style={{ color: 'var(--text)' }}>{verification.exploitability}</strong>
                  </span>
                  <span style={{ color: 'var(--muted)' }}>
                    Data flow reachable: <strong style={{ color: verification.data_flow_reachable ? 'var(--green)' : 'var(--red)' }}>
                      {verification.data_flow_reachable ? 'Yes' : 'No'}
                    </strong>
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'code' && (
          <div>
            <pre style={{
              margin: 0, padding: 12, borderRadius: 6,
              background: 'var(--bg)', border: '1px solid var(--border)',
              overflow: 'auto', fontSize: 12, lineHeight: 1.5,
              color: 'var(--text)', fontFamily: 'monospace',
            }}>
              {finding.code_snippet || 'No code snippet available.'}
            </pre>
            {finding.file && onViewInFile && (
              <button
                onClick={onViewInFile}
                style={{
                  marginTop: 10, padding: '6px 14px', fontSize: 12,
                  background: 'var(--surface-2)', color: 'var(--text)',
                  border: '1px solid var(--border)', borderRadius: 5, cursor: 'pointer',
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                }}
              >
                <span>&#128193;</span>
                View {finding.file.split(/[/\\]/).pop()}{finding.line_start ? ` : ${finding.line_start}` : ''} in full
              </button>
            )}
          </div>
        )}

        {activeTab === 'fix' && (
          <div>
            {finding.suggested_fix ? (
              <pre style={{
                margin: 0, padding: 12, borderRadius: 6,
                background: 'var(--bg)', border: '1px solid var(--border)',
                overflow: 'auto', fontSize: 12, lineHeight: 1.5,
                color: 'var(--text)', fontFamily: 'monospace',
              }}>
                {finding.suggested_fix}
              </pre>
            ) : verification?.enriched_fix ? (
              <pre style={{
                margin: 0, padding: 12, borderRadius: 6,
                background: 'var(--bg)', border: '1px solid var(--border)',
                overflow: 'auto', fontSize: 12, lineHeight: 1.5,
                color: 'var(--text)', fontFamily: 'monospace',
              }}>
                {verification.enriched_fix}
              </pre>
            ) : (
              <div style={{ color: 'var(--muted)', textAlign: 'center', padding: 40 }}>
                No suggested fix available.
              </div>
            )}
          </div>
        )}

        {activeTab === 'raw' && (
          <div>
            {finding.ai_filter_reason && (
              <div style={{ marginBottom: 12 }}>
                <div style={labelStyle}>AI Filter Decision</div>
                <p style={{ color: 'var(--muted)', fontSize: 12, margin: 0 }}>{finding.ai_filter_reason}</p>
              </div>
            )}
            <div style={labelStyle}>Raw Tool Output</div>
            <pre style={{
              margin: 0, padding: 12, borderRadius: 6,
              background: 'var(--bg)', border: '1px solid var(--border)',
              overflow: 'auto', fontSize: 11, lineHeight: 1.4,
              color: 'var(--muted)', fontFamily: 'monospace', maxHeight: 300,
            }}>
              {finding.description || 'No raw output stored.'}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

// ── File Viewer Modal ─────────────────────────────────────────────────────
// Fetches the file from the server's /projects/:id/file endpoint and
// renders it in a CodeViewer with the flagged line(s) highlighted.
// Escape or backdrop click closes.

function FileViewerModal({
  projectId, path, lineStart, lineEnd, onClose,
}: {
  projectId: number;
  path: string;
  lineStart: number | null;
  lineEnd: number | null;
  onClose: () => void;
}) {
  const [content, setContent] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getProjectFile(projectId, path)
      .then((r) => { if (!cancelled) setContent(r.content); })
      .catch((e) => { if (!cancelled) setError(e.message || String(e)); });
    return () => { cancelled = true; };
  }, [projectId, path]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 10000,
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 10, width: 'min(1100px, 95vw)', maxHeight: '88vh',
          overflow: 'hidden', display: 'flex', flexDirection: 'column',
        }}
      >
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div>
            <strong style={{ color: 'var(--text)' }}>{path}</strong>
            {lineStart && (
              <span style={{ color: 'var(--muted)', marginLeft: 8, fontSize: 12 }}>
                :{lineStart}{lineEnd && lineEnd !== lineStart ? `-${lineEnd}` : ''}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent', border: 'none', color: 'var(--muted)',
              fontSize: 20, cursor: 'pointer', lineHeight: 1, padding: 0,
            }}
            aria-label="Close"
          >&times;</button>
        </div>
        <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
          {error ? (
            <div style={{ color: 'var(--red)', fontSize: 13 }}>{error}</div>
          ) : (
            <CodeViewer
              content={content}
              path={path}
              lineStart={lineStart}
              lineEnd={lineEnd}
              contextLines={60}
            />
          )}
        </div>
      </div>
    </div>
  );
}

// ── Styles ──────────────────────────────────────────────────────────────────

function tryParse(json: string): any {
  try { return JSON.parse(json); } catch { return null; }
}

const labelStyle: React.CSSProperties = {
  color: 'var(--muted)', fontSize: 11, fontWeight: 600,
  textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4,
};

function btnStyle(color: string, small = false): React.CSSProperties {
  return {
    padding: small ? '6px 12px' : '8px 16px',
    border: `1px solid ${color}66`,
    borderRadius: 6, cursor: 'pointer',
    background: `${color}18`, color,
    fontSize: small ? 12 : 13, fontWeight: 600,
  };
}

function actionBtnStyle(color: string): React.CSSProperties {
  return {
    padding: '12px 32px', border: `1px solid ${color}`,
    borderRadius: 8, cursor: 'pointer',
    background: `${color}22`, color, fontSize: 15, fontWeight: 700,
    transition: 'all 0.15s',
  };
}

function smallBtnStyle(color: string): React.CSSProperties {
  return {
    padding: '4px 10px', border: `1px solid ${color}44`,
    borderRadius: 4, cursor: 'pointer',
    background: 'transparent', color, fontSize: 11, fontWeight: 600,
  };
}

const navBtnStyle: React.CSSProperties = {
  padding: '6px 14px', border: '1px solid var(--border)',
  borderRadius: 6, cursor: 'pointer',
  background: 'transparent', color: 'var(--muted)',
  fontSize: 12,
};

const toggleBtnStyle: React.CSSProperties = {
  padding: '4px 12px', border: 'none', cursor: 'pointer',
  color: 'var(--text)', fontSize: 12,
};

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '8px 12px', color: 'var(--muted)',
  fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5,
};

const tdStyle: React.CSSProperties = {
  padding: '10px 12px', verticalAlign: 'middle',
};

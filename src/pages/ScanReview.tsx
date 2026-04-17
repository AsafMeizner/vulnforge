import { useState, useEffect, useCallback } from 'react';
import {
  getScanFindings,
  acceptScanFinding,
  rejectScanFinding,
  bulkAcceptScanFindings,
  bulkRejectScanFindings,
  acceptAllScanFindings,
  aiReviewScanFindings,
  type ScanFinding,
  type ScanFindingCounts,
} from '@/lib/api';
import { SeverityBadge } from '@/components/Badge';
import { useToast } from '@/components/Toast';

interface ScanReviewProps {
  scanId: number;
  scanDbId?: number;
  projectName?: string;
  onClose: () => void;
  onAccepted?: (count: number) => void;
}

type FilterTab = 'pending' | 'auto_rejected' | 'accepted' | 'rejected';

export default function ScanReview({ scanId, projectName, onClose, onAccepted }: ScanReviewProps) {
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [counts, setCounts] = useState<ScanFindingCounts>({ pending: 0, accepted: 0, rejected: 0, auto_rejected: 0 });
  const [tab, setTab] = useState<FilterTab>('pending');
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const { toast } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getScanFindings({ scan_id: scanId });
      setCounts(result.counts);
      // Filter by current tab client-side (all findings loaded at once since counts are small post-scan)
      setFindings(result.data);
    } catch (err) {
      toast(`Failed to load scan findings: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [scanId, toast]);

  useEffect(() => { load(); }, [load]);

  // Reset selection when tab changes
  useEffect(() => { setSelected(new Set()); }, [tab]);

  const visibleFindings = findings.filter(f => {
    if (f.status !== tab) return false;
    if (severityFilter && f.severity !== severityFilter) return false;
    if (searchFilter) {
      const q = searchFilter.toLowerCase();
      if (!f.title.toLowerCase().includes(q) && !f.file.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const allSelected = visibleFindings.length > 0 && visibleFindings.every(f => selected.has(f.id));

  const toggleAll = () => {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(visibleFindings.map(f => f.id)));
    }
  };

  const toggleOne = (id: number) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleAcceptSelected = async () => {
    const ids = [...selected];
    if (ids.length === 0) return;
    try {
      const result = await bulkAcceptScanFindings(ids);
      toast(`Accepted ${result.accepted} finding(s) into Vulnerabilities`, 'success');
      onAccepted?.(result.accepted);
      await load();
    } catch (err) {
      toast(`Bulk accept failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const handleRejectSelected = async () => {
    const ids = [...selected];
    if (ids.length === 0) return;
    try {
      const result = await bulkRejectScanFindings(ids, 'Manually rejected');
      toast(`Rejected ${result.rejected} finding(s)`, 'success');
      await load();
    } catch (err) {
      toast(`Bulk reject failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const handleAcceptAll = async () => {
    try {
      const result = await acceptAllScanFindings(scanId);
      toast(`Accepted all ${result.accepted} pending findings`, 'success');
      onAccepted?.(result.accepted);
      await load();
    } catch (err) {
      toast(`Accept all failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const handleAIReview = async () => {
    setAiLoading(true);
    try {
      const result = await aiReviewScanFindings(scanId);
      toast(`AI review: ${result.accepted} accepted, ${result.rejected} rejected`, 'success');
      onAccepted?.(result.accepted);
      await load();
    } catch (err) {
      toast(`AI review failed: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setAiLoading(false);
    }
  };

  const handleAcceptOne = async (id: number) => {
    try {
      await acceptScanFinding(id);
      toast('Finding accepted into Vulnerabilities', 'success');
      onAccepted?.(1);
      await load();
    } catch (err) {
      toast(`Accept failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const handleRejectOne = async (id: number) => {
    try {
      await rejectScanFinding(id, 'Manually rejected');
      toast('Finding rejected', 'success');
      await load();
    } catch (err) {
      toast(`Reject failed: ${err instanceof Error ? err.message : err}`, 'error');
    }
  };

  const confidenceColor: Record<string, string> = {
    High: 'var(--green)',
    Medium: 'var(--yellow)',
    Low: 'var(--muted)',
  };

  const tabLabel = (t: FilterTab) => {
    const c = counts[t];
    return `${t === 'auto_rejected' ? 'Auto-rejected' : t.charAt(0).toUpperCase() + t.slice(1)} (${c})`;
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.7)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 16,
    }}>
      <div style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 10,
        width: '100%',
        maxWidth: 1000,
        maxHeight: '90vh',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '14px 18px',
          borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text)' }}>
              Review Scan Findings
            </div>
            <div style={{ fontSize: 12, color: 'var(--muted)', marginTop: 2 }}>
              {projectName && <span>{projectName} - </span>}
              <span style={{ color: 'var(--green)' }}>{counts.pending} pending</span>
              {counts.auto_rejected > 0 && (
                <span style={{ color: 'var(--muted)', marginLeft: 8 }}>
                  {counts.auto_rejected} auto-rejected as false positives
                </span>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: 18, lineHeight: 1, padding: '2px 6px' }}
          >
            x
          </button>
        </div>

        {/* Action bar */}
        <div style={{
          display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center',
          padding: '10px 18px',
          borderBottom: '1px solid var(--border)',
          flexShrink: 0,
          background: 'var(--bg)',
        }}>
          {tab === 'pending' && (
            <>
              <button onClick={handleAcceptAll} style={actionBtn('var(--green)')}>
                Accept All ({counts.pending})
              </button>
              <button
                onClick={handleAcceptSelected}
                disabled={selected.size === 0}
                style={actionBtn('var(--blue)', selected.size === 0)}
              >
                Accept Selected ({selected.size})
              </button>
              <button
                onClick={handleRejectSelected}
                disabled={selected.size === 0}
                style={actionBtn('var(--red)', selected.size === 0)}
              >
                Reject Selected ({selected.size})
              </button>
              <button
                onClick={handleAIReview}
                disabled={aiLoading || counts.pending === 0}
                style={actionBtn('var(--purple)', aiLoading || counts.pending === 0)}
              >
                {aiLoading ? 'AI Reviewing...' : 'AI Review'}
              </button>
            </>
          )}

          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <input
              type="text"
              placeholder="Search title or file..."
              value={searchFilter}
              onChange={e => setSearchFilter(e.target.value)}
              style={filterInput}
            />
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} style={filterSel}>
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        {/* Tabs */}
        <div style={{
          display: 'flex', gap: 0,
          borderBottom: '1px solid var(--border)',
          flexShrink: 0,
          paddingLeft: 18,
        }}>
          {(['pending', 'auto_rejected', 'accepted', 'rejected'] as FilterTab[]).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              style={{
                background: 'none',
                border: 'none',
                borderBottom: tab === t ? '2px solid var(--blue)' : '2px solid transparent',
                color: tab === t ? 'var(--text)' : 'var(--muted)',
                fontWeight: tab === t ? 600 : 400,
                fontSize: 12,
                cursor: 'pointer',
                padding: '8px 14px',
                transition: 'color 0.15s',
              }}
            >
              {tabLabel(t)}
            </button>
          ))}
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              Loading findings...
            </div>
          ) : visibleFindings.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              {tab === 'pending'
                ? 'No pending findings. All have been reviewed.'
                : `No ${tab.replace('_', ' ')} findings.`}
            </div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead style={{ position: 'sticky', top: 0, background: 'var(--surface)', zIndex: 1 }}>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {tab === 'pending' && (
                    <th style={thStyle}>
                      <input
                        type="checkbox"
                        checked={allSelected}
                        onChange={toggleAll}
                        style={{ accentColor: 'var(--blue)', cursor: 'pointer' }}
                      />
                    </th>
                  )}
                  <th style={{ ...thStyle, textAlign: 'left' }}>Severity</th>
                  <th style={{ ...thStyle, textAlign: 'left' }}>Title</th>
                  <th style={{ ...thStyle, textAlign: 'left' }}>File</th>
                  <th style={{ ...thStyle, textAlign: 'left' }}>Tool</th>
                  <th style={{ ...thStyle, textAlign: 'left' }}>Confidence</th>
                  {tab === 'auto_rejected' && (
                    <th style={{ ...thStyle, textAlign: 'left' }}>Reason</th>
                  )}
                  {tab === 'pending' && (
                    <th style={{ ...thStyle, textAlign: 'left' }}>Actions</th>
                  )}
                </tr>
              </thead>
              <tbody>
                {visibleFindings.map(f => (
                  <tr
                    key={f.id}
                    style={{
                      borderBottom: '1px solid var(--border)',
                      background: selected.has(f.id) ? 'var(--blue)11' : undefined,
                    }}
                  >
                    {tab === 'pending' && (
                      <td style={tdStyle}>
                        <input
                          type="checkbox"
                          checked={selected.has(f.id)}
                          onChange={() => toggleOne(f.id)}
                          style={{ accentColor: 'var(--blue)', cursor: 'pointer' }}
                        />
                      </td>
                    )}
                    <td style={tdStyle}>
                      <SeverityBadge severity={f.severity as any} />
                    </td>
                    <td style={{ ...tdStyle, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text)' }}>
                      {f.title}
                    </td>
                    <td style={{ ...tdStyle, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--muted)', fontFamily: 'monospace', fontSize: 11 }}>
                      {f.file ? (
                        <>
                          {f.file}
                          {f.line_start ? <span style={{ color: 'var(--blue)' }}>:{f.line_start}</span> : null}
                        </>
                      ) : '-'}
                    </td>
                    <td style={{ ...tdStyle, color: 'var(--muted)', fontFamily: 'monospace', fontSize: 11 }}>
                      {f.tool_name || '-'}
                    </td>
                    <td style={{ ...tdStyle }}>
                      <span style={{
                        color: confidenceColor[f.confidence] || 'var(--muted)',
                        fontSize: 11,
                        fontWeight: 600,
                      }}>
                        {f.confidence}
                      </span>
                    </td>
                    {tab === 'auto_rejected' && (
                      <td style={{ ...tdStyle, color: 'var(--muted)', fontSize: 11, fontStyle: 'italic' }}>
                        {f.rejection_reason || '-'}
                      </td>
                    )}
                    {tab === 'pending' && (
                      <td style={{ ...tdStyle, whiteSpace: 'nowrap' }}>
                        <button
                          onClick={() => handleAcceptOne(f.id)}
                          style={rowBtn('var(--green)')}
                        >
                          Accept
                        </button>
                        <button
                          onClick={() => handleRejectOne(f.id)}
                          style={{ ...rowBtn('var(--red)'), marginLeft: 4 }}
                        >
                          Reject
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: '10px 18px',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'flex-end',
          flexShrink: 0,
          background: 'var(--bg)',
        }}>
          <button onClick={onClose} style={actionBtn('var(--muted)')}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Styles ─────────────────────────────────────────────────────────────────

function actionBtn(color: string, disabled = false): React.CSSProperties {
  return {
    background: disabled ? 'var(--surface-2)' : `${color}22`,
    border: `1px solid ${disabled ? 'var(--border)' : color}`,
    borderRadius: 5,
    padding: '5px 12px',
    color: disabled ? 'var(--muted)' : color,
    fontSize: 12,
    fontWeight: 600,
    cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled ? 0.6 : 1,
    transition: 'opacity 0.15s',
  };
}

function rowBtn(color: string): React.CSSProperties {
  return {
    background: 'none',
    border: `1px solid ${color}`,
    borderRadius: 4,
    padding: '2px 8px',
    color,
    fontSize: 11,
    cursor: 'pointer',
  };
}

const thStyle: React.CSSProperties = {
  padding: '8px 12px',
  color: 'var(--muted)',
  fontWeight: 500,
  fontSize: 10,
  textTransform: 'uppercase',
  letterSpacing: '0.4px',
  whiteSpace: 'nowrap',
};

const tdStyle: React.CSSProperties = {
  padding: '8px 12px',
  verticalAlign: 'middle',
};

const filterInput: React.CSSProperties = {
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '5px 10px',
  color: 'var(--text)',
  fontSize: 12,
  outline: 'none',
  width: 180,
};

const filterSel: React.CSSProperties = {
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '5px 8px',
  color: 'var(--text)',
  fontSize: 12,
  outline: 'none',
  cursor: 'pointer',
};

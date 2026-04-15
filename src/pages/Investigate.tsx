import { useState, useEffect, useCallback } from 'react';
import {
  listInvestigations,
  getInvestigation,
  startInvestigation,
  proposeNextStep,
  executeInvestigateStep,
  rejectInvestigateStep,
  cancelInvestigation,
  type InvestigateSession,
  type InvestigateStep,
} from '@/lib/api';
import { useToast } from '@/components/Toast';

function statusColor(status: string): string {
  switch (status) {
    case 'active': return 'var(--blue)';
    case 'completed': return 'var(--green)';
    case 'cancelled': return 'var(--muted)';
    case 'executed': return 'var(--green)';
    case 'pending': return 'var(--yellow)';
    case 'approved': return 'var(--blue)';
    case 'rejected': return 'var(--muted)';
    case 'failed': return 'var(--red)';
    default: return 'var(--muted)';
  }
}

export default function Investigate() {
  const { toast } = useToast() as { toast: (msg: string, type?: 'success' | 'error' | 'info') => void };
  const [sessions, setSessions] = useState<InvestigateSession[]>([]);
  const [selected, setSelected] = useState<InvestigateSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [proposing, setProposing] = useState(false);
  const [newModalOpen, setNewModalOpen] = useState(false);

  const loadSessions = useCallback(async () => {
    setLoading(true);
    try {
      const res = await listInvestigations();
      setSessions(res.data);
    } catch (err: any) {
      toast(`Failed to load: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const refreshSelected = useCallback(async () => {
    if (!selected) return;
    try {
      const updated = await getInvestigation(selected.id);
      setSelected(updated);
    } catch { /* may be cancelled */ }
  }, [selected]);

  useEffect(() => { loadSessions(); }, [loadSessions]);

  const handlePropose = async () => {
    if (!selected) return;
    setProposing(true);
    try {
      await proposeNextStep(selected.id);
      await refreshSelected();
      toast('Next step proposed', 'success');
    } catch (err: any) {
      toast(`Propose failed: ${err.message}`, 'error');
    } finally {
      setProposing(false);
    }
  };

  const handleExecute = async (stepIndex: number) => {
    if (!selected) return;
    try {
      await executeInvestigateStep(selected.id, stepIndex);
      await refreshSelected();
      toast('Step executed', 'success');
    } catch (err: any) {
      toast(`Execute failed: ${err.message}`, 'error');
    }
  };

  const handleReject = async (stepIndex: number) => {
    if (!selected) return;
    const reason = prompt('Reason for rejecting?') || undefined;
    try {
      await rejectInvestigateStep(selected.id, stepIndex, reason);
      await refreshSelected();
      toast('Step rejected', 'info');
    } catch (err: any) {
      toast(err.message, 'error');
    }
  };

  const handleCancel = async () => {
    if (!selected) return;
    if (!confirm('Cancel this investigation?')) return;
    try {
      await cancelInvestigation(selected.id);
      await refreshSelected();
      loadSessions();
    } catch (err: any) {
      toast(err.message, 'error');
    }
  };

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16, height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>AI Investigation</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            Interactive, step-gated AI investigation. Each proposed step requires your approval.
          </p>
        </div>
        <button onClick={() => setNewModalOpen(true)} style={{
          background: 'var(--purple)', color: '#fff', border: 'none',
          borderRadius: 6, padding: '8px 16px', fontSize: 13, fontWeight: 700, cursor: 'pointer',
        }}>+ New Investigation</button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16, flex: 1, overflow: 'hidden' }}>
        {/* Session list */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'auto' }}>
          {loading ? (
            <div style={{ padding: 20, color: 'var(--muted)', fontSize: 13, textAlign: 'center' }}>Loading...</div>
          ) : sessions.length === 0 ? (
            <div style={{ padding: 40, color: 'var(--muted)', fontSize: 13, textAlign: 'center' }}>
              No investigations yet.
            </div>
          ) : (
            sessions.map(s => (
              <div
                key={s.id}
                onClick={() => setSelected(s)}
                style={{
                  padding: '12px 14px',
                  borderBottom: '1px solid var(--border)',
                  background: selected?.id === s.id ? 'var(--surface-2)' : 'transparent',
                  cursor: 'pointer',
                  borderLeft: `3px solid ${statusColor(s.status)}`,
                }}
              >
                <div style={{ color: 'var(--text)', fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                  {s.goal.slice(0, 60)}
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{
                    padding: '2px 8px', borderRadius: 10,
                    background: `${statusColor(s.status)}22`, color: statusColor(s.status),
                    fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                  }}>{s.status}</span>
                  <span style={{ color: 'var(--muted)', fontSize: 11 }}>{s.steps.length} steps</span>
                  {s.finding_id && <span style={{ color: 'var(--muted)', fontSize: 11 }}>#{s.finding_id}</span>}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Session detail */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {!selected ? (
            <div style={{ padding: 40, color: 'var(--muted)', fontSize: 13, textAlign: 'center', margin: 'auto' }}>
              Select an investigation to view steps.
            </div>
          ) : (
            <>
              {/* Header */}
              <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <h3 style={{ margin: 0, color: 'var(--text)', fontSize: 15 }}>{selected.goal}</h3>
                  <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 4 }}>
                    Session {selected.id} · {selected.steps.length} steps
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  {selected.status === 'active' && (
                    <>
                      <button onClick={handlePropose} disabled={proposing} style={{
                        padding: '8px 14px', background: 'var(--blue)', color: '#fff',
                        border: 'none', borderRadius: 5, fontSize: 12, fontWeight: 600, cursor: 'pointer',
                        opacity: proposing ? 0.5 : 1,
                      }}>{proposing ? 'Thinking...' : 'Propose Next Step'}</button>
                      <button onClick={handleCancel} style={{
                        padding: '8px 14px', background: 'transparent', color: 'var(--muted)',
                        border: '1px solid var(--border)', borderRadius: 5, fontSize: 12, cursor: 'pointer',
                      }}>Cancel</button>
                    </>
                  )}
                </div>
              </div>

              {/* Steps */}
              <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
                {selected.steps.length === 0 ? (
                  <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
                    No steps yet. Click "Propose Next Step" to begin.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    {selected.steps.map(step => (
                      <StepCard
                        key={step.index}
                        step={step}
                        onExecute={() => handleExecute(step.index)}
                        onReject={() => handleReject(step.index)}
                      />
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>

      {newModalOpen && <NewSessionModal
        onClose={() => setNewModalOpen(false)}
        onCreated={(s) => {
          setNewModalOpen(false);
          setSelected(s);
          loadSessions();
        }}
      />}
    </div>
  );
}

function StepCard({ step, onExecute, onReject }: {
  step: InvestigateStep;
  onExecute: () => void;
  onReject: () => void;
}) {
  return (
    <div style={{
      background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 8,
      padding: 14, borderLeft: `3px solid ${statusColor(step.status)}`,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <span style={{
          padding: '2px 8px', borderRadius: 10,
          background: `${statusColor(step.status)}22`, color: statusColor(step.status),
          fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
        }}>{step.status}</span>
        <span style={{ color: 'var(--muted)', fontSize: 11 }}>Step {step.index + 1}</span>
        <span style={{ color: 'var(--blue)', fontSize: 11, fontFamily: 'monospace', fontWeight: 600 }}>
          {step.proposed_action}
        </span>
      </div>

      <div style={{ color: 'var(--text)', fontSize: 13, marginBottom: 8, lineHeight: 1.5 }}>
        {step.thought}
      </div>

      {step.proposed_args && Object.keys(step.proposed_args).length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 2 }}>Args</div>
          <pre style={{
            margin: 0, padding: 8, background: 'var(--surface-2)', borderRadius: 4,
            fontSize: 11, color: 'var(--text)', fontFamily: 'monospace', overflow: 'auto',
          }}>{JSON.stringify(step.proposed_args, null, 2)}</pre>
        </div>
      )}

      {step.result && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ fontSize: 10, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 2 }}>Result</div>
          <pre style={{
            margin: 0, padding: 8, background: '#000', color: '#0f0',
            borderRadius: 4, fontSize: 11, fontFamily: 'monospace',
            overflow: 'auto', maxHeight: 240, whiteSpace: 'pre-wrap',
          }}>{step.result}</pre>
        </div>
      )}

      {step.status === 'pending' && (
        <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
          <button onClick={onExecute} style={{
            padding: '6px 14px', background: 'var(--green)', color: '#000',
            border: 'none', borderRadius: 4, fontSize: 12, fontWeight: 600, cursor: 'pointer',
          }}>Approve &amp; Execute</button>
          <button onClick={onReject} style={{
            padding: '6px 14px', background: 'var(--red)22', color: 'var(--red)',
            border: '1px solid var(--red)44', borderRadius: 4, fontSize: 12, cursor: 'pointer',
          }}>Reject</button>
        </div>
      )}
    </div>
  );
}

function NewSessionModal({ onClose, onCreated }: {
  onClose: () => void;
  onCreated: (s: InvestigateSession) => void;
}) {
  const { toast } = useToast() as { toast: (msg: string, type?: 'success' | 'error' | 'info') => void };
  const [goal, setGoal] = useState('');
  const [findingId, setFindingId] = useState('');

  const handleCreate = async () => {
    if (!goal.trim()) { toast('Goal required', 'error'); return; }
    try {
      const s = await startInvestigation({
        goal: goal.trim(),
        finding_id: findingId ? Number(findingId) : undefined,
      });
      onCreated(s);
    } catch (err: any) {
      toast(err.message, 'error');
    }
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, background: '#0008', zIndex: 1000,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 10,
        padding: 24, width: '90%', maxWidth: 560,
      }} onClick={e => e.stopPropagation()}>
        <h3 style={{ margin: '0 0 16px', color: 'var(--text)' }}>New Investigation</h3>

        <div style={{ marginBottom: 12 }}>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
            Goal / Question
          </label>
          <textarea value={goal} onChange={e => setGoal(e.target.value)} autoFocus rows={4}
            placeholder="e.g. Is the UAF in parseHeader actually reachable from pre-auth input?"
            style={{
              width: '100%', padding: 10, background: 'var(--bg)',
              border: '1px solid var(--border)', borderRadius: 5, color: 'var(--text)',
              fontSize: 13, outline: 'none', resize: 'vertical', boxSizing: 'border-box', fontFamily: 'inherit',
            }}
          />
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
            Link to finding (optional)
          </label>
          <input value={findingId} onChange={e => setFindingId(e.target.value)} placeholder="finding ID"
            style={{
              width: '100%', padding: '8px 10px', background: 'var(--bg)',
              border: '1px solid var(--border)', borderRadius: 5, color: 'var(--text)',
              fontSize: 13, outline: 'none', boxSizing: 'border-box',
            }}
          />
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{
            padding: '8px 16px', background: 'var(--surface-2)', border: '1px solid var(--border)',
            borderRadius: 5, color: 'var(--text)', fontSize: 13, cursor: 'pointer',
          }}>Cancel</button>
          <button onClick={handleCreate} style={{
            padding: '8px 20px', background: 'var(--purple)', color: '#fff',
            border: 'none', borderRadius: 5, fontSize: 13, fontWeight: 700, cursor: 'pointer',
          }}>Start</button>
        </div>
      </div>
    </div>
  );
}

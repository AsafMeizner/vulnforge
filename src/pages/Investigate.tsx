import { useState, useEffect, useCallback } from 'react';
import {
  listInvestigations,
  getInvestigation,
  startInvestigation,
  proposeNextStep,
  addManualInvestigateStep,
  executeInvestigateStep,
  rejectInvestigateStep,
  cancelInvestigation,
  type InvestigateSession,
  type InvestigateStep,
} from '@/lib/api';
import { useToast } from '@/components/Toast';
import { FindingCombo } from '@/components/FindingCombo';

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
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [sessions, setSessions] = useState<InvestigateSession[]>([]);
  const [selected, setSelected] = useState<InvestigateSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [proposing, setProposing] = useState(false);
  // "+ Add Step Manually" modal open state. When true, renders a
  // small form at the bottom of the component where the user can
  // type a free-form step without touching AI.
  const [addManualOpen, setAddManualOpen] = useState(false);
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

  const handleAddManualStep = async (thought: string, action?: string) => {
    if (!selected) return;
    try {
      await addManualInvestigateStep(selected.id, {
        thought,
        action: action?.trim() || 'note',
      });
      await refreshSelected();
      toast('Step added', 'success');
      setAddManualOpen(false);
    } catch (err: any) {
      toast(`Add step failed: ${err.message}`, 'error');
    }
  };

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
                      }} title="Ask the AI to propose the next step (requires a provider)">
                        {proposing ? 'Thinking...' : 'Propose Next Step (AI)'}
                      </button>
                      <button onClick={() => setAddManualOpen(true)} style={{
                        padding: '8px 14px', background: 'var(--surface-2)', color: 'var(--text)',
                        border: '1px solid var(--border)', borderRadius: 5, fontSize: 12, fontWeight: 600, cursor: 'pointer',
                      }} title="Write your own next step without any AI">
                        + Add Step Manually
                      </button>
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
                    No steps yet. Click <strong>Propose Next Step</strong> to have AI suggest one,
                    or <strong>+ Add Step Manually</strong> to write your own.
                    <br />AI is optional — you can drive the whole investigation by hand.
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

      {/* "Add step manually" modal - free-form thought + optional
          action name. No AI call, no provider required. */}
      {addManualOpen && (
        <ManualStepModal
          onClose={() => setAddManualOpen(false)}
          onSubmit={handleAddManualStep}
        />
      )}
    </div>
  );
}

function ManualStepModal({ onClose, onSubmit }: {
  onClose: () => void;
  onSubmit: (thought: string, action?: string) => Promise<void>;
}) {
  const [thought, setThought] = useState('');
  const [action, setAction] = useState('');
  const [saving, setSaving] = useState(false);
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
          borderRadius: 10, width: 'min(640px, 95vw)', padding: 20,
          display: 'flex', flexDirection: 'column', gap: 14,
        }}
      >
        <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--text)' }}>
          Add step manually
        </div>
        <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>
          Write your own reasoning about what to do next. No AI call is made.
          Leave "Action" blank to save it as a free-form note, or enter an action
          name like <code>read_file</code>, <code>find_callers</code>,
          <code>git_blame</code>, or <code>run_tool</code> to make the step
          executable later.
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
            Thought / reasoning
          </label>
          <textarea
            value={thought}
            onChange={(e) => setThought(e.target.value)}
            placeholder="e.g. The malloc() on line 3932 takes a uint64_t cast to size_t. On 32-bit this truncates..."
            autoFocus
            style={{
              width: '100%', minHeight: 120, resize: 'vertical',
              padding: '8px 10px', background: 'var(--bg)',
              border: '1px solid var(--border)', borderRadius: 5, color: 'var(--text)',
              fontSize: 13, outline: 'none', boxSizing: 'border-box',
              fontFamily: 'inherit', lineHeight: 1.5,
            }}
          />
        </div>
        <div>
          <label style={{ fontSize: 11, color: 'var(--muted)', display: 'block', marginBottom: 4 }}>
            Action (optional) — leave blank for a plain note
          </label>
          <input
            value={action}
            onChange={(e) => setAction(e.target.value)}
            placeholder="read_file / find_callers / run_tool / ..."
            style={{
              width: '100%', padding: '7px 10px', background: 'var(--bg)',
              border: '1px solid var(--border)', borderRadius: 5, color: 'var(--text)',
              fontSize: 13, outline: 'none', boxSizing: 'border-box',
              fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace',
            }}
          />
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} disabled={saving} style={{
            padding: '8px 16px', background: 'var(--surface-2)', border: '1px solid var(--border)',
            borderRadius: 5, color: 'var(--text)', fontSize: 13, cursor: 'pointer',
          }}>Cancel</button>
          <button
            onClick={async () => {
              if (!thought.trim()) return;
              setSaving(true);
              try { await onSubmit(thought.trim(), action); }
              finally { setSaving(false); }
            }}
            disabled={saving || !thought.trim()}
            style={{
              padding: '8px 18px', background: 'var(--green)', color: '#fff',
              border: 'none', borderRadius: 5, fontSize: 13, fontWeight: 700,
              cursor: (saving || !thought.trim()) ? 'not-allowed' : 'pointer',
              opacity: (saving || !thought.trim()) ? 0.6 : 1,
            }}
          >{saving ? 'Saving...' : 'Add Step'}</button>
        </div>
      </div>
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
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [goal, setGoal] = useState('');
  // Store the selected finding's numeric id. Null means "not linked."
  const [findingId, setFindingId] = useState<number | null>(null);

  const handleCreate = async () => {
    if (!goal.trim()) { toast('Goal required', 'error'); return; }
    try {
      const s = await startInvestigation({
        goal: goal.trim(),
        finding_id: findingId ?? undefined,
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
          {/* Searchable combobox - type a few letters of the finding
              title or paste the id. Replaces the old raw-number input
              which required users to remember numeric ids. */}
          <FindingCombo
            value={findingId}
            onChange={setFindingId}
            placeholder="Search findings by title or paste id..."
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

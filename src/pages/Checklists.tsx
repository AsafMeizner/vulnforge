import { useState, useEffect, useCallback } from 'react';
import {
  getProjects, apiFetch,
  createChecklist, deleteChecklist,
  createChecklistItem, deleteChecklistItem,
  type Project,
} from '@/lib/api';
import { useToast } from '@/components/Toast';

// Use the shared apiFetch helper so this page works in packaged Electron,
// vite dev, and server-served modes (including dynamic server port).
async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await apiFetch(path.startsWith('/api') ? path : `/api${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
  return res.json();
}

interface ChecklistSummary {
  id: number;
  name: string;
  category?: string;
  total_items: number;
  verified_count: number;
  progress_pct: number;
}

interface ChecklistItem {
  id: number;
  checklist_id: number;
  category?: string;
  title: string;
  description?: string;
  severity?: string;
  tool_names?: string;
  verified: number;
  vuln_id?: number;
  notes?: string;
}

interface ChecklistDetail extends ChecklistSummary {
  items: ChecklistItem[];
}

export default function Checklists() {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [checklists, setChecklists] = useState<ChecklistSummary[]>([]);
  const [selected, setSelected] = useState<ChecklistDetail | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<number | ''>('');
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  // Modals: null = closed. For-a-checklist add-item state lives on
  // `selected` itself so one state is enough to drive both.
  const [newChecklistOpen, setNewChecklistOpen] = useState(false);
  const [addItemOpen, setAddItemOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [clRes, projRes] = await Promise.all([
        req<{ data: ChecklistSummary[] }>('/checklists'),
        getProjects(),
      ]);
      setChecklists(clRes.data);
      setProjects(projRes);
    } catch (err: any) {
      toast(`Load failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const loadChecklist = async (id: number) => {
    try {
      const detail = await req<ChecklistDetail>(`/checklists/${id}`);
      setSelected(detail);
    } catch (err: any) {
      toast(`Failed: ${err.message}`, 'error');
    }
  };

  const handleVerify = async () => {
    if (!selected || !projectId) {
      toast('Select a checklist and a project', 'error');
      return;
    }
    setVerifying(true);
    try {
      await req<any>(`/checklists/${selected.id}/verify`, {
        method: 'POST',
        body: JSON.stringify({ project_id: Number(projectId) }),
      });
      toast('Verification complete', 'success');
      loadChecklist(selected.id);
      load();
    } catch (err: any) {
      toast(`Verify failed: ${err.message}`, 'error');
    } finally {
      setVerifying(false);
    }
  };

  const toggleItem = async (item: ChecklistItem) => {
    try {
      await req<any>(`/checklists/items/${item.id}`, {
        method: 'PUT',
        body: JSON.stringify({ verified: item.verified ? 0 : 1 }),
      });
      if (selected) loadChecklist(selected.id);
      load();
    } catch (err: any) {
      toast(`Update failed: ${err.message}`, 'error');
    }
  };

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16, height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Security Checklists</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            Audit checklists stored in the database. Select a project and auto-verify items against its findings.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select value={projectId} onChange={e => setProjectId(e.target.value ? Number(e.target.value) : '')} style={selectStyle}>
            <option value="">Select project...</option>
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <button
            onClick={handleVerify}
            disabled={verifying || !selected || !projectId}
            style={{
              padding: '8px 14px', background: verifying ? 'var(--muted)' : 'var(--green)',
              color: '#000', border: 'none', borderRadius: 6, fontSize: 12,
              fontWeight: 700, cursor: verifying ? 'wait' : 'pointer',
              opacity: (!selected || !projectId) ? 0.4 : 1,
            }}
          >
            {verifying ? 'Verifying...' : 'Auto-Verify Against Project'}
          </button>
          <button
            onClick={() => setNewChecklistOpen(true)}
            style={{
              padding: '8px 14px', background: 'var(--blue)',
              color: '#fff', border: 'none', borderRadius: 6, fontSize: 12,
              fontWeight: 700, cursor: 'pointer',
            }}
          >
            + New Checklist
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 16, flex: 1, overflow: 'hidden' }}>
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'auto' }}>
          {loading ? (
            <div style={{ padding: 20, textAlign: 'center', color: 'var(--muted)' }}>Loading...</div>
          ) : checklists.length === 0 ? (
            <div style={{ padding: 30, textAlign: 'center', color: 'var(--muted)', fontSize: 13, display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center' }}>
              <div>No checklists yet.</div>
              <button
                onClick={() => setNewChecklistOpen(true)}
                style={{
                  padding: '8px 16px', fontSize: 12, fontWeight: 600,
                  border: '1px solid var(--blue)44', borderRadius: 5,
                  background: 'var(--blue)22', color: 'var(--blue)',
                  cursor: 'pointer',
                }}
              >
                + Create your first checklist
              </button>
            </div>
          ) : (
            checklists.map(cl => (
              <div
                key={cl.id}
                role="button"
                tabIndex={0}
                aria-pressed={selected?.id === cl.id}
                aria-label={`Open checklist: ${cl.name}`}
                onClick={() => loadChecklist(cl.id)}
                onKeyDown={e => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    loadChecklist(cl.id);
                  }
                }}
                style={{
                  padding: '14px 16px', borderBottom: '1px solid var(--border)',
                  background: selected?.id === cl.id ? 'var(--surface-2)' : 'transparent', cursor: 'pointer',
                }}>
                <div style={{ color: 'var(--text)', fontSize: 14, fontWeight: 600, marginBottom: 6 }}>{cl.name}</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{ flex: 1, height: 6, background: 'var(--bg)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', borderRadius: 3, width: `${cl.progress_pct}%`,
                      background: cl.progress_pct === 100 ? 'var(--green)' : cl.progress_pct > 50 ? 'var(--yellow)' : 'var(--orange)',
                      transition: 'width 0.3s',
                    }} />
                  </div>
                  <span style={{ color: 'var(--muted)', fontSize: 11 }}>{cl.verified_count}/{cl.total_items}</span>
                </div>
                {cl.category && <span style={{ fontSize: 10, color: 'var(--muted)', marginTop: 4, display: 'block' }}>{cl.category}</span>}
              </div>
            ))
          )}
        </div>

        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'auto' }}>
          {!selected ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              Select a checklist to view items.
            </div>
          ) : (
            <div>
              <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, color: 'var(--text)', fontSize: 16, flex: 1 }}>{selected.name}</h3>
                <span style={{
                  padding: '4px 12px', borderRadius: 10, fontSize: 12, fontWeight: 600,
                  background: selected.progress_pct === 100 ? 'var(--green)22' : 'var(--yellow)22',
                  color: selected.progress_pct === 100 ? 'var(--green)' : 'var(--yellow)',
                }}>
                  {selected.progress_pct}% complete
                </span>
                <button
                  onClick={() => setAddItemOpen(true)}
                  style={{
                    padding: '5px 12px', fontSize: 11, fontWeight: 600,
                    border: '1px solid var(--border)', borderRadius: 4,
                    background: 'var(--surface-2)', color: 'var(--text)', cursor: 'pointer',
                  }}
                >
                  + Add item
                </button>
                <button
                  onClick={async () => {
                    if (!window.confirm(`Delete checklist "${selected.name}" and all ${selected.total_items} items? This cannot be undone.`)) return;
                    try {
                      await deleteChecklist(selected.id);
                      setSelected(null);
                      await load();
                      toast('Checklist deleted', 'success');
                    } catch (err: any) {
                      toast(`Delete failed: ${err.message || err}`, 'error');
                    }
                  }}
                  style={{
                    padding: '5px 12px', fontSize: 11, fontWeight: 600,
                    border: '1px solid var(--red)44', borderRadius: 4,
                    background: 'transparent', color: 'var(--red)', cursor: 'pointer',
                  }}
                >
                  Delete
                </button>
              </div>
              <div style={{ padding: '8px 0' }}>
                {selected.items.map(item => {
                  const sevColor = item.severity === 'Critical' ? 'var(--red)' : item.severity === 'High' ? 'var(--orange)' : item.severity === 'Medium' ? 'var(--yellow)' : 'var(--muted)';
                  return (
                    <div key={item.id} style={{
                      padding: '12px 18px', borderBottom: '1px solid var(--border)',
                      display: 'flex', gap: 12, alignItems: 'flex-start',
                      opacity: item.verified ? 0.7 : 1,
                    }}>
                      <input type="checkbox" checked={!!item.verified} onChange={() => toggleItem(item)}
                        style={{ marginTop: 3, accentColor: 'var(--green)', cursor: 'pointer' }} />
                      <div style={{ flex: 1 }}>
                        <div style={{ color: 'var(--text)', fontSize: 13, textDecoration: item.verified ? 'line-through' : 'none' }}>
                          {item.title}
                        </div>
                        {item.description && (
                          <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 3, lineHeight: 1.5 }}>{item.description}</div>
                        )}
                        <div style={{ display: 'flex', gap: 8, marginTop: 4, alignItems: 'center' }}>
                          {item.severity && <span style={{ fontSize: 10, color: sevColor, fontWeight: 600 }}>{item.severity}</span>}
                          {item.category && <span style={{ fontSize: 10, color: 'var(--muted)', background: 'var(--bg)', padding: '1px 6px', borderRadius: 3 }}>{item.category}</span>}
                          {item.vuln_id && <span style={{ fontSize: 10, color: 'var(--blue)', fontFamily: 'monospace' }}>linked to #{item.vuln_id}</span>}
                        </div>
                      </div>
                      <button
                        onClick={async () => {
                          if (!window.confirm(`Delete item "${item.title.slice(0, 40)}"?`)) return;
                          try {
                            await deleteChecklistItem(item.id);
                            await loadChecklist(selected.id);
                            await load();
                          } catch (err: any) {
                            toast(`Delete failed: ${err.message || err}`, 'error');
                          }
                        }}
                        title="Delete this item"
                        style={{
                          background: 'transparent', border: 'none',
                          color: 'var(--muted)', fontSize: 16, lineHeight: 1,
                          cursor: 'pointer', padding: 0,
                        }}
                      >&times;</button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* New checklist modal */}
      {newChecklistOpen && (
        <NewChecklistModal
          onClose={() => setNewChecklistOpen(false)}
          onCreated={async () => { setNewChecklistOpen(false); await load(); }}
        />
      )}

      {/* Add item modal - only openable while a checklist is selected */}
      {addItemOpen && selected && (
        <NewItemModal
          checklist={selected}
          onClose={() => setAddItemOpen(false)}
          onCreated={async () => {
            setAddItemOpen(false);
            await loadChecklist(selected.id);
            await load();
          }}
        />
      )}
    </div>
  );
}

function NewChecklistModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void | Promise<void> }) {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [name, setName] = useState('');
  const [category, setCategory] = useState('');
  const [sourceUrl, setSourceUrl] = useState('');
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    if (!name.trim()) { toast('Name required', 'error'); return; }
    setSaving(true);
    try {
      await createChecklist({
        name: name.trim(),
        category: category.trim() || undefined,
        source_url: sourceUrl.trim() || undefined,
      });
      toast('Checklist created', 'success');
      await onCreated();
    } catch (err: any) {
      toast(`Create failed: ${err.message || err}`, 'error');
    } finally { setSaving(false); }
  };

  return <ChecklistFormShell title="New Checklist" onClose={onClose} onSubmit={submit} saving={saving} submitLabel="Create" submitDisabled={!name.trim()}>
    <FieldLabel>Name (required)</FieldLabel>
    <input value={name} onChange={(e) => setName(e.target.value)} autoFocus placeholder="e.g. OWASP API Top 10" style={modalInputStyle} />
    <FieldLabel>Category (optional)</FieldLabel>
    <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="e.g. API Security" style={modalInputStyle} />
    <FieldLabel>Source URL (optional)</FieldLabel>
    <input value={sourceUrl} onChange={(e) => setSourceUrl(e.target.value)} placeholder="https://..." style={modalInputStyle} />
  </ChecklistFormShell>;
}

function NewItemModal({ checklist, onClose, onCreated }: {
  checklist: ChecklistDetail;
  onClose: () => void;
  onCreated: () => void | Promise<void>;
}) {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    if (!title.trim()) { toast('Title required', 'error'); return; }
    setSaving(true);
    try {
      await createChecklistItem(checklist.id, {
        title: title.trim(),
        description: description.trim() || undefined,
        category: category.trim() || undefined,
        severity: severity || undefined,
      });
      await onCreated();
    } catch (err: any) {
      toast(`Create failed: ${err.message || err}`, 'error');
    } finally { setSaving(false); }
  };

  return <ChecklistFormShell title={`Add item to "${checklist.name}"`} onClose={onClose} onSubmit={submit} saving={saving} submitLabel="Add item" submitDisabled={!title.trim()}>
    <FieldLabel>Title (required)</FieldLabel>
    <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus placeholder="e.g. Validate user input against a JSON Schema" style={modalInputStyle} />
    <FieldLabel>Description (optional; markdown supported at render time)</FieldLabel>
    <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={4} style={{ ...modalInputStyle, resize: 'vertical' }} />
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
      <div>
        <FieldLabel>Category</FieldLabel>
        <input value={category} onChange={(e) => setCategory(e.target.value)} placeholder="optional" style={modalInputStyle} />
      </div>
      <div>
        <FieldLabel>Severity</FieldLabel>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={modalInputStyle}>
          <option value="">-</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>
    </div>
  </ChecklistFormShell>;
}

function ChecklistFormShell({ title, onClose, onSubmit, saving, submitLabel, submitDisabled, children }: {
  title: string;
  onClose: () => void;
  onSubmit: () => void | Promise<void>;
  saving: boolean;
  submitLabel: string;
  submitDisabled?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 1000,
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 10, padding: 22, width: 'min(560px, 95vw)',
          display: 'flex', flexDirection: 'column', gap: 10,
        }}
      >
        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>{title}</div>
        {children}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 10 }}>
          <button onClick={onClose} disabled={saving} style={{
            padding: '8px 16px', background: 'var(--surface-2)', border: '1px solid var(--border)',
            borderRadius: 5, color: 'var(--text)', fontSize: 13, cursor: 'pointer',
          }}>Cancel</button>
          <button
            onClick={onSubmit}
            disabled={saving || submitDisabled}
            style={{
              padding: '8px 18px', background: 'var(--blue)', color: '#fff',
              border: 'none', borderRadius: 5, fontSize: 13, fontWeight: 700,
              cursor: (saving || submitDisabled) ? 'not-allowed' : 'pointer',
              opacity: (saving || submitDisabled) ? 0.6 : 1,
            }}
          >{saving ? 'Saving...' : submitLabel}</button>
        </div>
      </div>
    </div>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 3, marginTop: 6 }}>{children}</div>;
}

const modalInputStyle: React.CSSProperties = {
  width: '100%', padding: '7px 10px', background: 'var(--bg)',
  border: '1px solid var(--border)', borderRadius: 5, color: 'var(--text)',
  fontSize: 13, outline: 'none', boxSizing: 'border-box', fontFamily: 'inherit',
};

const selectStyle: React.CSSProperties = {
  padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 6, color: 'var(--text)', fontSize: 12, cursor: 'pointer',
};

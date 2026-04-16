import { useState, useEffect, useCallback } from 'react';
import { getProjects, type Project } from '@/lib/api';
import { useToast } from '@/components/Toast';

const BASE = '/api';
async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
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
  const { toast } = useToast() as { toast: (msg: string, type?: 'success' | 'error' | 'info') => void };
  const [checklists, setChecklists] = useState<ChecklistSummary[]>([]);
  const [selected, setSelected] = useState<ChecklistDetail | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<number | ''>('');
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);

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
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 16, flex: 1, overflow: 'hidden' }}>
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'auto' }}>
          {loading ? (
            <div style={{ padding: 20, textAlign: 'center', color: 'var(--muted)' }}>Loading...</div>
          ) : checklists.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              No checklists loaded. Restart server to seed defaults.
            </div>
          ) : (
            checklists.map(cl => (
              <div key={cl.id} onClick={() => loadChecklist(cl.id)} style={{
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
              <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 12 }}>
                <h3 style={{ margin: 0, color: 'var(--text)', fontSize: 16, flex: 1 }}>{selected.name}</h3>
                <span style={{
                  padding: '4px 12px', borderRadius: 10, fontSize: 12, fontWeight: 600,
                  background: selected.progress_pct === 100 ? 'var(--green)22' : 'var(--yellow)22',
                  color: selected.progress_pct === 100 ? 'var(--green)' : 'var(--yellow)',
                }}>
                  {selected.progress_pct}% complete
                </span>
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
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const selectStyle: React.CSSProperties = {
  padding: '8px 12px', background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 6, color: 'var(--text)', fontSize: 12, cursor: 'pointer',
};

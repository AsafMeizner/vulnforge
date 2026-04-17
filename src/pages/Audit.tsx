import { useState, useEffect, useCallback } from 'react';
import { getAuditLog, exportWorkspaceUrl, exportSarifUrl, type AuditEntry } from '@/lib/api';
import { useToast } from '@/components/Toast';

const ACTION_COLORS: Record<string, string> = {
  create: 'var(--green)',
  update: 'var(--blue)',
  delete: 'var(--red)',
  export: 'var(--purple)',
  import: 'var(--orange)',
  view: 'var(--muted)',
};

export default function Audit() {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('');
  const [entityFilter, setEntityFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAuditLog({
        action: actionFilter || undefined,
        entity_type: entityFilter || undefined,
        limit: 500,
      });
      setEntries(res.data);
    } catch (err: any) {
      toast(`Failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [actionFilter, entityFilter, toast]);

  useEffect(() => { load(); }, [load]);

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Audit & Export</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            Audit trail, SARIF/CVE exports, and workspace backups.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <a href={exportSarifUrl()} download style={btnStyle('var(--blue)')}>Export SARIF</a>
          <a href={exportWorkspaceUrl()} download style={btnStyle('var(--green)')}>Backup Workspace</a>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 10 }}>
        <select value={actionFilter} onChange={e => setActionFilter(e.target.value)} style={filterStyle}>
          <option value="">All actions</option>
          <option value="create">Create</option>
          <option value="update">Update</option>
          <option value="delete">Delete</option>
          <option value="export">Export</option>
          <option value="import">Import</option>
        </select>
        <select value={entityFilter} onChange={e => setEntityFilter(e.target.value)} style={filterStyle}>
          <option value="">All entities</option>
          <option value="vulnerability">Vulnerability</option>
          <option value="project">Project</option>
          <option value="disclosure">Disclosure</option>
          <option value="note">Note</option>
          <option value="workspace">Workspace</option>
        </select>
      </div>

      {/* Log table */}
      {loading ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)' }}>Loading...</div>
      ) : entries.length === 0 ? (
        <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13, border: '1px dashed var(--border)', borderRadius: 8 }}>
          No audit entries yet. Audit entries are created automatically on exports and future compliance actions.
        </div>
      ) : (
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Time', 'Actor', 'Action', 'Entity', 'ID', 'Details'].map(h => (
                  <th key={h} style={thStyle}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ ...tdStyle, color: 'var(--muted)', fontFamily: 'monospace', fontSize: 10 }}>
                    {e.ts?.replace('T', ' ').split('.')[0]}
                  </td>
                  <td style={{ ...tdStyle, color: 'var(--text)' }}>{e.actor || 'system'}</td>
                  <td style={tdStyle}>
                    <span style={{
                      padding: '2px 8px', borderRadius: 10,
                      background: `${ACTION_COLORS[e.action] || 'var(--muted)'}22`,
                      color: ACTION_COLORS[e.action] || 'var(--muted)',
                      fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                    }}>{e.action}</span>
                  </td>
                  <td style={{ ...tdStyle, color: 'var(--muted)' }}>{e.entity_type || '-'}</td>
                  <td style={{ ...tdStyle, color: 'var(--muted)', fontFamily: 'monospace' }}>{e.entity_id || '-'}</td>
                  <td style={{ ...tdStyle, color: 'var(--muted)', fontSize: 10, maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {e.details || ''}
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

function btnStyle(color: string): React.CSSProperties {
  return {
    padding: '8px 16px', background: color, color: '#000',
    border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 700,
    textDecoration: 'none', cursor: 'pointer', whiteSpace: 'nowrap',
  };
}

const filterStyle: React.CSSProperties = {
  padding: '6px 12px', background: 'var(--bg)', border: '1px solid var(--border)',
  borderRadius: 5, color: 'var(--text)', fontSize: 12, cursor: 'pointer',
};

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '8px 12px',
  color: 'var(--muted)', fontSize: 10, fontWeight: 600,
  textTransform: 'uppercase', letterSpacing: 0.5,
};

const tdStyle: React.CSSProperties = {
  padding: '8px 12px', verticalAlign: 'middle',
};

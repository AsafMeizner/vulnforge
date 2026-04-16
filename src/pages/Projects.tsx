import { useState, useEffect, useCallback } from 'react';
import { getProjects, importProject, importProjectFromUrl, getVulnerabilities } from '@/lib/api';
import type { Project, Vulnerability } from '@/lib/types';
import { SeverityBadge, StatusBadge } from '@/components/Badge';
import { Modal } from '@/components/Modal';
import { FindingDetailModal } from './FindingDetail';
import { useToast } from '@/components/Toast';
import { NotesPanel } from '@/components/NotesPanel';

function relativeTime(iso: string | null) {
  if (!iso) return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const LANG_COLORS: Record<string, string> = {
  C: 'var(--blue)',
  'C++': 'var(--blue)',
  Rust: 'var(--orange)',
  Go: 'var(--green)',
  Python: 'var(--yellow)',
  JavaScript: 'var(--yellow)',
  TypeScript: 'var(--blue)',
  Java: 'var(--red)',
  Ruby: 'var(--red)',
};

export default function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [importOpen, setImportOpen] = useState(false);
  const [importPath, setImportPath] = useState('');
  const [importing, setImporting] = useState(false);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [projectVulns, setProjectVulns] = useState<Vulnerability[]>([]);
  const [vulnsLoading, setVulnsLoading] = useState(false);
  const [selectedVulnId, setSelectedVulnId] = useState<number | null>(null);
  const { toast } = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getProjects();
      setProjects(data);
    } catch (err) {
      toast(`Failed to load projects: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const loadProjectVulns = useCallback(async (project: Project) => {
    setSelectedProject(project);
    setVulnsLoading(true);
    try {
      const result = await getVulnerabilities({ search: project.name });
      setProjectVulns(result.data);
    } catch (err) {
      toast(`Failed to load findings: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setVulnsLoading(false);
    }
  }, [toast]);

  const handleImport = async () => {
    if (!importPath.trim()) { toast('Enter a project path', 'error'); return; }
    setImporting(true);
    try {
      const project = await importProject(importPath.trim());
      toast(`Imported project: ${project.name}`, 'success');
      setImportOpen(false);
      setImportPath('');
      load();
    } catch (err) {
      toast(`Import failed: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setImporting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Projects</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            {loading ? 'Loading...' : `${projects.length} projects`}
          </p>
        </div>
        <button
          onClick={() => setImportOpen(true)}
          style={{
            background: 'var(--blue)',
            border: 'none',
            borderRadius: 6,
            padding: '8px 16px',
            color: '#fff',
            fontSize: 13,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          Import Project
        </button>
      </div>

      {/* Projects grid */}
      {loading ? (
        <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading...</div>
      ) : projects.length === 0 ? (
        <div style={{
          padding: 48,
          textAlign: 'center',
          border: '1px dashed var(--border)',
          borderRadius: 8,
          color: 'var(--muted)',
          fontSize: 13,
        }}>
          No projects yet. Click "Import Project" to add a target.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
          {projects.map(p => (
            <div
              key={p.id}
              onClick={() => loadProjectVulns(p)}
              style={{
                background: 'var(--surface)',
                border: `1px solid ${selectedProject?.id === p.id ? 'var(--blue)' : 'var(--border)'}`,
                borderRadius: 8,
                padding: 16,
                cursor: 'pointer',
                transition: 'border-color 0.15s',
              }}
              onMouseEnter={e => { if (selectedProject?.id !== p.id) (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--muted)'; }}
              onMouseLeave={e => { if (selectedProject?.id !== p.id) (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)'; }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text)' }}>{p.name}</div>
                {p.language && (
                  <span style={{
                    fontSize: 10,
                    color: LANG_COLORS[p.language] ?? 'var(--muted)',
                    background: `${LANG_COLORS[p.language] ?? 'var(--muted)'}22`,
                    padding: '2px 7px',
                    borderRadius: 3,
                    fontWeight: 600,
                    border: `1px solid ${LANG_COLORS[p.language] ?? 'var(--muted)'}44`,
                  }}>
                    {p.language}
                  </span>
                )}
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace', marginBottom: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {p.path}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--muted)' }}>
                <span>Last scanned: {relativeTime(p.last_scanned)}</span>
                {p.vuln_count !== undefined && (
                  <span style={{ color: p.vuln_count > 0 ? 'var(--orange)' : 'var(--green)' }}>
                    {p.vuln_count} finding{p.vuln_count !== 1 ? 's' : ''}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Project detail panel */}
      {selectedProject && (
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <span style={{ fontWeight: 600, fontSize: 15, color: 'var(--text)' }}>{selectedProject.name}</span>
              <span style={{ fontSize: 12, color: 'var(--muted)', marginLeft: 10 }}>{selectedProject.path}</span>
            </div>
            <button
              onClick={() => setSelectedProject(null)}
              style={{ background: 'none', border: 'none', color: 'var(--muted)', cursor: 'pointer', fontSize: 16 }}
            >
              x
            </button>
          </div>

          {vulnsLoading ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading findings...</div>
          ) : projectVulns.length === 0 ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>No findings for this project.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Title', 'Severity', 'Status', 'Method', 'Found'].map(h => (
                    <th key={h} style={{ padding: '8px 14px', textAlign: 'left', color: 'var(--muted)', fontWeight: 500, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {projectVulns.map(v => (
                  <tr
                    key={v.id}
                    onClick={() => setSelectedVulnId(v.id)}
                    style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-2)')}
                    onMouseLeave={e => (e.currentTarget.style.background = '')}
                  >
                    <td style={{ padding: '9px 14px', color: 'var(--text)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.title}</td>
                    <td style={{ padding: '9px 14px' }}><SeverityBadge severity={v.severity} /></td>
                    <td style={{ padding: '9px 14px' }}><StatusBadge status={v.status} /></td>
                    <td style={{ padding: '9px 14px', color: 'var(--muted)', fontSize: 11 }}>{v.method ?? '—'}</td>
                    <td style={{ padding: '9px 14px', color: 'var(--muted)' }}>{relativeTime(v.found_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Research Workspace — notes for this project */}
          <div style={{ padding: 16, borderTop: '1px solid var(--border)' }}>
            <NotesPanel projectId={selectedProject.id} initiallyOpen={false} />
          </div>
        </div>
      )}

      {/* Import modal — Local Path or Git URL */}
      <Modal open={importOpen} onClose={() => setImportOpen(false)} title="Import Project" width={520}>
        <ImportProjectForm
          onImported={() => { setImportOpen(false); loadProjects(); }}
          onCancel={() => setImportOpen(false)}
        />
      </Modal>

      {/* Finding detail modal */}
      {selectedVulnId != null && (
        <FindingDetailModal
          vulnId={selectedVulnId}
          onClose={() => setSelectedVulnId(null)}
        />
      )}
    </div>
  );
}

const labelStyle: React.CSSProperties = {
  fontSize: 11,
  color: 'var(--muted)',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  fontWeight: 600,
  marginBottom: 6,
  display: 'block',
};

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 5,
  padding: '8px 10px',
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
  fontFamily: 'inherit',
  boxSizing: 'border-box',
};

function ImportProjectForm({ onImported, onCancel }: { onImported: () => void; onCancel: () => void }) {
  const { toast } = useToast();
  const [mode, setMode] = useState<'path' | 'url'>('url');
  const [localPath, setLocalPath] = useState('');
  const [url, setUrl] = useState('');
  const [branch, setBranch] = useState('');
  const [importing, setImporting] = useState(false);

  const handleImport = async () => {
    setImporting(true);
    try {
      if (mode === 'path') {
        if (!localPath.trim()) { toast('Path is required', 'error'); setImporting(false); return; }
        await importProject(localPath.trim());
      } else {
        if (!url.trim()) { toast('URL is required', 'error'); setImporting(false); return; }
        await importProjectFromUrl(url.trim(), branch || undefined);
      }
      toast('Project imported', 'success');
      onImported();
    } catch (err: any) {
      toast(`Import failed: ${err.message}`, 'error');
    } finally {
      setImporting(false);
    }
  };

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Mode toggle */}
      <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
        <button onClick={() => setMode('url')} style={{
          flex: 1, padding: '8px 0', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600,
          background: mode === 'url' ? 'var(--surface-2)' : 'transparent',
          color: mode === 'url' ? 'var(--text)' : 'var(--muted)',
        }}>Git URL</button>
        <button onClick={() => setMode('path')} style={{
          flex: 1, padding: '8px 0', border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600,
          background: mode === 'path' ? 'var(--surface-2)' : 'transparent',
          color: mode === 'path' ? 'var(--text)' : 'var(--muted)',
        }}>Local Path</button>
      </div>

      {mode === 'url' ? (
        <>
          <div>
            <label style={labelStyle}>Repository URL</label>
            <input value={url} onChange={e => setUrl(e.target.value)}
              placeholder="https://github.com/org/repo"
              onKeyDown={e => e.key === 'Enter' && handleImport()}
              autoFocus style={inputStyle} />
          </div>
          <div>
            <label style={labelStyle}>Branch (optional)</label>
            <input value={branch} onChange={e => setBranch(e.target.value)}
              placeholder="main" style={inputStyle} />
          </div>
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>
            The repo will be cloned, language auto-detected, and dependencies extracted.
          </div>
        </>
      ) : (
        <div>
          <label style={labelStyle}>Project Path</label>
          <input value={localPath} onChange={e => setLocalPath(e.target.value)}
            placeholder="/path/to/project or C:\projects\target"
            onKeyDown={e => e.key === 'Enter' && handleImport()}
            autoFocus style={inputStyle} />
          <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 6 }}>
            Absolute path to an existing local repository.
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button onClick={onCancel} style={{
          background: 'var(--surface-2)', border: '1px solid var(--border)',
          borderRadius: 5, padding: '7px 16px', color: 'var(--text)', fontSize: 13, cursor: 'pointer',
        }}>Cancel</button>
        <button onClick={handleImport} disabled={importing} style={{
          background: importing ? 'var(--surface-2)' : 'var(--blue)', border: 'none',
          borderRadius: 5, padding: '7px 16px',
          color: importing ? 'var(--muted)' : '#fff',
          fontSize: 13, fontWeight: 600, cursor: importing ? 'not-allowed' : 'pointer',
        }}>
          {importing ? 'Importing...' : 'Import'}
        </button>
      </div>
    </div>
  );
}

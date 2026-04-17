import { useState, useEffect, useCallback } from 'react';
import {
  listCveIntel,
  syncNvd,
  listCveMatches,
  listBisectResults,
  getProjects,
  type CveIntel,
  type CveProjectMatch,
  type BisectResult,
  type Project,
} from '@/lib/api';
import { useToast } from '@/components/Toast';

type SubTab = 'cves' | 'matches' | 'bisect';

const TAB_LABELS: Record<SubTab, string> = {
  cves: 'CVE Intel',
  matches: 'Project Matches',
  bisect: 'Bisect Results',
};

function severityColor(sev?: string): string {
  if (!sev) return 'var(--muted)';
  switch (sev.toUpperCase()) {
    case 'CRITICAL': return 'var(--red)';
    case 'HIGH': return 'var(--orange)';
    case 'MEDIUM': return 'var(--yellow)';
    case 'LOW': return 'var(--green)';
    default: return 'var(--muted)';
  }
}

export default function History() {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };
  const [tab, setTab] = useState<SubTab>('cves');
  const [cves, setCves] = useState<CveIntel[]>([]);
  const [matches, setMatches] = useState<CveProjectMatch[]>([]);
  const [bisects, setBisects] = useState<BisectResult[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [selectedCve, setSelectedCve] = useState<CveIntel | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [cvesRes, matchesRes, bisectRes, projsRes] = await Promise.all([
        listCveIntel({ limit: 100 }),
        listCveMatches(),
        listBisectResults(),
        getProjects(),
      ]);
      setCves(cvesRes.data);
      setMatches(matchesRes.data);
      setBisects(bisectRes.data);
      setProjects(projsRes);
    } catch (err: any) {
      toast(`Load failed: ${err.message}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const handleSync = async () => {
    setSyncing(true);
    try {
      const result = await syncNvd(30);
      toast(`Synced ${result.fetch.stored} CVEs, found ${Object.keys(result.matches).length} projects with matches`, 'success');
      load();
    } catch (err: any) {
      toast(`Sync failed: ${err.message}`, 'error');
    } finally {
      setSyncing(false);
    }
  };

  const projectName = (id: number) => projects.find(p => p.id === id)?.name || `#${id}`;

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Historical Intelligence</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            CVE intelligence, dependency matching, and git bisect results.
          </p>
        </div>
        <button
          onClick={handleSync}
          disabled={syncing}
          style={{
            background: syncing ? 'var(--muted)' : 'var(--blue)', color: '#fff',
            border: 'none', borderRadius: 6, padding: '8px 16px',
            fontSize: 13, fontWeight: 600, cursor: syncing ? 'wait' : 'pointer',
          }}
        >
          {syncing ? 'Syncing NVD...' : 'Sync NVD (last 30 days)'}
        </button>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10 }}>
        <StatCard label="CVEs Cached" value={cves.length} color="var(--blue)" />
        <StatCard label="Project Matches" value={matches.length} color="var(--orange)" />
        <StatCard label="Bisect Jobs" value={bisects.length} color="var(--green)" />
        <StatCard label="Critical CVEs" value={cves.filter(c => c.severity === 'CRITICAL').length} color="var(--red)" />
      </div>

      {/* Sub-tabs */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)' }}>
        {(Object.keys(TAB_LABELS) as SubTab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              background: 'none', border: 'none',
              borderBottom: `2px solid ${tab === t ? 'var(--blue)' : 'transparent'}`,
              color: tab === t ? 'var(--text)' : 'var(--muted)',
              padding: '8px 14px', fontSize: 13, fontWeight: tab === t ? 600 : 400, cursor: 'pointer',
            }}
          >
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {loading ? (
        <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)' }}>Loading...</div>
      ) : (
        <>
          {tab === 'cves' && (
            cves.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13, border: '1px dashed var(--border)', borderRadius: 8 }}>
                No CVE intel yet. Click "Sync NVD" to fetch recent CVEs.
              </div>
            ) : (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['CVE ID', 'Severity', 'Score', 'Published', 'Description'].map(h => (
                        <th key={h} style={thStyle}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {cves.map(c => (
                      <tr key={c.id} onClick={() => setSelectedCve(c)}
                        style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}>
                        <td style={{ ...tdStyle, fontFamily: 'monospace', color: 'var(--blue)' }}>{c.cve_id}</td>
                        <td style={tdStyle}>
                          <span style={{
                            padding: '2px 8px', borderRadius: 10,
                            background: `${severityColor(c.severity)}22`, color: severityColor(c.severity),
                            fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                          }}>{c.severity || 'unknown'}</span>
                        </td>
                        <td style={{ ...tdStyle, fontFamily: 'monospace', color: 'var(--text)' }}>{c.cvss_score ?? '—'}</td>
                        <td style={{ ...tdStyle, color: 'var(--muted)', fontSize: 11 }}>{c.published?.split('T')[0] || '—'}</td>
                        <td style={{ ...tdStyle, maxWidth: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text)' }}>
                          {c.description || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}

          {tab === 'matches' && (
            matches.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13, border: '1px dashed var(--border)', borderRadius: 8 }}>
                No CVE-to-project matches yet. Sync NVD and match your imported projects' dependencies.
              </div>
            ) : (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['CVE', 'Project', 'Dependency', 'Version', 'Reason', 'Confidence'].map(h => (
                        <th key={h} style={thStyle}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {matches.map(m => (
                      <tr key={m.id} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ ...tdStyle, fontFamily: 'monospace', color: 'var(--blue)' }}>{m.cve_id}</td>
                        <td style={{ ...tdStyle, color: 'var(--text)' }}>{projectName(m.project_id)}</td>
                        <td style={{ ...tdStyle, color: 'var(--text)' }}>{m.dependency_name || '—'}</td>
                        <td style={{ ...tdStyle, color: 'var(--muted)', fontFamily: 'monospace' }}>{m.dependency_version || '—'}</td>
                        <td style={{ ...tdStyle, color: 'var(--muted)' }}>{m.match_reason}</td>
                        <td style={{ ...tdStyle, color: 'var(--muted)' }}>{m.confidence ? `${(m.confidence * 100).toFixed(0)}%` : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}

          {tab === 'bisect' && (
            bisects.length === 0 ? (
              <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13, border: '1px dashed var(--border)', borderRadius: 8 }}>
                No bisect jobs yet. Start one from the Runtime page with type "bisect".
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {bisects.map(b => (
                  <div key={b.id} style={{
                    background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
                    padding: '14px 18px',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                      <span style={{ color: 'var(--blue)', fontFamily: 'monospace', fontSize: 13 }}>
                        {b.first_bad_commit?.slice(0, 12) || 'no result'}
                      </span>
                      <span style={{ color: 'var(--muted)', fontSize: 11 }}>
                        {b.tests_run} tests run
                      </span>
                      {b.author && <span style={{ color: 'var(--muted)', fontSize: 11, marginLeft: 'auto' }}>{b.author}</span>}
                    </div>
                    <div style={{ color: 'var(--text)', fontSize: 13, fontWeight: 500 }}>
                      {b.commit_message || '(no commit message)'}
                    </div>
                    {b.first_bad_date && (
                      <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 4 }}>
                        {b.first_bad_date.split('T')[0]}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )
          )}
        </>
      )}

      {/* CVE detail modal */}
      {selectedCve && (
        <div style={{
          position: 'fixed', inset: 0, background: '#0008', zIndex: 1000,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }} onClick={() => setSelectedCve(null)}>
          <div style={{
            background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 10,
            padding: 24, width: '90%', maxWidth: 700, maxHeight: '80vh', overflow: 'auto',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <h3 style={{ margin: 0, color: 'var(--blue)', fontFamily: 'monospace' }}>{selectedCve.cve_id}</h3>
              <span style={{
                padding: '3px 10px', borderRadius: 10,
                background: `${severityColor(selectedCve.severity)}22`, color: severityColor(selectedCve.severity),
                fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
              }}>{selectedCve.severity}</span>
              <span style={{ color: 'var(--text)', fontWeight: 700, fontFamily: 'monospace' }}>{selectedCve.cvss_score ?? '—'}</span>
            </div>

            <p style={{ color: 'var(--text)', fontSize: 13, lineHeight: 1.6, margin: '10px 0' }}>
              {selectedCve.description}
            </p>

            {selectedCve.affected_products && selectedCve.affected_products.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
                  Affected Products
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {selectedCve.affected_products.slice(0, 20).map((p, i) => (
                    <span key={i} style={{
                      padding: '2px 8px', background: 'var(--bg)', border: '1px solid var(--border)',
                      borderRadius: 4, fontSize: 10, fontFamily: 'monospace', color: 'var(--text)',
                    }}>{p}</span>
                  ))}
                </div>
              </div>
            )}

            {selectedCve.cve_references && selectedCve.cve_references.length > 0 && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
                  References
                </div>
                <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>
                  {selectedCve.cve_references.slice(0, 10).map((r, i) => (
                    <li key={i}><a href={r} target="_blank" rel="noreferrer" style={{ color: 'var(--blue)' }}>{r}</a></li>
                  ))}
                </ul>
              </div>
            )}

            <button onClick={() => setSelectedCve(null)} style={{
              marginTop: 16, padding: '8px 16px',
              background: 'var(--surface-2)', border: '1px solid var(--border)',
              borderRadius: 5, color: 'var(--text)', fontSize: 13, cursor: 'pointer',
            }}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
      padding: '16px 18px', borderTop: `3px solid ${color}`,
    }}>
      <div style={{ fontSize: 24, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 6 }}>
        {label}
      </div>
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '10px 14px',
  color: 'var(--muted)', fontSize: 11, fontWeight: 600,
  textTransform: 'uppercase', letterSpacing: 0.5,
};

const tdStyle: React.CSSProperties = {
  padding: '10px 14px', verticalAlign: 'middle',
};

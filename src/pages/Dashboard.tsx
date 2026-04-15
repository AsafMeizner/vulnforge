import { useState, useEffect, useRef } from 'react';
import { getStats, getVulnerabilities, getScans, getPipelines, type PipelineRun } from '@/lib/api';
import type { Stats, Vulnerability, Scan } from '@/lib/types';
import { SeverityBadge, StatusBadge, CvssScore } from '@/components/Badge';
import { useToast } from '@/components/Toast';

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div style={{
      background: 'var(--surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '18px 20px',
      borderTop: `3px solid ${color}`,
    }}>
      <div style={{ fontSize: 28, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.6px', marginTop: 6 }}>{label}</div>
    </div>
  );
}

function relativeTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

interface DashboardProps {
  onNavigate: (page: string, extra?: unknown) => void;
}

// Extended stats shape returned by /api/stats
interface ExtendedStats extends Stats {
  totalVulns?: number;
  medium?: number;
  low?: number;
  submitted?: number;
  verified?: number;
  totalProjects?: number;
  totalTools?: number;
  bySeverity?: { severity: string; count: number }[];
  byStatus?: { status: string; count: number }[];
  recentVulns?: Vulnerability[];
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'var(--red)',
  High: 'var(--orange)',
  Medium: 'var(--yellow)',
  Low: 'var(--muted)',
  Info: 'var(--blue)',
};

export default function Dashboard({ onNavigate }: DashboardProps) {
  const [stats, setStats] = useState<ExtendedStats | null>(null);
  const [findings, setFindings] = useState<Vulnerability[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  const load = async () => {
    setLoading(true);
    try {
      const [s, v, sc] = await Promise.all([
        getStats() as Promise<ExtendedStats>,
        getVulnerabilities({ sort: 'found_at', order: 'desc', limit: 10 }),
        getScans(),
      ]);
      setStats(s);
      setFindings(v.data);
      setScans(sc);
    } catch (err) {
      toast(`Failed to load dashboard: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const runningScans = scans.filter(s => s.status === 'running');

  // Severity distribution data
  const severityData = stats?.bySeverity ?? [];
  const totalSeverityCount = severityData.reduce((acc, d) => acc + Number(d.count), 0) || 1;

  // Recent activity — merge scans + findings sorted by time
  const recentActivity = [
    ...scans.slice(0, 10).map(s => ({
      type: 'scan' as const,
      label: `Scan: ${s.tool_name} on ${s.project_name ?? `Project #${s.project_id}`}`,
      detail: s.findings_count != null ? `${s.findings_count} finding(s)` : '',
      time: s.started_at,
      color: s.status === 'completed' ? 'var(--green)' : s.status === 'failed' ? 'var(--red)' : 'var(--orange)',
    })),
    ...findings.slice(0, 10).map(v => ({
      type: 'finding' as const,
      label: v.title,
      detail: v.project,
      time: v.found_at,
      color: SEVERITY_COLORS[v.severity] ?? 'var(--muted)',
    })),
  ]
    .sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime())
    .slice(0, 10);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Dashboard</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>Security research overview</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={() => onNavigate('scanner')} style={btnStyle('var(--blue)')}>
            New Scan
          </button>
          <button onClick={() => onNavigate('projects')} style={btnStyle('var(--surface-2)')}>
            Import Project
          </button>
          <button onClick={() => toast('AI triage queued for all new findings...', 'info')} style={btnStyle('var(--purple)')}>
            AI Triage All
          </button>
        </div>
      </div>

      {/* Quick Hunt */}
      <QuickHunt onNavigate={onNavigate} />

      {/* Stats cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
        <StatCard label="Total Findings" value={loading ? '—' : (stats?.totalVulns ?? stats?.total ?? 0)} color="var(--text)" />
        <StatCard label="Critical" value={loading ? '—' : (stats?.critical ?? 0)} color="var(--red)" />
        <StatCard label="High" value={loading ? '—' : (stats?.high ?? 0)} color="var(--orange)" />
        <StatCard label="Medium" value={loading ? '—' : (stats?.medium ?? 0)} color="var(--yellow)" />
        <StatCard label="Verified" value={loading ? '—' : (stats?.verified ?? 0)} color="var(--green)" />
        <StatCard label="Projects" value={loading ? '—' : (stats?.totalProjects ?? stats?.projects ?? 0)} color="var(--blue)" />
      </div>

      {/* Two-column layout: severity distribution + recent activity */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Severity Distribution */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
            <span style={{ fontWeight: 600, fontSize: 14 }}>Severity Distribution</span>
          </div>
          <div style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {loading ? (
              <div style={{ color: 'var(--muted)', fontSize: 13 }}>Loading...</div>
            ) : severityData.length === 0 ? (
              <div style={{ color: 'var(--muted)', fontSize: 13 }}>No findings yet.</div>
            ) : (
              ['Critical', 'High', 'Medium', 'Low', 'Info'].map(sev => {
                const entry = severityData.find(d => d.severity === sev);
                const count = entry ? Number(entry.count) : 0;
                if (count === 0) return null;
                const pct = Math.round((count / totalSeverityCount) * 100);
                const color = SEVERITY_COLORS[sev] ?? 'var(--muted)';
                return (
                  <div key={sev}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <span style={{ fontSize: 12, color, fontWeight: 600 }}>{sev}</span>
                      <span style={{ fontSize: 12, color: 'var(--muted)' }}>{count} ({pct}%)</span>
                    </div>
                    <div style={{ height: 8, background: 'var(--bg)', borderRadius: 4, overflow: 'hidden', border: '1px solid var(--border)' }}>
                      <div style={{
                        height: '100%',
                        width: `${pct}%`,
                        background: color,
                        borderRadius: 4,
                        transition: 'width 0.6s ease',
                      }} />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Recent Activity */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
            <span style={{ fontWeight: 600, fontSize: 14 }}>Recent Activity</span>
          </div>
          <div style={{ padding: '8px 0' }}>
            {loading ? (
              <div style={{ padding: '12px 18px', color: 'var(--muted)', fontSize: 13 }}>Loading...</div>
            ) : recentActivity.length === 0 ? (
              <div style={{ padding: '12px 18px', color: 'var(--muted)', fontSize: 13 }}>No activity yet.</div>
            ) : (
              recentActivity.map((item, i) => (
                <div key={i} style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 10,
                  padding: '8px 18px',
                  borderBottom: i < recentActivity.length - 1 ? '1px solid var(--border)' : 'none',
                }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: item.color, flexShrink: 0, marginTop: 4 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.label}</div>
                    {item.detail && <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 1 }}>{item.detail}</div>}
                  </div>
                  <span style={{ fontSize: 10, color: 'var(--muted)', flexShrink: 0, marginTop: 2 }}>{relativeTime(item.time)}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Active scans */}
      {runningScans.length > 0 && (
        <div style={{
          background: 'var(--surface)',
          border: '1px solid var(--orange)',
          borderRadius: 8,
          padding: 16,
        }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--orange)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            Active Scans ({runningScans.length})
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {runningScans.map(sc => (
              <div key={sc.id} style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 13 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--orange)', display: 'inline-block', flexShrink: 0 }} />
                <span style={{ color: 'var(--text)' }}>{sc.project_name ?? `Project #${sc.project_id}`}</span>
                <span style={{ color: 'var(--muted)' }}>{sc.tool_name}</span>
                <span style={{ color: 'var(--muted)', marginLeft: 'auto' }}>{relativeTime(sc.started_at)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent findings table */}
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontWeight: 600, fontSize: 14 }}>Recent Findings</span>
          <button
            onClick={() => onNavigate('findings')}
            style={{ background: 'none', border: 'none', color: 'var(--blue)', fontSize: 12, cursor: 'pointer' }}
          >
            View all
          </button>
        </div>
        {loading ? (
          <div style={{ padding: 32, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>Loading...</div>
        ) : findings.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
            <div style={{ color: 'var(--muted)', fontSize: 13 }}>No findings yet. Run a scan to get started.</div>
            <button onClick={() => onNavigate('scanner')} style={btnStyle('var(--blue)')}>
              Go to Scanner
            </button>
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Project', 'Title', 'Severity', 'CVSS', 'Status', 'Found'].map(h => (
                  <th key={h} style={{ padding: '8px 14px', textAlign: 'left', color: 'var(--muted)', fontWeight: 500, fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {findings.map(v => (
                <tr
                  key={v.id}
                  onClick={() => onNavigate('findings', v.id)}
                  style={{ borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-2)')}
                  onMouseLeave={e => (e.currentTarget.style.background = '')}
                >
                  <td style={{ padding: '9px 14px', color: 'var(--muted)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.project}</td>
                  <td style={{ padding: '9px 14px', color: 'var(--text)', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.title}</td>
                  <td style={{ padding: '9px 14px' }}><SeverityBadge severity={v.severity} /></td>
                  <td style={{ padding: '9px 14px' }}><CvssScore score={v.cvss} /></td>
                  <td style={{ padding: '9px 14px' }}><StatusBadge status={v.status} /></td>
                  <td style={{ padding: '9px 14px', color: 'var(--muted)' }}>{relativeTime(v.found_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function QuickHunt({ onNavigate }: { onNavigate: (page: string, extra?: unknown) => void }) {
  const [url, setUrl] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--green)33',
      borderRadius: 8, padding: '16px 20px',
      display: 'flex', alignItems: 'center', gap: 14,
      borderLeft: '3px solid var(--green)',
    }}>
      <div style={{ flexShrink: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text)' }}>Quick Hunt</div>
        <div style={{ fontSize: 11, color: 'var(--muted)' }}>Paste a URL to auto-scan</div>
      </div>
      <input
        ref={inputRef}
        value={url}
        onChange={e => setUrl(e.target.value)}
        placeholder="https://github.com/org/repo"
        onKeyDown={e => {
          if (e.key === 'Enter' && url.trim()) onNavigate('hunt', { prefillUrl: url.trim() });
        }}
        style={{
          flex: 1, padding: '8px 12px', background: 'var(--bg)',
          border: '1px solid var(--border)', borderRadius: 6,
          color: 'var(--text)', fontSize: 13, outline: 'none',
        }}
      />
      <button
        onClick={() => url.trim() ? onNavigate('hunt', { prefillUrl: url.trim() }) : onNavigate('hunt')}
        style={{
          padding: '8px 18px', background: 'var(--green)', color: '#000',
          border: 'none', borderRadius: 6, fontSize: 13, fontWeight: 700,
          cursor: 'pointer', whiteSpace: 'nowrap',
        }}
      >
        Go
      </button>
    </div>
  );
}

function btnStyle(bg: string): React.CSSProperties {
  return {
    background: bg,
    border: '1px solid var(--border)',
    borderRadius: 6,
    padding: '7px 14px',
    color: 'var(--text)',
    fontSize: 12,
    fontWeight: 500,
    cursor: 'pointer',
  };
}

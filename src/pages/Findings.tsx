import { useState, useEffect, useCallback, useRef } from 'react';
import { getVulnerabilities } from '@/lib/api';
import type { Vulnerability, Severity, VulnStatus } from '@/lib/types';
import { SeverityBadge, StatusBadge, CvssScore } from '@/components/Badge';
import { FindingDetailModal } from './FindingDetail';
import { useToast } from '@/components/Toast';

type SortKey = 'title' | 'severity' | 'cvss' | 'status' | 'found_at' | 'project';

const SEVERITY_ORDER: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
const PAGE_SIZE = 50;

function relativeTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

interface FindingsProps {
  initialVulnId?: number | null;
  searchQuery?: string;
  onNavigate?: (page: string, extra?: unknown) => void;
}

export default function Findings({ initialVulnId, searchQuery = '', onNavigate }: FindingsProps) {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [localSearch, setLocalSearch] = useState('');
  // Debounced mirror of localSearch - this is what actually feeds
  // effectiveSearch/load(). Without this, every keystroke fires a
  // network GET; typing a 20-char query sent 20 requests.
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('found_at');
  const [sortAsc, setSortAsc] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(initialVulnId ?? null);
  // Keyboard-focused row index (j/k navigation)
  const [focusedIdx, setFocusedIdx] = useState<number>(0);
  const tableRef = useRef<HTMLTableSectionElement>(null);
  const { toast } = useToast();

  // 300ms debounce between the user typing and hitting the server.
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(localSearch), 300);
    return () => clearTimeout(t);
  }, [localSearch]);

  const effectiveSearch = searchQuery || debouncedSearch;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getVulnerabilities({
        severity: severity || undefined,
        status: status || undefined,
        search: effectiveSearch || undefined,
        sort: sortKey,
        order: sortAsc ? 'asc' : 'desc',
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      });
      setVulns(result.data);
      setTotal(result.total);
    } catch (err) {
      toast(`Failed to load findings: ${err instanceof Error ? err.message : err}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [severity, status, effectiveSearch, sortKey, sortAsc, page, toast]);

  useEffect(() => { load(); }, [load]);

  // Reset to page 1 when filters change
  useEffect(() => { setPage(1); }, [severity, status, effectiveSearch, sortKey, sortAsc]);

  useEffect(() => {
    if (initialVulnId != null) setSelectedId(initialVulnId);
  }, [initialVulnId]);

  // j/k/Enter keyboard navigation
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Only when not in an input and no panel open
      if (selectedId != null) return;
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

      if (e.key === 'j') {
        e.preventDefault();
        setFocusedIdx(prev => Math.min(prev + 1, vulns.length - 1));
      } else if (e.key === 'k') {
        e.preventDefault();
        setFocusedIdx(prev => Math.max(prev - 1, 0));
      } else if (e.key === 'Enter') {
        if (vulns[focusedIdx]) {
          setSelectedId(vulns[focusedIdx].id);
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
    // Re-subscribe only when the navigation target set changes. Without
    // a dep array the listener was re-registered every render; with an
    // empty array the handler would close over stale vulns/focusedIdx.
  }, [vulns, focusedIdx, selectedId]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(a => !a);
    else { setSortKey(key); setSortAsc(true); }
  };

  // Rows come pre-sorted from server; no client-side sort needed
  const sortedVulns = vulns;

  const SortIcon = ({ k }: { k: SortKey }) =>
    sortKey === k ? <span style={{ color: 'var(--blue)', marginLeft: 4 }}>{sortAsc ? '↑' : '↓'}</span> : null;

  const hasFilters = severity || status || localSearch;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: 'var(--text)' }}>Findings</h2>
          <p style={{ fontSize: 12, color: 'var(--muted)', margin: '4px 0 0' }}>
            {loading ? 'Loading...' : `${total} vulnerabilit${total === 1 ? 'y' : 'ies'}`}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ fontSize: 10, color: 'var(--muted)' }}>
            <kbd style={kbdStyle}>j</kbd>/<kbd style={kbdStyle}>k</kbd> navigate
            {' '}<kbd style={kbdStyle}>Enter</kbd> open
          </span>
        </div>
      </div>

      {/* Filter bar */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Search findings..."
          value={localSearch}
          onChange={e => setLocalSearch(e.target.value)}
          style={{
            flex: '1 1 200px',
            minWidth: 0,
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            padding: '7px 12px',
            color: 'var(--text)',
            fontSize: 13,
            outline: 'none',
          }}
        />
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={filterSelect}>
          <option value="">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
          <option value="Info">Info</option>
        </select>
        <select value={status} onChange={e => setStatus(e.target.value)} style={filterSelect}>
          <option value="">All Statuses</option>
          <option value="New">New</option>
          <option value="Triaged">Triaged</option>
          <option value="Submitted">Submitted</option>
          <option value="Fixed">Fixed</option>
          <option value="Rejected">Rejected</option>
          <option value="Wont Fix">Wont Fix</option>
        </select>
        {hasFilters && (
          <button
            onClick={() => { setSeverity(''); setStatus(''); setLocalSearch(''); }}
            style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 6, padding: '7px 12px', color: 'var(--muted)', fontSize: 12, cursor: 'pointer' }}
          >
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        {loading ? (
          // Skeleton rows
          <div>
            <div style={{ padding: '9px 14px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 16 }}>
              {[120, 280, 70, 50, 80, 80, 70].map((w, i) => (
                <div key={i} style={{ height: 12, width: w, background: 'var(--surface-2)', borderRadius: 3, animation: 'shimmer 1.5s infinite' }} />
              ))}
            </div>
            {[1, 2, 3, 4, 5].map(i => (
              <div key={i} style={{ padding: '11px 14px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 16, opacity: 1 - i * 0.15 }}>
                {[80, 240, 60, 40, 70, 60, 60].map((w, j) => (
                  <div key={j} style={{ height: 12, width: w, background: 'var(--surface-2)', borderRadius: 3, animation: 'shimmer 1.5s infinite' }} />
                ))}
              </div>
            ))}
          </div>
        ) : sortedVulns.length === 0 ? (
          hasFilters ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              No findings match current filters.
            </div>
          ) : (
            <div style={{ padding: 48, textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
              <div style={{ fontSize: 14, color: 'var(--text)', fontWeight: 500 }}>No findings yet</div>
              <div style={{ fontSize: 13, color: 'var(--muted)' }}>Run a scan to start finding vulnerabilities.</div>
              {onNavigate && (
                <button
                  onClick={() => onNavigate('scanner')}
                  style={{
                    background: 'var(--blue)',
                    border: 'none',
                    borderRadius: 6,
                    padding: '8px 18px',
                    color: '#fff',
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: 'pointer',
                    marginTop: 4,
                  }}
                >
                  Go to Scanner
                </button>
              )}
            </div>
          )
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {([
                    ['Project', 'project'],
                    ['Title', 'title'],
                    ['Severity', 'severity'],
                    ['CVSS', 'cvss'],
                    ['Status', 'status'],
                    ['Method', null],
                    ['Found', 'found_at'],
                  ] as [string, SortKey | null][]).map(([label, key]) => (
                    <th
                      key={label}
                      style={{
                        padding: '9px 14px',
                        textAlign: 'left',
                        color: 'var(--muted)',
                        fontWeight: 500,
                        fontSize: 11,
                        textTransform: 'uppercase',
                        letterSpacing: '0.4px',
                        cursor: key ? 'pointer' : 'default',
                        userSelect: 'none',
                        whiteSpace: 'nowrap',
                      }}
                      onClick={key ? () => toggleSort(key as SortKey) : undefined}
                    >
                      {label}
                      {key && <SortIcon k={key as SortKey} />}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody ref={tableRef}>
                {sortedVulns.map((v, idx) => {
                  const isFocused = idx === focusedIdx && selectedId == null;
                  return (
                    <tr
                      key={v.id}
                      onClick={() => { setSelectedId(v.id); setFocusedIdx(idx); }}
                      style={{
                        borderBottom: '1px solid var(--border)',
                        cursor: 'pointer',
                        background: isFocused ? 'var(--surface-2)' : '',
                        outline: isFocused ? '1px solid var(--blue)' : 'none',
                        outlineOffset: -1,
                      }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-2)')}
                      onMouseLeave={e => (e.currentTarget.style.background = isFocused ? 'var(--surface-2)' : '')}
                    >
                      <td style={{ padding: '9px 14px', color: 'var(--muted)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.project}</td>
                      <td style={{ padding: '9px 14px', color: 'var(--text)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {(v as any).verified === 1 && (
                          <span style={{ fontSize: 9, color: 'var(--green)', background: 'var(--green)22', border: '1px solid var(--green)44', borderRadius: 3, padding: '1px 4px', marginRight: 6, verticalAlign: 'middle' }}>V</span>
                        )}
                        {v.title}
                      </td>
                      <td style={{ padding: '9px 14px' }}><SeverityBadge severity={v.severity} /></td>
                      <td style={{ padding: '9px 14px' }}><CvssScore score={v.cvss} /></td>
                      <td style={{ padding: '9px 14px' }}><StatusBadge status={v.status} /></td>
                      <td style={{ padding: '9px 14px', color: 'var(--muted)', fontSize: 11, fontFamily: 'monospace' }}>{v.method ?? '-'}</td>
                      <td style={{ padding: '9px 14px', color: 'var(--muted)', whiteSpace: 'nowrap' }}>{relativeTime(v.found_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination controls */}
      {!loading && total > PAGE_SIZE && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            style={paginationBtn(page === 1)}
          >
            Previous
          </button>
          <span style={{ fontSize: 12, color: 'var(--muted)' }}>
            Page {page} of {totalPages} ({total} total)
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            style={paginationBtn(page === totalPages)}
          >
            Next
          </button>
        </div>
      )}

      {/* Detail slide-over */}
      {selectedId != null && (
        <FindingDetailModal
          vulnId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}

      <style>{`
        @keyframes shimmer {
          0%   { opacity: 0.4; }
          50%  { opacity: 0.7; }
          100% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}

const filterSelect: React.CSSProperties = {
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: '7px 10px',
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
  cursor: 'pointer',
};

const kbdStyle: React.CSSProperties = {
  background: 'var(--surface-2)',
  border: '1px solid var(--border)',
  borderRadius: 3,
  padding: '1px 5px',
  fontSize: 10,
  fontFamily: 'monospace',
  color: 'var(--muted)',
};

function paginationBtn(disabled: boolean): React.CSSProperties {
  return {
    background: disabled ? 'var(--surface-2)' : 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    padding: '6px 14px',
    color: disabled ? 'var(--muted)' : 'var(--text)',
    fontSize: 12,
    cursor: disabled ? 'not-allowed' : 'pointer',
    opacity: disabled ? 0.5 : 1,
  };
}

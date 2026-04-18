import { useEffect, useRef, useState } from 'react';
import { getVulnerabilities } from '@/lib/api';
import type { Vulnerability } from '@/lib/types';
import { SeverityBadge } from '@/components/Badge';

/**
 * Searchable combobox for picking a vulnerability by id. Typing into
 * the input fires a debounced /vulnerabilities?search=<q> GET and
 * shows the top matches as a dropdown; clicking a result sets the
 * value and closes the menu.
 *
 * Designed to replace the "paste a numeric id into a text box" pattern
 * that lives in Investigate and Exploits. The user sees the finding's
 * title + severity while choosing, which is the actually-useful view.
 *
 * Controlled component. `value` is the finding id (number) or null.
 * `onChange(id)` fires on selection and on clear.
 */
export function FindingCombo({
  value, onChange, placeholder,
}: {
  value: number | null;
  onChange: (id: number | null) => void;
  placeholder?: string;
}) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [results, setResults] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(false);
  // Cache of id -> vulnerability so we can show the currently-selected
  // finding's title even before the user opens the dropdown. Populated
  // from the search results + from the initial-resolve effect below.
  const [labels, setLabels] = useState<Record<number, Vulnerability>>({});
  const containerRef = useRef<HTMLDivElement | null>(null);

  // When `value` is set but not in labels, fetch its row once so we can
  // show the title instead of an opaque "#7".
  useEffect(() => {
    if (value == null || labels[value]) return;
    let cancelled = false;
    getVulnerabilities({ limit: 1, offset: 0 })
      .then(async () => {
        // We don't have a getVulnerability(id) helper in every build,
        // so just search by id and pick the match. This is cheap and
        // only fires once per selection.
        const res = await getVulnerabilities({ search: String(value), limit: 50 });
        if (cancelled) return;
        const hit = res.data.find((v) => v.id === value);
        if (hit) setLabels((prev) => ({ ...prev, [hit.id]: hit }));
      })
      .catch(() => { /* non-fatal */ });
    return () => { cancelled = true; };
  }, [value, labels]);

  // Debounced search as the user types.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setLoading(true);
    const t = setTimeout(async () => {
      try {
        const res = await getVulnerabilities({
          search: query || undefined,
          limit: 25,
        });
        if (cancelled) return;
        setResults(res.data);
        setLabels((prev) => {
          const next = { ...prev };
          for (const v of res.data) next[v.id] = v;
          return next;
        });
      } catch { /* swallow - empty results acceptable */ }
      finally { if (!cancelled) setLoading(false); }
    }, 180);
    return () => { cancelled = true; clearTimeout(t); };
  }, [query, open]);

  // Close on outside click.
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => {
      if (!containerRef.current) return;
      if (!containerRef.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener('mousedown', h);
    return () => window.removeEventListener('mousedown', h);
  }, [open]);

  const selected = value != null ? labels[value] : null;

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100%' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 5,
        padding: '6px 10px', cursor: 'text',
      }}
        onClick={() => setOpen(true)}
      >
        {selected && !open && (
          <>
            <SeverityBadge severity={selected.severity} />
            <span style={{ fontSize: 12, color: 'var(--muted)', fontFamily: 'monospace' }}>#{selected.id}</span>
            <span style={{ fontSize: 13, color: 'var(--text)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {selected.title}
            </span>
          </>
        )}
        {(open || !selected) && (
          <input
            autoFocus={open}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setOpen(true); }}
            onFocus={() => setOpen(true)}
            placeholder={placeholder || 'Search findings by title or id...'}
            style={{
              flex: 1, background: 'transparent', border: 'none', outline: 'none',
              color: 'var(--text)', fontSize: 13,
            }}
          />
        )}
        {selected && (
          <button
            onClick={(e) => { e.stopPropagation(); onChange(null); setQuery(''); }}
            title="Clear"
            style={{
              background: 'transparent', border: 'none', color: 'var(--muted)',
              cursor: 'pointer', fontSize: 14, padding: 0, lineHeight: 1,
            }}
          >&times;</button>
        )}
      </div>

      {open && (
        <div style={{
          position: 'absolute', top: 'calc(100% + 4px)', left: 0, right: 0,
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 6, boxShadow: '0 8px 20px rgba(0,0,0,0.35)',
          maxHeight: 320, overflow: 'auto', zIndex: 100,
        }}>
          {loading && results.length === 0 && (
            <div style={{ padding: 10, color: 'var(--muted)', fontSize: 12 }}>Searching...</div>
          )}
          {!loading && results.length === 0 && (
            <div style={{ padding: 10, color: 'var(--muted)', fontSize: 12 }}>
              No findings match "{query}".
            </div>
          )}
          {results.map((v) => (
            <button
              key={v.id}
              onClick={() => { onChange(v.id); setOpen(false); setQuery(''); }}
              style={{
                width: '100%', textAlign: 'left',
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '8px 10px', border: 'none',
                background: v.id === value ? 'var(--surface-2)' : 'transparent',
                color: 'var(--text)', cursor: 'pointer',
                borderBottom: '1px solid var(--border)',
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--surface-2)'; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = v.id === value ? 'var(--surface-2)' : 'transparent'; }}
            >
              <SeverityBadge severity={v.severity} />
              <span style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace', minWidth: 36 }}>#{v.id}</span>
              <span style={{ fontSize: 13, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {v.title}
              </span>
              {v.file && (
                <span style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {v.file.split(/[/\\]/).pop()}
                </span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useToast } from '@/components/Toast';
import { Modal } from '@/components/Modal';
import { QuickCapture } from '@/components/QuickCapture';
import { listHypotheses, updateNote, getNote, getProjects, type Note } from '@/lib/api';
import type { Project } from '@/lib/types';

type HStatus = 'open' | 'investigating' | 'confirmed' | 'disproved';

interface ColumnDef {
  id: HStatus;
  label: string;
  color: string;
}

const COLUMNS: ColumnDef[] = [
  { id: 'open',          label: 'Open',          color: 'var(--muted)' },
  { id: 'investigating', label: 'Investigating', color: 'var(--blue)'  },
  { id: 'confirmed',     label: 'Confirmed',     color: 'var(--green)' },
  { id: 'disproved',     label: 'Disproved',     color: 'var(--red)'   },
];

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function normalizeTags(tags: Note['tags']): string[] {
  if (Array.isArray(tags)) return tags;
  if (typeof tags === 'string' && tags) {
    try {
      const parsed = JSON.parse(tags);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return tags.split(',').map(t => t.trim()).filter(Boolean);
    }
  }
  return [];
}

function normalizeFindings(fids: Note['finding_ids']): number[] {
  if (Array.isArray(fids)) return fids as number[];
  if (typeof fids === 'string' && fids) {
    try {
      const parsed = JSON.parse(fids);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

function normalizeStatus(s: string | undefined): HStatus {
  const valid: HStatus[] = ['open', 'investigating', 'confirmed', 'disproved'];
  if (s && valid.includes(s as HStatus)) return s as HStatus;
  return 'open';
}

function confidencePercent(c: number | undefined): number {
  if (c === undefined || c === null) return 0;
  // Backend may store as 0-1 or 0-100; tolerate either.
  if (c <= 1) return Math.round(c * 100);
  return Math.min(100, Math.round(c));
}

export default function HypothesisBoard() {
  const { toast } = useToast() as { toast: (a: string, b?: string) => void };

  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectFilter, setProjectFilter] = useState<number | 'all'>('all');
  const [quickOpen, setQuickOpen] = useState<boolean>(false);
  const [draggingId, setDraggingId] = useState<number | null>(null);
  const [dragOverCol, setDragOverCol] = useState<HStatus | null>(null);
  const [viewerId, setViewerId] = useState<number | null>(null);
  const [viewerNote, setViewerNote] = useState<Note | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: { project_id?: number } = {};
      if (projectFilter !== 'all') params.project_id = projectFilter;
      const result = await listHypotheses(params);
      setNotes(result.data);
    } catch (err: any) {
      toast(`Failed to load hypotheses: ${err?.message || err}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [projectFilter, toast]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    getProjects().then(setProjects).catch(() => { /* ignore */ });
  }, []);

  // Load full content when opening the card viewer.
  useEffect(() => {
    let cancelled = false;
    if (viewerId == null) { setViewerNote(null); return; }
    (async () => {
      try {
        const full = await getNote(viewerId);
        if (!cancelled) setViewerNote(full);
      } catch (err: any) {
        if (!cancelled) toast(`Failed to load note: ${err?.message || err}`, 'error');
      }
    })();
    return () => { cancelled = true; };
  }, [viewerId, toast]);

  // Group notes by column.
  const grouped = useMemo(() => {
    const map: Record<HStatus, Note[]> = {
      open: [], investigating: [], confirmed: [], disproved: [],
    };
    for (const n of notes) {
      const s = normalizeStatus(n.status);
      map[s].push(n);
    }
    // Most recent first within each column.
    (Object.keys(map) as HStatus[]).forEach(k => {
      map[k].sort((a, b) => (b.updated_at || '').localeCompare(a.updated_at || ''));
    });
    return map;
  }, [notes]);

  const onDragStart = (id: number) => (e: React.DragEvent) => {
    setDraggingId(id);
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', String(id));
  };

  const onDragEnd = () => {
    setDraggingId(null);
    setDragOverCol(null);
  };

  const onDragOverCol = (col: HStatus) => (e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (dragOverCol !== col) setDragOverCol(col);
  };

  const onDropCol = (col: HStatus) => async (e: React.DragEvent) => {
    e.preventDefault();
    const idStr = e.dataTransfer.getData('text/plain');
    const id = Number(idStr);
    setDragOverCol(null);
    setDraggingId(null);
    if (!id) return;

    const note = notes.find(n => n.id === id);
    if (!note) return;
    if (normalizeStatus(note.status) === col) return;

    // Optimistic update.
    setNotes(prev => prev.map(n => (n.id === id ? { ...n, status: col } : n)));

    try {
      await updateNote(id, { status: col });
      toast(`Moved to ${col}`, 'success');
    } catch (err: any) {
      // Revert on failure.
      setNotes(prev => prev.map(n => (n.id === id ? { ...n, status: note.status } : n)));
      toast(`Failed to update: ${err?.message || err}`, 'error');
    }
  };

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        marginBottom: 18,
      }}>
        <div>
          <h2 style={{
            fontSize: 22,
            fontWeight: 700,
            color: 'var(--text)',
            margin: 0,
            letterSpacing: '-0.3px',
          }}>
            Hypothesis Board
          </h2>
          <p style={{ color: 'var(--muted)', fontSize: 12, margin: '3px 0 0' }}>
            Track research hypotheses from idea to confirmed vulnerability.
          </p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <select
            value={projectFilter === 'all' ? 'all' : String(projectFilter)}
            onChange={e => setProjectFilter(e.target.value === 'all' ? 'all' : Number(e.target.value))}
            style={{
              padding: '7px 12px',
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              color: 'var(--text)',
              fontSize: 12,
              outline: 'none',
              minWidth: 170,
            }}
          >
            <option value="all">All projects</option>
            {projects.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <button
            onClick={() => setQuickOpen(true)}
            style={{
              padding: '8px 16px',
              background: 'var(--orange)',
              color: '#000',
              border: 'none',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 700,
              cursor: 'pointer',
              letterSpacing: 0.2,
            }}
          >
            + New Hypothesis
          </button>
        </div>
      </div>

      {/* Board */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
        gap: 12,
        alignItems: 'flex-start',
      }}>
        {COLUMNS.map(col => {
          const colNotes = grouped[col.id];
          const isOver = dragOverCol === col.id;
          return (
            <div
              key={col.id}
              onDragOver={onDragOverCol(col.id)}
              onDrop={onDropCol(col.id)}
              onDragLeave={() => { if (dragOverCol === col.id) setDragOverCol(null); }}
              style={{
                background: 'var(--surface)',
                border: `1px solid ${isOver ? col.color : 'var(--border)'}`,
                borderRadius: 8,
                padding: 10,
                minHeight: 320,
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                transition: 'border-color 0.15s, background 0.15s',
                boxShadow: isOver ? `0 0 0 2px ${col.color}22` : 'none',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '2px 4px 8px', borderBottom: `1px solid ${col.color}33` }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: col.color, flexShrink: 0 }} />
                <span style={{ color: 'var(--text)', fontSize: 12, fontWeight: 700, letterSpacing: 0.3, textTransform: 'uppercase' }}>
                  {col.label}
                </span>
                <span style={{
                  marginLeft: 'auto', fontSize: 10, color: col.color,
                  background: `${col.color}22`, border: `1px solid ${col.color}44`,
                  borderRadius: 10, padding: '1px 7px', fontWeight: 700,
                }}>
                  {colNotes.length}
                </span>
              </div>

              {loading && <ColumnSkeleton />}

              {!loading && colNotes.length === 0 && (
                <div style={{
                  padding: '16px 8px', textAlign: 'center', color: 'var(--muted)',
                  fontSize: 11, fontStyle: 'italic', border: '1px dashed var(--border)',
                  borderRadius: 6, marginTop: 6,
                }}>
                  No hypotheses here
                </div>
              )}

              {!loading && colNotes.map(n => (
                <HypothesisCard
                  key={n.id}
                  note={n}
                  dragging={draggingId === n.id}
                  onDragStart={onDragStart(n.id)}
                  onDragEnd={onDragEnd}
                  onClick={() => setViewerId(n.id)}
                />
              ))}
            </div>
          );
        })}
      </div>

      {/* QuickCapture for hypothesis (pre-set type). */}
      <QuickCapture
        open={quickOpen}
        onClose={() => setQuickOpen(false)}
        defaultProjectId={projectFilter === 'all' ? undefined : projectFilter}
        defaultType="hypothesis"
        onCreated={() => { void load(); }}
      />

      {/* Note viewer */}
      <Modal
        open={viewerId != null}
        onClose={() => setViewerId(null)}
        title={viewerNote?.title || 'Hypothesis'}
        width={640}
      >
        {!viewerNote && (
          <div style={{ padding: 20, color: 'var(--muted)', fontSize: 13 }}>Loading...</div>
        )}
        {viewerNote && (
          <div style={{ padding: 20 }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              marginBottom: 14,
              flexWrap: 'wrap',
            }}>
              <span style={{
                fontSize: 11,
                color: 'var(--orange)',
                background: 'var(--orange)22',
                border: '1px solid var(--orange)44',
                borderRadius: 3,
                padding: '2px 8px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: 0.4,
              }}>
                Hypothesis
              </span>
              <span style={{
                fontSize: 10,
                color: 'var(--text)',
                background: 'var(--surface-2)',
                border: '1px solid var(--border)',
                borderRadius: 3,
                padding: '2px 8px',
                textTransform: 'uppercase',
                letterSpacing: 0.3,
                fontWeight: 600,
              }}>
                {normalizeStatus(viewerNote.status)}
              </span>
              <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--muted)' }}>
                Updated {relativeTime(viewerNote.updated_at)}
              </span>
            </div>

            {viewerNote.confidence !== undefined && viewerNote.confidence !== null && (
              <div style={{ marginBottom: 12 }}>
                <div style={viewerLabelStyle}>
                  Confidence: {confidencePercent(viewerNote.confidence)}%
                </div>
                <ConfidenceBar pct={confidencePercent(viewerNote.confidence)} />
              </div>
            )}

            <div style={{
              whiteSpace: 'pre-wrap',
              fontSize: 13,
              color: 'var(--text)',
              lineHeight: 1.55,
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              padding: 14,
              maxHeight: '55vh',
              overflow: 'auto',
            }}>
              {viewerNote.content || '(no content)'}
            </div>

            {normalizeTags(viewerNote.tags).length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 10 }}>
                {normalizeTags(viewerNote.tags).map((t, i) => (
                  <span key={i} style={tagChipStyle}>#{t}</span>
                ))}
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}

interface HypothesisCardProps {
  note: Note;
  dragging: boolean;
  onDragStart: (e: React.DragEvent) => void;
  onDragEnd: () => void;
  onClick: () => void;
}

function HypothesisCard({ note, dragging, onDragStart, onDragEnd, onClick }: HypothesisCardProps) {
  const status = normalizeStatus(note.status);
  const col = COLUMNS.find(c => c.id === status) ?? COLUMNS[0];
  const pct = confidencePercent(note.confidence);
  const tags = normalizeTags(note.tags).slice(0, 4);
  const fids = normalizeFindings(note.finding_ids);

  return (
    <div
      draggable
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
      onClick={onClick}
      style={{
        background: 'var(--bg)',
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${col.color}`,
        borderRadius: 6,
        padding: 10,
        cursor: 'grab',
        opacity: dragging ? 0.4 : 1,
        transform: dragging ? 'scale(0.98)' : 'scale(1)',
        transition: 'opacity 0.15s, transform 0.15s, background 0.12s',
        userSelect: 'none',
      }}
      onMouseEnter={e => {
        if (!dragging) (e.currentTarget as HTMLDivElement).style.background = 'var(--surface-2)';
      }}
      onMouseLeave={e => {
        if (!dragging) (e.currentTarget as HTMLDivElement).style.background = 'var(--bg)';
      }}
    >
      {/* Title */}
      <div style={{
        color: 'var(--text)',
        fontSize: 13,
        fontWeight: 600,
        lineHeight: 1.35,
        marginBottom: 6,
        display: '-webkit-box',
        WebkitLineClamp: 2,
        WebkitBoxOrient: 'vertical',
        overflow: 'hidden',
      }}>
        {note.title || '(untitled)'}
      </div>

      {/* Confidence bar */}
      <div style={{ marginBottom: 7 }}>
        <ConfidenceBar pct={pct} small />
      </div>

      {/* Tags */}
      {tags.length > 0 && (
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 3,
          marginBottom: 6,
        }}>
          {tags.map((t, i) => (
            <span key={i} style={tagChipStyle}>#{t}</span>
          ))}
        </div>
      )}

      {/* Footer */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        fontSize: 10,
        color: 'var(--muted)',
      }}>
        {fids.length > 0 && (
          <span title={`${fids.length} linked finding(s)`} style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 3,
          }}>
            <span style={{
              display: 'inline-block',
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: 'var(--blue)',
            }} />
            {fids.length} linked
          </span>
        )}
        <span style={{ marginLeft: 'auto' }}>{relativeTime(note.updated_at)}</span>
      </div>
    </div>
  );
}

function ConfidenceBar({ pct, small }: { pct: number; small?: boolean }) {
  // Pick a color ramp based on pct.
  const color =
    pct >= 75 ? 'var(--green)' :
    pct >= 50 ? 'var(--yellow)' :
    pct >= 25 ? 'var(--orange)' :
    'var(--red)';

  return (
    <div style={{
      position: 'relative',
      height: small ? 4 : 6,
      background: 'var(--surface-2)',
      borderRadius: 2,
      overflow: 'hidden',
    }}>
      <div style={{
        height: '100%',
        width: `${pct}%`,
        background: color,
        transition: 'width 0.25s',
      }} />
    </div>
  );
}

function ColumnSkeleton() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {[0, 1].map(i => (
        <div key={i} style={{
          height: 72,
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          opacity: 0.45,
          animation: 'pulse 1.4s ease-in-out infinite',
        }} />
      ))}
      <style>{`@keyframes pulse { 0%,100% { opacity: 0.3 } 50% { opacity: 0.55 } }`}</style>
    </div>
  );
}

const tagChipStyle: React.CSSProperties = {
  fontSize: 10,
  color: 'var(--muted)',
  background: 'var(--surface-2)',
  border: '1px solid var(--border)',
  borderRadius: 3,
  padding: '1px 5px',
  lineHeight: 1.4,
};

const viewerLabelStyle: React.CSSProperties = {
  fontSize: 10,
  color: 'var(--muted)',
  textTransform: 'uppercase',
  letterSpacing: 0.3,
  fontWeight: 600,
  marginBottom: 4,
};

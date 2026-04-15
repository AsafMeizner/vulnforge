import { useState, useEffect, useCallback } from 'react';
import { useToast } from '@/components/Toast';
import { Modal } from '@/components/Modal';
import { listNotes, getNote, type Note } from '@/lib/api';
import { QuickCapture } from '@/components/QuickCapture';

interface NotesPanelProps {
  projectId?: number;
  findingId?: number;
  onNoteClick?: (noteId: number) => void;
  initiallyOpen?: boolean;
}

type SubTab = 'all' | 'hypothesis' | 'observation' | 'todo';

// ── Helpers ─────────────────────────────────────────────────────────────────

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

function truncate(text: string | undefined, len: number): string {
  if (!text) return '';
  if (text.length <= len) return text;
  return text.slice(0, len - 1) + '\u2026';
}

// Color mapping for note types (left border stripe).
function typeColor(type: string): string {
  switch (type) {
    case 'hypothesis':   return 'var(--orange)';
    case 'observation':  return 'var(--blue)';
    case 'exploit-idea': return 'var(--red)';
    case 'todo':         return 'var(--green)';
    default:             return 'var(--muted)';
  }
}

// Small square icon for each type.
function TypeIcon({ type }: { type: string }) {
  const color = typeColor(type);
  const glyph = (() => {
    switch (type) {
      case 'hypothesis':   return '\u2699';     // gear
      case 'observation':  return '\u25CE';     // bullseye
      case 'exploit-idea': return '\u26A1';     // bolt
      case 'todo':         return '\u2713';     // check
      default:             return '\u270E';     // pencil
    }
  })();
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      width: 20,
      height: 20,
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 700,
      color,
      background: `${color}22`,
      border: `1px solid ${color}44`,
      flexShrink: 0,
    }}>
      {glyph}
    </span>
  );
}

// ── Main Component ──────────────────────────────────────────────────────────

export function NotesPanel({
  projectId,
  findingId,
  onNoteClick,
  initiallyOpen = true,
}: NotesPanelProps) {
  const { toast } = useToast() as { toast: (msg: string, type?: 'success' | 'error' | 'info') => void };

  const [open, setOpen] = useState<boolean>(initiallyOpen);
  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [tab, setTab] = useState<SubTab>('all');
  const [quickOpen, setQuickOpen] = useState<boolean>(false);
  const [viewerId, setViewerId] = useState<number | null>(null);
  const [viewerNote, setViewerNote] = useState<Note | null>(null);

  const load = useCallback(async () => {
    if (!open) return;
    setLoading(true);
    try {
      const result = await listNotes({ project_id: projectId, finding_id: findingId, limit: 100 });
      // Sort most recent first (updated_at desc).
      const sorted = [...result.data].sort((a, b) =>
        (b.updated_at || '').localeCompare(a.updated_at || '')
      );
      setNotes(sorted);
    } catch (err: any) {
      toast(`Failed to load notes: ${err?.message || err}`, 'error');
    } finally {
      setLoading(false);
    }
  }, [open, projectId, findingId, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  // Load full content when opening the in-panel viewer.
  useEffect(() => {
    let cancelled = false;
    if (viewerId == null) {
      setViewerNote(null);
      return;
    }
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

  const filtered = notes.filter(n => {
    if (tab === 'all') return true;
    return n.type === tab;
  });

  const count = notes.length;

  const handleNoteClick = (noteId: number) => {
    if (onNoteClick) {
      onNoteClick(noteId);
    } else {
      setViewerId(noteId);
    }
  };

  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 8,
      background: 'var(--surface)',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          width: '100%',
          padding: '10px 14px',
          background: 'var(--surface-2)',
          border: 'none',
          borderBottom: open ? '1px solid var(--border)' : 'none',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          cursor: 'pointer',
          color: 'var(--text)',
          fontSize: 13,
          fontWeight: 600,
          textAlign: 'left',
        }}
      >
        <span style={{
          display: 'inline-block',
          width: 10,
          transition: 'transform 0.15s',
          transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
          color: 'var(--muted)',
        }}>
          &#9656;
        </span>
        <span>Notes</span>
        <span style={{
          fontSize: 11,
          color: 'var(--muted)',
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 10,
          padding: '1px 8px',
          fontWeight: 600,
        }}>
          {count}
        </span>
        <span
          onClick={(e) => { e.stopPropagation(); setQuickOpen(true); setOpen(true); }}
          style={{
            marginLeft: 'auto',
            padding: '4px 10px',
            background: 'var(--blue)22',
            color: 'var(--blue)',
            border: '1px solid var(--blue)44',
            borderRadius: 4,
            fontSize: 11,
            fontWeight: 600,
            cursor: 'pointer',
            userSelect: 'none',
          }}
        >
          + New note
        </span>
      </button>

      {/* Body */}
      {open && (
        <div style={{ padding: 12 }}>
          {/* Sub-tabs */}
          <div style={{
            display: 'flex',
            gap: 4,
            marginBottom: 10,
            padding: 3,
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: 6,
          }}>
            {([
              ['all', 'All'],
              ['hypothesis', 'Hypotheses'],
              ['observation', 'Observations'],
              ['todo', 'Todos'],
            ] as const).map(([key, label]) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                style={{
                  flex: 1,
                  padding: '5px 0',
                  border: 'none',
                  background: tab === key ? 'var(--surface-2)' : 'transparent',
                  color: tab === key ? 'var(--text)' : 'var(--muted)',
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: 'pointer',
                  borderRadius: 4,
                  letterSpacing: 0.2,
                }}
              >
                {label}
              </button>
            ))}
          </div>

          {/* List / states */}
          {loading && <SkeletonRows />}

          {!loading && filtered.length === 0 && (
            <EmptyState
              onCreate={() => setQuickOpen(true)}
              tab={tab}
            />
          )}

          {!loading && filtered.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {filtered.map(n => (
                <NoteRow key={n.id} note={n} onClick={() => handleNoteClick(n.id)} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* QuickCapture modal */}
      <QuickCapture
        open={quickOpen}
        onClose={() => setQuickOpen(false)}
        defaultProjectId={projectId}
        defaultFindingId={findingId}
        defaultType={tab === 'all' ? 'note' : (tab as any)}
        onCreated={() => { void load(); }}
      />

      {/* In-panel viewer modal */}
      <Modal
        open={viewerId != null}
        onClose={() => setViewerId(null)}
        title={viewerNote?.title || 'Note'}
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
              gap: 8,
              marginBottom: 12,
              flexWrap: 'wrap',
            }}>
              <TypeIcon type={viewerNote.type} />
              <span style={{
                fontSize: 11,
                color: typeColor(viewerNote.type),
                textTransform: 'uppercase',
                letterSpacing: 0.4,
                fontWeight: 700,
              }}>
                {viewerNote.type}
              </span>
              {viewerNote.status && (
                <span style={{
                  fontSize: 10,
                  color: 'var(--muted)',
                  background: 'var(--bg)',
                  border: '1px solid var(--border)',
                  borderRadius: 3,
                  padding: '1px 6px',
                }}>
                  {viewerNote.status}
                </span>
              )}
              <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--muted)' }}>
                {relativeTime(viewerNote.updated_at)}
              </span>
            </div>
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

// ── Sub-components ──────────────────────────────────────────────────────────

function NoteRow({ note, onClick }: { note: Note; onClick: () => void }) {
  const color = typeColor(note.type);
  const tags = normalizeTags(note.tags);
  return (
    <div
      onClick={onClick}
      style={{
        display: 'flex',
        gap: 10,
        padding: 10,
        borderRadius: 6,
        background: 'var(--bg)',
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${color}`,
        cursor: 'pointer',
        transition: 'background 0.12s, border-color 0.12s',
      }}
      onMouseEnter={e => {
        (e.currentTarget as HTMLDivElement).style.background = 'var(--surface-2)';
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLDivElement).style.background = 'var(--bg)';
      }}
    >
      <TypeIcon type={note.type} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 3,
        }}>
          <span style={{
            color: 'var(--text)',
            fontSize: 13,
            fontWeight: 600,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            flex: 1,
            minWidth: 0,
          }}>
            {note.title || '(untitled)'}
          </span>
          <span style={{
            color: 'var(--muted)',
            fontSize: 10,
            flexShrink: 0,
          }}>
            {relativeTime(note.updated_at)}
          </span>
        </div>
        {note.content && (
          <div style={{
            color: 'var(--muted)',
            fontSize: 11,
            lineHeight: 1.4,
            overflow: 'hidden',
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
          }}>
            {truncate(note.content, 120)}
          </div>
        )}
        {tags.length > 0 && (
          <div style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 3,
            marginTop: 5,
          }}>
            {tags.slice(0, 6).map((t, i) => (
              <span key={i} style={tagChipStyle}>#{t}</span>
            ))}
            {tags.length > 6 && (
              <span style={{ fontSize: 10, color: 'var(--muted)' }}>+{tags.length - 6}</span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function SkeletonRows() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {[0, 1, 2].map(i => (
        <div key={i} style={{
          padding: 10,
          height: 54,
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          opacity: 0.5,
          animation: 'pulse 1.4s ease-in-out infinite',
        }}>
          <div style={{ width: '40%', height: 10, background: 'var(--surface-2)', borderRadius: 3, marginBottom: 6 }} />
          <div style={{ width: '85%', height: 8, background: 'var(--surface-2)', borderRadius: 3 }} />
        </div>
      ))}
      <style>{`@keyframes pulse { 0%,100% { opacity: 0.35 } 50% { opacity: 0.6 } }`}</style>
    </div>
  );
}

function EmptyState({ onCreate, tab }: { onCreate: () => void; tab: SubTab }) {
  const label = tab === 'all' ? 'notes' : tab === 'hypothesis' ? 'hypotheses' : tab === 'observation' ? 'observations' : 'todos';
  return (
    <div style={{
      padding: '20px 16px',
      textAlign: 'center',
      border: '1px dashed var(--border)',
      borderRadius: 6,
      background: 'var(--bg)',
    }}>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8 }}>
        No {label} yet. Press <kbd style={kbdStyle}>Ctrl+N</kbd> or click below to add one.
      </div>
      <button
        onClick={onCreate}
        style={{
          padding: '6px 14px',
          background: 'var(--blue)22',
          color: 'var(--blue)',
          border: '1px solid var(--blue)44',
          borderRadius: 4,
          fontSize: 11,
          fontWeight: 600,
          cursor: 'pointer',
        }}
      >
        + New note
      </button>
    </div>
  );
}

// ── Styles ──────────────────────────────────────────────────────────────────

const tagChipStyle: React.CSSProperties = {
  fontSize: 10,
  color: 'var(--muted)',
  background: 'var(--surface-2)',
  border: '1px solid var(--border)',
  borderRadius: 3,
  padding: '1px 5px',
  lineHeight: 1.4,
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

export default NotesPanel;

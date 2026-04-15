import { useState, useEffect, useRef, useCallback } from 'react';
import { useToast } from '@/components/Toast';
import { Modal } from '@/components/Modal';
import { createNote } from '@/lib/api';

type NoteType = 'note' | 'hypothesis' | 'observation' | 'exploit-idea' | 'todo';
type HypothesisStatus = 'open' | 'investigating' | 'confirmed' | 'disproved';

interface QuickCaptureProps {
  open: boolean;
  onClose: () => void;
  defaultProjectId?: number;
  defaultFindingId?: number;
  defaultType?: NoteType;
  onCreated?: (noteId: number) => void;
}

interface DraftState {
  title: string;
  type: NoteType;
  tags: string;
  content: string;
  status: HypothesisStatus;
  confidence: number;
}

const DRAFT_KEY = 'quick-capture-draft';

const TYPE_OPTIONS: Array<{ value: NoteType; label: string; color: string }> = [
  { value: 'note',         label: 'Note',         color: 'var(--muted)'  },
  { value: 'hypothesis',   label: 'Hypothesis',   color: 'var(--orange)' },
  { value: 'observation',  label: 'Observation',  color: 'var(--blue)'   },
  { value: 'exploit-idea', label: 'Exploit Idea', color: 'var(--red)'    },
  { value: 'todo',         label: 'Todo',         color: 'var(--green)'  },
];

const STATUS_OPTIONS: HypothesisStatus[] = ['open', 'investigating', 'confirmed', 'disproved'];

function emptyDraft(defaultType: NoteType): DraftState {
  return {
    title: '',
    type: defaultType,
    tags: '',
    content: '',
    status: 'open',
    confidence: 50,
  };
}

function loadDraft(): DraftState | null {
  try {
    const raw = sessionStorage.getItem(DRAFT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return parsed as DraftState;
    return null;
  } catch {
    return null;
  }
}

function saveDraft(draft: DraftState) {
  try {
    sessionStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
  } catch { /* ignore quota errors */ }
}

function clearDraft() {
  try { sessionStorage.removeItem(DRAFT_KEY); } catch { /* ignore */ }
}

export function QuickCapture({
  open,
  onClose,
  defaultProjectId,
  defaultFindingId,
  defaultType = 'note',
  onCreated,
}: QuickCaptureProps) {
  const { toast } = useToast() as { toast: (msg: string, type?: 'success' | 'error' | 'info') => void };

  const [state, setState] = useState<DraftState>(() => emptyDraft(defaultType));
  const [submitting, setSubmitting] = useState(false);
  const titleRef = useRef<HTMLInputElement>(null);

  // On open: restore draft (if any) or seed with default type.
  useEffect(() => {
    if (!open) return;
    const draft = loadDraft();
    if (draft) {
      setState(draft);
    } else {
      setState(emptyDraft(defaultType));
    }
    // Auto-focus title once the modal renders.
    const t = setTimeout(() => titleRef.current?.focus(), 40);
    return () => clearTimeout(t);
  }, [open, defaultType]);

  // Auto-save draft every 2s while dirty.
  useEffect(() => {
    if (!open) return;
    const dirty = state.title.trim() || state.content.trim() || state.tags.trim();
    if (!dirty) return;
    const t = setTimeout(() => saveDraft(state), 2000);
    return () => clearTimeout(t);
  }, [state, open]);

  const parseTags = (raw: string): string[] =>
    raw.split(',').map(t => t.trim()).filter(Boolean);

  const handleSubmit = useCallback(async () => {
    const title = state.title.trim();
    const content = state.content.trim();
    if (!title) {
      toast('Title is required', 'error');
      titleRef.current?.focus();
      return;
    }
    if (!content) {
      toast('Content is required', 'error');
      return;
    }

    setSubmitting(true);
    try {
      const body: any = {
        title,
        content,
        type: state.type,
        tags: parseTags(state.tags),
      };
      if (defaultProjectId !== undefined) body.project_id = defaultProjectId;
      if (defaultFindingId !== undefined) body.finding_ids = [defaultFindingId];
      if (state.type === 'hypothesis') {
        body.status = state.status;
        body.confidence = state.confidence / 100; // 0-1 range
      }

      const note = await createNote(body);
      toast('Note saved', 'success');
      clearDraft();
      setState(emptyDraft(defaultType));
      onCreated?.(note.id);
      onClose();
    } catch (err: any) {
      toast(`Failed to save note: ${err?.message || err}`, 'error');
    } finally {
      setSubmitting(false);
    }
  }, [state, defaultProjectId, defaultFindingId, defaultType, onCreated, onClose, toast]);

  // Keyboard shortcut inside the modal: Ctrl/Cmd + Enter -> submit.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        void handleSubmit();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, handleSubmit]);

  const patch = (p: Partial<DraftState>) => setState(prev => ({ ...prev, ...p }));

  // Compute dynamic textarea rows based on line count (min 8 / max 20).
  const contentRows = Math.max(8, Math.min(20, state.content.split('\n').length + 1));

  const selectedType = TYPE_OPTIONS.find(t => t.value === state.type) ?? TYPE_OPTIONS[0];

  return (
    <Modal open={open} onClose={onClose} title="Quick Capture" width={620}>
      <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
        {/* Title */}
        <div>
          <label style={labelStyle}>Title</label>
          <input
            ref={titleRef}
            value={state.title}
            onChange={e => patch({ title: e.target.value })}
            placeholder="What is this about?"
            style={inputStyle}
          />
        </div>

        {/* Type + Tags row */}
        <div style={{ display: 'flex', gap: 10 }}>
          <div style={{ width: 180 }}>
            <label style={labelStyle}>Type</label>
            <select
              value={state.type}
              onChange={e => patch({ type: e.target.value as NoteType })}
              style={{
                ...inputStyle,
                borderLeft: `3px solid ${selectedType.color}`,
              }}
            >
              {TYPE_OPTIONS.map(opt => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
          <div style={{ flex: 1 }}>
            <label style={labelStyle}>Tags</label>
            <input
              value={state.tags}
              onChange={e => patch({ tags: e.target.value })}
              placeholder="auth, sqli, openssl (comma separated)"
              style={inputStyle}
            />
          </div>
        </div>

        {/* Hypothesis-only extras */}
        {state.type === 'hypothesis' && (
          <div style={{
            display: 'flex',
            gap: 12,
            padding: 10,
            background: 'var(--bg)',
            border: '1px solid var(--orange)33',
            borderRadius: 6,
          }}>
            <div style={{ width: 180 }}>
              <label style={labelStyle}>Status</label>
              <select
                value={state.status}
                onChange={e => patch({ status: e.target.value as HypothesisStatus })}
                style={inputStyle}
              >
                {STATUS_OPTIONS.map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div style={{ flex: 1 }}>
              <label style={labelStyle}>Confidence: {state.confidence}%</label>
              <input
                type="range"
                min={0}
                max={100}
                step={5}
                value={state.confidence}
                onChange={e => patch({ confidence: Number(e.target.value) })}
                style={{
                  width: '100%',
                  accentColor: 'var(--orange)',
                  marginTop: 8,
                  cursor: 'pointer',
                }}
              />
            </div>
          </div>
        )}

        {/* Content */}
        <div>
          <label style={labelStyle}>Content</label>
          <textarea
            value={state.content}
            onChange={e => patch({ content: e.target.value })}
            placeholder="Markdown-friendly. Describe the observation, idea, or hypothesis..."
            rows={contentRows}
            style={{
              ...inputStyle,
              fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
              fontSize: 12,
              lineHeight: 1.55,
              resize: 'vertical',
              minHeight: 160,
              maxHeight: 440,
            }}
          />
        </div>

        {/* Footer */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          marginTop: 4,
          paddingTop: 10,
          borderTop: '1px solid var(--border)',
        }}>
          <span style={{ fontSize: 11, color: 'var(--muted)' }}>
            <kbd style={kbdStyle}>Ctrl</kbd>+<kbd style={kbdStyle}>Enter</kbd> to save
            &nbsp;&middot;&nbsp;
            <kbd style={kbdStyle}>Esc</kbd> to close
          </span>
          <span style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <button
              onClick={onClose}
              disabled={submitting}
              style={{
                padding: '7px 14px',
                background: 'transparent',
                border: '1px solid var(--border)',
                borderRadius: 6,
                color: 'var(--muted)',
                fontSize: 12,
                fontWeight: 600,
                cursor: submitting ? 'not-allowed' : 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={submitting}
              style={{
                padding: '7px 18px',
                background: submitting ? 'var(--surface-2)' : 'var(--blue)',
                border: 'none',
                borderRadius: 6,
                color: submitting ? 'var(--muted)' : '#fff',
                fontSize: 12,
                fontWeight: 700,
                cursor: submitting ? 'not-allowed' : 'pointer',
                letterSpacing: 0.3,
              }}
            >
              {submitting ? 'Saving\u2026' : 'Save'}
            </button>
          </span>
        </div>
      </div>
    </Modal>
  );
}

// ── Styles ──────────────────────────────────────────────────────────────────

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: 11,
  color: 'var(--muted)',
  marginBottom: 4,
  letterSpacing: 0.3,
  textTransform: 'uppercase',
  fontWeight: 600,
};

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '8px 12px',
  boxSizing: 'border-box',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  color: 'var(--text)',
  fontSize: 13,
  outline: 'none',
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

export default QuickCapture;

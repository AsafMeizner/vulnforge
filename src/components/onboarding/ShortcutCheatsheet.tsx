/**
 * Keyboard-shortcut cheatsheet modal.
 *
 * Self-contained — manages its own open/close state and listens for a
 * global `?` keypress. Can also be opened programmatically via the imperative
 * API returned from `useShortcutCheatsheet()`.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { SHORTCUT_CATEGORIES, type ShortcutCategory } from '@/lib/tours/shortcuts';

export interface ShortcutCheatsheetProps {
  /** Controlled open state. Omit to use the built-in `?` hotkey. */
  open?: boolean;
  /** Close callback. Required when `open` is provided. */
  onClose?: () => void;
  /** Override the shortcut catalog (primarily for tests). */
  categories?: ShortcutCategory[];
  /**
   * When true (default), register a global `?` key handler that toggles the
   * modal. Set to false when another component already owns `?` routing.
   */
  enableHotkey?: boolean;
}

/** Returns true when the event target is an editable element. */
export function isEditableTarget(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) {
    return true;
  }
  return el.isContentEditable;
}

export function ShortcutCheatsheet(props: ShortcutCheatsheetProps) {
  const {
    open: controlledOpen,
    onClose,
    categories = SHORTCUT_CATEGORIES,
    enableHotkey = true,
  } = props;

  const isControlled = typeof controlledOpen === 'boolean';
  const [internalOpen, setInternalOpen] = useState(false);
  const open = isControlled ? !!controlledOpen : internalOpen;

  const close = useCallback(() => {
    if (isControlled) {
      onClose?.();
    } else {
      setInternalOpen(false);
    }
  }, [isControlled, onClose]);

  const openSelf = useCallback(() => {
    if (!isControlled) setInternalOpen(true);
  }, [isControlled]);

  // Global `?` hotkey. Only active when we're uncontrolled AND the flag
  // is on, so we never double-up with the lead's own hotkey handler.
  useEffect(() => {
    if (isControlled || !enableHotkey) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key !== '?') return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (isEditableTarget(e.target)) return;
      e.preventDefault();
      setInternalOpen(prev => !prev);
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [isControlled, enableHotkey]);

  // Esc-to-close when open.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, close]);

  const groups = useMemo(() => categories, [categories]);

  if (!open) return null;

  return (
    <div
      data-testid="shortcut-cheatsheet-root"
      onClick={close}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.65)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 2100,
        padding: 24,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        role="dialog"
        aria-labelledby="shortcut-cheatsheet-title"
        style={{
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 12,
          padding: 28,
          width: '100%',
          maxWidth: 760,
          maxHeight: '85vh',
          overflow: 'auto',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 id="shortcut-cheatsheet-title" style={{ margin: 0, color: 'var(--text)', fontSize: 20 }}>
            Keyboard shortcuts
          </h2>
          <kbd style={kbdStyle}>?</kbd>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 24,
          }}
        >
          {groups.map(group => (
            <div key={group.title} data-testid={`shortcut-category-${group.title}`}>
              <div
                style={{
                  fontSize: 11,
                  color: 'var(--muted)',
                  textTransform: 'uppercase',
                  letterSpacing: 0.5,
                  marginBottom: 10,
                  borderBottom: '1px solid var(--border)',
                  paddingBottom: 6,
                }}
              >
                {group.title}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {group.entries.map(entry => (
                  <div
                    key={`${group.title}::${entry.keys}::${entry.label}`}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      gap: 12,
                    }}
                  >
                    <span style={{ color: 'var(--text)', fontSize: 12 }}>{entry.label}</span>
                    <kbd style={kbdStyle}>{entry.keys}</kbd>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 20, display: 'flex', justifyContent: 'flex-end' }}>
          <button
            type="button"
            onClick={close}
            style={{
              padding: '8px 20px',
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              color: 'var(--text)',
              fontSize: 13,
              cursor: 'pointer',
            }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Imperative handle — the lead may wire this instead of mounting the
 * uncontrolled component so the `?` key stays in App.tsx.
 */
export function useShortcutCheatsheet() {
  const [open, setOpen] = useState(false);
  return {
    open,
    show: useCallback(() => setOpen(true), []),
    hide: useCallback(() => setOpen(false), []),
    toggle: useCallback(() => setOpen(v => !v), []),
  };
}

const kbdStyle: React.CSSProperties = {
  padding: '3px 10px',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 4,
  fontFamily: 'monospace',
  fontSize: 11,
  color: 'var(--text)',
  whiteSpace: 'nowrap',
};

export { openSelfHelper as __testOnlyOpenMarker };

// Internal helper kept as a named export so tests can detect accidental
// renames without pulling in the full component tree.
function openSelfHelper() {
  return 'shortcut-cheatsheet-open';
}

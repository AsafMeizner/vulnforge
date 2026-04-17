/**
 * Small contextual-help button.
 *
 * Usage:
 *   <HelpButton id="scanner.tool-selection" />
 *
 * Renders a circular `?` icon. On hover it shows a tooltip with a short
 * explanation; on click it navigates to the relevant documentation page
 * (deep-linked from `help-content.ts`).
 */
import { useCallback, useRef, useState } from 'react';
import { getHelp } from '@/lib/tours/help-content';

export interface HelpButtonProps {
  /** Key into `HELP_CONTENT`. */
  id: string;
  /** Optional label override for screen readers (defaults to the help title). */
  ariaLabel?: string;
  /** Size in pixels — button and icon scale from here. Defaults to 16. */
  size?: number;
  /**
   * Inline style overrides (e.g. for aligning the button within a header).
   */
  style?: React.CSSProperties;
  /**
   * Custom click handler. If omitted, clicking opens `docLink` in a new tab
   * via `window.open(…, '_blank')`.
   */
  onClick?: (id: string) => void;
}

export function HelpButton({ id, ariaLabel, size = 16, style, onClick }: HelpButtonProps) {
  const help = getHelp(id);
  const [open, setOpen] = useState(false);
  const closeTimer = useRef<number | null>(null);

  const clearCloseTimer = useCallback(() => {
    if (closeTimer.current !== null) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  }, []);

  const scheduleClose = useCallback(() => {
    clearCloseTimer();
    closeTimer.current = window.setTimeout(() => setOpen(false), 120);
  }, [clearCloseTimer]);

  const handleClick = useCallback(() => {
    if (onClick) {
      onClick(id);
      return;
    }
    try {
      window.open(help.docLink, '_blank', 'noopener,noreferrer');
    } catch {
      // Non-browser environments — fall back to href navigation.
      try {
        window.location.href = help.docLink;
      } catch {
        /* swallow */
      }
    }
  }, [id, onClick, help.docLink]);

  return (
    <span
      style={{ position: 'relative', display: 'inline-flex', ...style }}
      onMouseEnter={() => {
        clearCloseTimer();
        setOpen(true);
      }}
      onMouseLeave={scheduleClose}
    >
      <button
        type="button"
        aria-label={ariaLabel ?? help.title}
        onClick={handleClick}
        onFocus={() => setOpen(true)}
        onBlur={scheduleClose}
        style={{
          width: size,
          height: size,
          borderRadius: '50%',
          border: '1px solid var(--border)',
          background: 'var(--surface-2)',
          color: 'var(--muted)',
          fontSize: Math.max(9, size - 6),
          lineHeight: 1,
          cursor: 'pointer',
          padding: 0,
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontWeight: 700,
        }}
      >
        ?
      </button>
      {open && (
        <span
          role="tooltip"
          style={{
            position: 'absolute',
            top: '100%',
            left: '50%',
            transform: 'translate(-50%, 6px)',
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            boxShadow: '0 8px 24px rgba(0,0,0,0.35)',
            padding: '10px 12px',
            width: 240,
            fontSize: 12,
            color: 'var(--text)',
            zIndex: 2200,
            pointerEvents: 'auto',
          }}
        >
          <div style={{ fontWeight: 600, marginBottom: 4 }}>{help.title}</div>
          <div style={{ color: 'var(--muted)', lineHeight: 1.45 }}>{help.text}</div>
          <div style={{ marginTop: 8 }}>
            <a
              href={help.docLink}
              target="_blank"
              rel="noopener noreferrer"
              onClick={e => e.stopPropagation()}
              style={{ fontSize: 11, color: 'var(--blue)', textDecoration: 'none' }}
            >
              Open docs -&gt;
            </a>
          </div>
        </span>
      )}
    </span>
  );
}

export default HelpButton;

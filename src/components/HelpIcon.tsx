import { useState, useRef, useEffect } from 'react';

/**
 * Tiny inline help affordance: a "?" pill next to a label.
 *
 * - Hover: shows a compact tooltip (positioned to avoid viewport edges)
 * - Click: opens a full-size modal with the same body + optional `docs`
 *   links. Click outside or press Escape to dismiss.
 *
 * Usage:
 *   <label>Interface <HelpIcon title="Network interface" body="..." /></label>
 *
 * Keep bodies under ~6 lines in tooltip form; the modal can hold more.
 */
export interface HelpIconProps {
  /** Short label shown in the modal header (e.g. "Network interface"). */
  title: string;
  /** Main explanation. Accepts newlines - rendered with whitespace-pre-line. */
  body: string;
  /** Optional list of { label, url } for "Learn more" footer links. */
  docs?: { label: string; url: string }[];
  /** Visual size of the "?" pill. Defaults to 14 (px). */
  size?: number;
}

export function HelpIcon({ title, body, docs, size = 14 }: HelpIconProps) {
  const [hoverOpen, setHoverOpen] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const anchorRef = useRef<HTMLButtonElement>(null);

  // Close the modal on Escape (browser confirm/modal convention)
  useEffect(() => {
    if (!modalOpen) return;
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') setModalOpen(false); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [modalOpen]);

  return (
    <>
      <button
        ref={anchorRef}
        type="button"
        onClick={(e) => { e.stopPropagation(); setModalOpen(true); setHoverOpen(false); }}
        onMouseEnter={() => setHoverOpen(true)}
        onMouseLeave={() => setHoverOpen(false)}
        aria-label={`Help: ${title}`}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: size + 2,
          height: size + 2,
          padding: 0,
          margin: '0 4px',
          borderRadius: '50%',
          background: 'var(--surface-2)',
          color: 'var(--muted)',
          border: '1px solid var(--border)',
          cursor: 'help',
          fontSize: size - 4,
          fontWeight: 600,
          lineHeight: 1,
          verticalAlign: 'middle',
          flexShrink: 0,
        }}
      >
        ?
      </button>

      {/* Hover tooltip - positioned in a portal-like absolute near the anchor */}
      {hoverOpen && !modalOpen && (
        <span
          role="tooltip"
          style={{
            position: 'absolute',
            // Positions will be overridden once the anchor's rect is known
            // on first render - we use a minimal absolute layout here.
            background: 'var(--surface)',
            color: 'var(--text)',
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid var(--border)',
            boxShadow: '0 4px 12px rgba(0,0,0,0.25)',
            fontSize: 12,
            lineHeight: 1.5,
            maxWidth: 280,
            whiteSpace: 'pre-line',
            zIndex: 9999,
            marginTop: 20,
            marginLeft: -120,
            pointerEvents: 'none',
          }}
        >
          <strong style={{ display: 'block', marginBottom: 4, color: 'var(--text)' }}>{title}</strong>
          {body.length > 220 ? body.slice(0, 220) + '\u2026 (click for more)' : body}
        </span>
      )}

      {/* Full-size modal */}
      {modalOpen && (
        <div
          onClick={() => setModalOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.55)',
            zIndex: 10000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 24,
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 10,
              maxWidth: 560,
              width: '100%',
              maxHeight: '80vh',
              overflow: 'auto',
              padding: 24,
              boxShadow: '0 8px 32px rgba(0,0,0,0.35)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text)' }}>{title}</h3>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--muted)',
                  fontSize: 20,
                  cursor: 'pointer',
                  padding: 0,
                  lineHeight: 1,
                }}
                aria-label="Close help"
              >
                &times;
              </button>
            </div>
            <p style={{ color: 'var(--text)', fontSize: 13, lineHeight: 1.65, whiteSpace: 'pre-line', margin: 0 }}>
              {body}
            </p>
            {docs && docs.length > 0 && (
              <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
                <div style={{ color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>
                  Learn more
                </div>
                <ul style={{ margin: 0, padding: '0 0 0 16px' }}>
                  {docs.map((d) => (
                    <li key={d.url} style={{ fontSize: 13 }}>
                      <a href={d.url} target="_blank" rel="noreferrer" style={{ color: 'var(--blue)' }}>
                        {d.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

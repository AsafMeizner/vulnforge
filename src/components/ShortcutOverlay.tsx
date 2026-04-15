interface ShortcutOverlayProps {
  open: boolean;
  onClose: () => void;
}

const GROUPS: Array<{
  title: string;
  shortcuts: Array<{ keys: string; label: string }>;
}> = [
  {
    title: 'Global',
    shortcuts: [
      { keys: 'Ctrl+K', label: 'Command palette (jump anywhere)' },
      { keys: 'Ctrl+N', label: 'Quick-capture note' },
      { keys: '?', label: 'Show this shortcut overlay' },
      { keys: '/', label: 'Focus global search' },
      { keys: 'Esc', label: 'Close modal or clear search' },
    ],
  },
  {
    title: 'Findings list',
    shortcuts: [
      { keys: 'j', label: 'Next finding' },
      { keys: 'k', label: 'Previous finding' },
      { keys: 'Enter', label: 'Open finding detail' },
    ],
  },
  {
    title: 'Review queue',
    shortcuts: [
      { keys: '→ / j', label: 'Next finding' },
      { keys: '← / k', label: 'Previous finding' },
      { keys: 'a', label: 'Accept current finding' },
      { keys: 'r', label: 'Reject current finding' },
      { keys: 's', label: 'Skip' },
    ],
  },
  {
    title: 'Quick capture',
    shortcuts: [
      { keys: 'Ctrl+Enter', label: 'Save note' },
      { keys: 'Esc', label: 'Cancel' },
    ],
  },
];

export function ShortcutOverlay({ open, onClose }: ShortcutOverlayProps) {
  if (!open) return null;

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, background: '#000a', zIndex: 2100,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 12, padding: 28,
          width: '90%', maxWidth: 680, maxHeight: '85vh', overflow: 'auto',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ margin: 0, color: 'var(--text)', fontSize: 20 }}>Keyboard Shortcuts</h2>
          <kbd style={kbdStyle}>?</kbd>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 24 }}>
          {GROUPS.map(group => (
            <div key={group.title}>
              <div style={{
                fontSize: 11, color: 'var(--muted)',
                textTransform: 'uppercase', letterSpacing: 0.5,
                marginBottom: 10, borderBottom: '1px solid var(--border)', paddingBottom: 6,
              }}>
                {group.title}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {group.shortcuts.map(s => (
                  <div key={s.keys} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
                    <span style={{ color: 'var(--text)', fontSize: 12 }}>{s.label}</span>
                    <kbd style={kbdStyle}>{s.keys}</kbd>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div style={{ marginTop: 20, textAlign: 'center' }}>
          <button onClick={onClose} style={{
            padding: '8px 20px', background: 'var(--surface-2)',
            border: '1px solid var(--border)', borderRadius: 6,
            color: 'var(--text)', fontSize: 13, cursor: 'pointer',
          }}>Close</button>
        </div>
      </div>
    </div>
  );
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

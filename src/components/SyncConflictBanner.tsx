/**
 * Shown when the sync engine reports a server-side conflict for a row
 * we pushed. User picks "keep mine" / "keep theirs" / "merge fields".
 *
 * The actual merge isn't done in this banner - we just emit the user's
 * choice via onResolve. Caller performs the DB write and re-enqueues
 * the row with a newer updated_at_ms if "mine" was kept.
 */
import type { ConflictEvent } from '../lib/sync';

interface Props {
  conflict: ConflictEvent;
  local: Record<string, any> | null;
  onResolve: (choice: 'mine' | 'theirs' | 'merge') => void;
  onDismiss: () => void;
}

const card: React.CSSProperties = {
  position: 'fixed',
  bottom: 20,
  right: 20,
  width: 380,
  maxHeight: '60vh',
  overflowY: 'auto',
  background: 'var(--bg, white)',
  border: '1px solid #fcc',
  borderLeft: '4px solid #c33',
  borderRadius: 8,
  padding: 14,
  boxShadow: '0 8px 24px rgba(0,0,0,0.12)',
  fontFamily: 'system-ui',
  zIndex: 9999,
};
const btn: React.CSSProperties = {
  padding: '6px 10px',
  border: '1px solid #ccc',
  borderRadius: 5,
  background: '#fafafa',
  cursor: 'pointer',
  fontSize: 13,
  marginRight: 6,
  marginTop: 8,
};
const primary: React.CSSProperties = { ...btn, background: '#0a66c2', color: 'white', borderColor: 'transparent' };

export default function SyncConflictBanner({ conflict, local, onResolve, onDismiss }: Props) {
  const title = guessTitle(conflict.current, local);
  return (
    <div style={card}>
      <div style={{ fontSize: 12, color: '#888', textTransform: 'uppercase' }}>
        Sync conflict - {conflict.table}
      </div>
      <h4 style={{ margin: '4px 0 10px' }}>{title}</h4>
      <p style={{ fontSize: 13, color: '#555', margin: '0 0 10px' }}>
        Another teammate updated this row while you were editing. Pick which version wins.
      </p>
      <div>
        <button style={primary} onClick={() => onResolve('mine')}>Keep mine</button>
        <button style={btn} onClick={() => onResolve('theirs')}>Use theirs</button>
        <button style={btn} onClick={() => onResolve('merge')}>Merge fields</button>
        <button style={{ ...btn, marginLeft: 12 }} onClick={onDismiss}>Dismiss</button>
      </div>
    </div>
  );
}

function guessTitle(current: Record<string, any>, local: Record<string, any> | null): string {
  return String(
    current.title ?? local?.title ??
    current.name ?? local?.name ??
    current.sync_id ?? 'conflict',
  );
}

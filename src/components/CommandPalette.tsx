import { useState, useEffect, useRef, useCallback } from 'react';

export interface Command {
  id: string;
  title: string;
  category: string;
  shortcut?: string;
  action: () => void;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  commands: Command[];
}

export function CommandPalette({ open, onClose, commands }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Fuzzy filter
  const filtered = commands.filter(c => {
    if (!query) return true;
    const q = query.toLowerCase();
    return c.title.toLowerCase().includes(q) || c.category.toLowerCase().includes(q);
  });

  // Reset on open
  useEffect(() => {
    if (open) {
      setQuery('');
      setSelectedIdx(0);
      setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [open]);

  // Keyboard nav
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIdx(i => Math.min(i + 1, filtered.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIdx(i => Math.max(i - 1, 0));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const cmd = filtered[selectedIdx];
        if (cmd) {
          cmd.action();
          onClose();
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, filtered, selectedIdx, onClose]);

  // Reset selection when query changes
  useEffect(() => { setSelectedIdx(0); }, [query]);

  if (!open) return null;

  // Group by category
  const grouped: Record<string, Command[]> = {};
  for (const cmd of filtered) {
    if (!grouped[cmd.category]) grouped[cmd.category] = [];
    grouped[cmd.category].push(cmd);
  }

  let globalIdx = 0;

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: '#0008', zIndex: 2000,
        display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: '15vh',
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: '90%', maxWidth: 600,
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 10, overflow: 'hidden',
          boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Input */}
        <input
          ref={inputRef}
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Type a command..."
          style={{
            width: '100%', padding: '16px 20px',
            background: 'var(--bg)', color: 'var(--text)',
            border: 'none', borderBottom: '1px solid var(--border)',
            outline: 'none', fontSize: 15, boxSizing: 'border-box',
          }}
        />

        {/* Results */}
        <div style={{ maxHeight: '50vh', overflow: 'auto' }}>
          {filtered.length === 0 ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
              No commands match "{query}"
            </div>
          ) : (
            Object.entries(grouped).map(([category, cmds]) => (
              <div key={category}>
                <div style={{
                  padding: '6px 20px', fontSize: 10, color: 'var(--muted)',
                  textTransform: 'uppercase', letterSpacing: 0.5,
                  background: 'var(--surface-2)',
                }}>
                  {category}
                </div>
                {cmds.map(cmd => {
                  const idx = globalIdx++;
                  const isSelected = idx === selectedIdx;
                  return (
                    <div
                      key={cmd.id}
                      onClick={() => { cmd.action(); onClose(); }}
                      onMouseEnter={() => setSelectedIdx(idx)}
                      style={{
                        padding: '10px 20px',
                        background: isSelected ? 'var(--blue)22' : 'transparent',
                        borderLeft: `3px solid ${isSelected ? 'var(--blue)' : 'transparent'}`,
                        cursor: 'pointer',
                        display: 'flex', alignItems: 'center', gap: 10,
                      }}
                    >
                      <span style={{ color: 'var(--text)', fontSize: 13, flex: 1 }}>{cmd.title}</span>
                      {cmd.shortcut && (
                        <kbd style={{
                          padding: '2px 8px', fontSize: 10,
                          background: 'var(--surface-2)', border: '1px solid var(--border)',
                          borderRadius: 3, color: 'var(--muted)', fontFamily: 'monospace',
                        }}>{cmd.shortcut}</kbd>
                      )}
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer hint */}
        <div style={{
          padding: '8px 20px', borderTop: '1px solid var(--border)',
          fontSize: 10, color: 'var(--muted)',
          display: 'flex', gap: 16, alignItems: 'center',
        }}>
          <span><kbd style={kbdStyle}>↑↓</kbd> navigate</span>
          <span><kbd style={kbdStyle}>↵</kbd> select</span>
          <span><kbd style={kbdStyle}>esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}

const kbdStyle: React.CSSProperties = {
  padding: '1px 5px',
  background: 'var(--surface-2)',
  border: '1px solid var(--border)',
  borderRadius: 3,
  fontFamily: 'monospace',
  fontSize: 9,
};

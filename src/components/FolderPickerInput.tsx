import { useState } from 'react';

/**
 * Text input that augments itself with a "Browse..." button when the
 * Electron IPC bridge is present.
 *
 * In a plain browser (dev / web), the Browse button disables itself
 * with a tooltip - the user can still type a path. In the packaged
 * desktop app, clicking Browse opens the native OS directory picker
 * and fills the input.
 *
 * Drop-in replacement for a plain <input type="text" /> next to a
 * filesystem-path label (Runtime harness_path, Hunt local path,
 * Project import, etc.). Keep the label + help tooltip outside this
 * component.
 */
export interface FolderPickerInputProps {
  value: string;
  onChange: (value: string) => void;
  /** Placeholder shown when value is empty. */
  placeholder?: string;
  /** When true, show "Files..." instead of "Browse..." for clarity. */
  kind?: 'directory' | 'file';
  style?: React.CSSProperties;
}

type Bridge = {
  openDirectoryDialog?: () => Promise<string | null>;
  openFileDialog?: () => Promise<string | null>;
};

function getBridge(): Bridge | null {
  if (typeof window === 'undefined') return null;
  const b = (window as any).vulnforge;
  return b && (typeof b.openDirectoryDialog === 'function' || typeof b.openFileDialog === 'function') ? b : null;
}

export function FolderPickerInput({
  value,
  onChange,
  placeholder,
  kind = 'directory',
  style,
}: FolderPickerInputProps) {
  const bridge = getBridge();
  const [busy, setBusy] = useState(false);

  async function browse() {
    if (!bridge) return;
    setBusy(true);
    try {
      const picked = kind === 'directory'
        ? await bridge.openDirectoryDialog?.()
        : await bridge.openFileDialog?.();
      if (picked) onChange(picked);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'stretch', width: '100%' }}>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          flex: 1,
          minWidth: 0,
          ...style,
        }}
      />
      <button
        type="button"
        onClick={browse}
        disabled={!bridge || busy}
        title={bridge ? `Open native ${kind} picker` : 'Only available in the desktop app'}
        style={{
          padding: '0 12px',
          borderRadius: 6,
          border: '1px solid var(--border)',
          background: 'var(--surface-2)',
          color: bridge ? 'var(--text)' : 'var(--muted)',
          cursor: bridge ? 'pointer' : 'not-allowed',
          fontSize: 12,
          whiteSpace: 'nowrap',
          opacity: busy ? 0.6 : 1,
        }}
      >
        {busy ? '...' : kind === 'directory' ? 'Browse\u2026' : 'File\u2026'}
      </button>
    </div>
  );
}

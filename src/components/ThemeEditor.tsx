import { useEffect, useMemo, useState, type CSSProperties } from 'react';
import { useTheme, type ThemeDefinition, THEMES } from '@/themes';

// ThemeEditor - minimal form for creating a custom theme by editing the CSS
// variables of a base theme. Opens from ThemePicker's "Create custom..." card.
// Saves via the ThemeProvider's saveCustomTheme API (which also persists to
// localStorage under vulnforge.themes.custom).

interface ThemeEditorProps {
  initialTheme: ThemeDefinition | null;
  onClose: () => void;
  onSaved?: (theme: ThemeDefinition) => void;
}

const FALLBACK_BASE: ThemeDefinition =
  THEMES['dark'] ?? Object.values(THEMES)[0];

export function ThemeEditor({ initialTheme, onClose, onSaved }: ThemeEditorProps) {
  const { saveCustomTheme, setTheme } = useTheme();
  const base = initialTheme ?? FALLBACK_BASE;

  const [id, setId] = useState(() => `custom-${Date.now().toString(36)}`);
  const [label, setLabel] = useState(`${base.label} (custom)`);
  const [mode, setMode] = useState<'light' | 'dark'>(base.mode);
  const [vars, setVars] = useState<Record<string, string>>({ ...base.variables });

  // Escape key closes the modal
  useEffect(() => {
    function onKey(e: KeyboardEvent): void {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  const grouped = useMemo(() => {
    const surface: string[] = [];
    const text: string[] = [];
    const accent: string[] = [];
    const semantic: string[] = [];
    for (const key of Object.keys(vars)) {
      if (/^--(bg|surface|panel|border)/.test(key)) surface.push(key);
      else if (/^--(fg|muted|text)/.test(key)) text.push(key);
      else if (/^--(accent|primary|brand|link)/.test(key)) accent.push(key);
      else semantic.push(key);
    }
    return { surface, text, accent, semantic };
  }, [vars]);

  const preview = useMemo<ThemeDefinition>(
    () => ({
      id,
      label,
      mode,
      description: 'Custom theme',
      preview: [
        vars['--bg'] || '#000',
        vars['--fg'] || '#fff',
        vars['--accent'] || '#888',
        vars['--border'] || '#444',
      ].join(','),
      variables: vars,
    }),
    [id, label, mode, vars]
  );

  function handleVarChange(key: string, value: string): void {
    setVars((prev) => ({ ...prev, [key]: value }));
  }

  function handleLivePreview(): void {
    const root = document.documentElement;
    for (const [k, v] of Object.entries(vars)) {
      root.style.setProperty(k, v);
    }
  }

  function handleSave(): void {
    saveCustomTheme(preview);
    setTheme(preview.id);
    onSaved?.(preview);
    onClose();
  }

  function handleExport(): void {
    const blob = new Blob([JSON.stringify(preview, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleImport(e: React.ChangeEvent<HTMLInputElement>): void {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result)) as ThemeDefinition;
        if (parsed && typeof parsed === 'object' && parsed.variables) {
          setId(parsed.id || id);
          setLabel(parsed.label || label);
          setMode(parsed.mode || mode);
          setVars({ ...parsed.variables });
        }
      } catch {
        // invalid JSON - ignore
      }
    };
    reader.readAsText(file);
  }

  const overlay: CSSProperties = {
    position: 'fixed',
    inset: 0,
    background: 'rgba(0,0,0,0.55)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
  };
  const modal: CSSProperties = {
    background: 'var(--bg, #0b0d12)',
    color: 'var(--fg, #fff)',
    border: '1px solid var(--border, #333)',
    borderRadius: 8,
    padding: 20,
    width: 'min(720px, 92vw)',
    maxHeight: '90vh',
    overflowY: 'auto',
  };
  const section: CSSProperties = { marginTop: 16 };
  const row: CSSProperties = { display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 };
  const labelStyle: CSSProperties = { width: 160, fontSize: 12, color: 'var(--muted, #888)' };
  const inputStyle: CSSProperties = {
    background: 'transparent',
    color: 'var(--fg, #fff)',
    border: '1px solid var(--border, #333)',
    padding: '4px 6px',
    borderRadius: 4,
  };

  return (
    <div role="dialog" aria-modal="true" aria-label="Theme editor" style={overlay}>
      <div style={modal}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ margin: 0, fontSize: 16 }}>Custom theme</h2>
          <button onClick={onClose} style={inputStyle} aria-label="Close">
            Close
          </button>
        </div>

        <div style={section}>
          <div style={row}>
            <label style={labelStyle}>ID</label>
            <input value={id} onChange={(e) => setId(e.target.value)} style={{ ...inputStyle, flex: 1 }} />
          </div>
          <div style={row}>
            <label style={labelStyle}>Name</label>
            <input value={label} onChange={(e) => setLabel(e.target.value)} style={{ ...inputStyle, flex: 1 }} />
          </div>
          <div style={row}>
            <label style={labelStyle}>Mode</label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as 'light' | 'dark')}
              style={inputStyle}
            >
              <option value="dark">dark</option>
              <option value="light">light</option>
            </select>
          </div>
        </div>

        {(['surface', 'text', 'accent', 'semantic'] as const).map((groupName) => {
          const keys = grouped[groupName];
          if (keys.length === 0) return null;
          return (
            <div key={groupName} style={section}>
              <div
                style={{
                  fontSize: 12,
                  textTransform: 'uppercase',
                  color: 'var(--muted, #888)',
                  marginBottom: 6,
                }}
              >
                {groupName}
              </div>
              {keys.map((key) => (
                <div key={key} style={row}>
                  <label style={labelStyle}>{key}</label>
                  <input
                    type="color"
                    value={vars[key]}
                    onChange={(e) => handleVarChange(key, e.target.value)}
                    aria-label={`${key} color`}
                    style={{ width: 40, height: 28, padding: 0, border: 'none', background: 'transparent' }}
                  />
                  <input
                    value={vars[key]}
                    onChange={(e) => handleVarChange(key, e.target.value)}
                    style={{ ...inputStyle, flex: 1 }}
                  />
                </div>
              ))}
            </div>
          );
        })}

        <div style={{ display: 'flex', gap: 8, marginTop: 20, flexWrap: 'wrap' }}>
          <button onClick={handleLivePreview} style={inputStyle}>
            Preview
          </button>
          <button
            onClick={handleSave}
            style={{
              ...inputStyle,
              background: 'var(--accent, #3b82f6)',
              borderColor: 'transparent',
              color: '#fff',
            }}
          >
            Save
          </button>
          <button onClick={handleExport} style={inputStyle}>
            Export JSON
          </button>
          <label style={{ ...inputStyle, cursor: 'pointer' }}>
            Import JSON
            <input
              type="file"
              accept="application/json"
              onChange={handleImport}
              style={{ display: 'none' }}
            />
          </label>
        </div>
      </div>
    </div>
  );
}

export default ThemeEditor;

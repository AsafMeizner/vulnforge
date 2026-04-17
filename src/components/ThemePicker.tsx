import { useMemo, useState, type CSSProperties, type KeyboardEvent } from 'react';
import {
  useTheme,
  checkThemeAccessibility,
  type ThemeDefinition,
} from '@/themes';
import { ThemeEditor } from './ThemeEditor';

// ThemePicker — grid of theme cards shown in Settings → Theme tab.
//
// Behavior:
//   - Lists every built-in + custom theme as a clickable card.
//   - First card is the "System preference" auto option.
//   - Each card shows: name, mode icon, color swatch strip, A11y badge
//     (warns if the theme fails WCAG AA), and a checkmark if active.
//   - Keyboard: arrow keys move focus, Enter/Space applies, Escape closes
//     the editor.
//   - "Create custom..." card at the end opens the ThemeEditor.

function SunIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M8 1v2M8 13v2M1 8h2M13 8h2M3.5 3.5l1.4 1.4M11.1 11.1l1.4 1.4M3.5 12.5l1.4-1.4M11.1 4.9l1.4-1.4"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path
        d="M13.5 10.5A6 6 0 016.5 3a6 6 0 100 10 6 6 0 007-2.5z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function AutoIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.4" />
      <path d="M8 2v12" stroke="currentColor" strokeWidth="1.4" />
      <path d="M2 8h6V2a6 6 0 000 12V8z" fill="currentColor" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path
        d="M3 8l3.5 3.5L13 5"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

interface CardItem {
  kind: 'theme' | 'auto' | 'create';
  id: string;
  label: string;
  description: string;
  mode: 'light' | 'dark' | 'auto';
  preview: string[] | null;
  accessibilityWarning: string | null;
  isCustom: boolean;
}

export interface ThemePickerProps {
  /** Optional class name on the root container. */
  className?: string;
}

export function ThemePicker({ className }: ThemePickerProps) {
  const {
    selectedId,
    resolvedId,
    allThemes,
    customThemes,
    isAuto,
    setTheme,
    deleteCustomTheme,
  } = useTheme();

  const [editorOpen, setEditorOpen] = useState(false);
  const [editingThemeId, setEditingThemeId] = useState<string | null>(null);
  const [focusIdx, setFocusIdx] = useState<number>(-1);

  const cards: CardItem[] = useMemo(() => {
    const items: CardItem[] = [
      {
        kind: 'auto',
        id: 'auto',
        label: 'System preference',
        description: 'Follow your OS light/dark setting.',
        mode: 'auto',
        preview: null,
        accessibilityWarning: null,
        isCustom: false,
      },
    ];
    for (const t of Object.values(allThemes)) {
      const report = checkThemeAccessibility(t);
      items.push({
        kind: 'theme',
        id: t.id,
        label: t.label,
        description: t.description,
        mode: t.mode,
        preview: t.preview.split('|'),
        accessibilityWarning: report.AA ? null : `${report.failures.length} low-contrast pair(s)`,
        isCustom: !!customThemes[t.id],
      });
    }
    items.push({
      kind: 'create',
      id: '__create__',
      label: 'Create custom…',
      description: 'Open the theme editor to build your own.',
      mode: 'auto',
      preview: null,
      accessibilityWarning: null,
      isCustom: false,
    });
    return items;
  }, [allThemes, customThemes]);

  const activate = (card: CardItem) => {
    if (card.kind === 'create') {
      setEditingThemeId(null);
      setEditorOpen(true);
      return;
    }
    setTheme(card.id);
  };

  const onKey = (e: KeyboardEvent<HTMLDivElement>, idx: number) => {
    const cols = 3; // visual column count; row nav approximates via cols.
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      setFocusIdx(Math.min(cards.length - 1, idx + 1));
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      setFocusIdx(Math.max(0, idx - 1));
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setFocusIdx(Math.min(cards.length - 1, idx + cols));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setFocusIdx(Math.max(0, idx - cols));
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      activate(cards[idx]);
    }
  };

  return (
    <div className={className} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ fontSize: 12, color: 'var(--muted)' }}>
        Choose a theme. Click to apply; changes persist across sessions.
      </div>

      <div
        role="radiogroup"
        aria-label="Theme picker"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
          gap: 12,
        }}
      >
        {cards.map((card, idx) => {
          const isActive =
            (card.kind === 'auto' && isAuto) ||
            (card.kind === 'theme' && !isAuto && card.id === resolvedId) ||
            (card.kind === 'theme' && selectedId === card.id);
          const isFocused = focusIdx === idx;
          return (
            <ThemeCard
              key={card.id}
              card={card}
              active={!!isActive}
              focused={isFocused}
              onClick={() => activate(card)}
              onKeyDown={e => onKey(e, idx)}
              onFocus={() => setFocusIdx(idx)}
              onEdit={
                card.isCustom
                  ? () => {
                      setEditingThemeId(card.id);
                      setEditorOpen(true);
                    }
                  : undefined
              }
              onDelete={
                card.isCustom
                  ? () => {
                      if (confirm(`Delete custom theme "${card.label}"?`)) {
                        deleteCustomTheme(card.id);
                      }
                    }
                  : undefined
              }
            />
          );
        })}
      </div>

      {editorOpen && (
        <ThemeEditor
          initialTheme={
            editingThemeId ? allThemes[editingThemeId] ?? null : null
          }
          onClose={() => {
            setEditorOpen(false);
            setEditingThemeId(null);
          }}
        />
      )}
    </div>
  );
}

interface ThemeCardProps {
  card: CardItem;
  active: boolean;
  focused: boolean;
  onClick: () => void;
  onKeyDown: (e: KeyboardEvent<HTMLDivElement>) => void;
  onFocus: () => void;
  onEdit?: () => void;
  onDelete?: () => void;
}

function ThemeCard({
  card,
  active,
  focused,
  onClick,
  onKeyDown,
  onFocus,
  onEdit,
  onDelete,
}: ThemeCardProps) {
  const [hover, setHover] = useState(false);

  const cardStyle: CSSProperties = {
    position: 'relative',
    background: card.kind === 'create' ? 'transparent' : 'var(--surface)',
    border: `1px ${card.kind === 'create' ? 'dashed' : 'solid'} ${
      active ? 'var(--accent, var(--blue))' : 'var(--border)'
    }`,
    borderRadius: 8,
    padding: 14,
    cursor: 'pointer',
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
    transition: 'border-color 0.12s, transform 0.12s',
    transform: hover && !active ? 'translateY(-1px)' : 'none',
    outline: focused ? '2px solid var(--focus-ring, var(--blue))' : 'none',
    outlineOffset: 2,
  };

  return (
    <div
      role="radio"
      aria-checked={active}
      tabIndex={0}
      style={cardStyle}
      onClick={onClick}
      onKeyDown={onKeyDown}
      onFocus={onFocus}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      title={card.description}
    >
      {/* Header: icon + label + checkmark */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span
          style={{
            color: card.mode === 'light' ? 'var(--yellow)' : card.mode === 'dark' ? 'var(--purple)' : 'var(--muted)',
            display: 'inline-flex',
          }}
        >
          {card.mode === 'light' ? <SunIcon /> : card.mode === 'dark' ? <MoonIcon /> : <AutoIcon />}
        </span>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', flex: 1 }}>
          {card.label}
        </span>
        {active && (
          <span
            style={{
              color: 'var(--accent, var(--blue))',
              display: 'inline-flex',
            }}
            aria-label="Active theme"
          >
            <CheckIcon />
          </span>
        )}
      </div>

      {/* Color strip (5 swatches from preview hex stripe) */}
      {card.preview && (
        <div
          style={{
            display: 'flex',
            height: 24,
            borderRadius: 4,
            overflow: 'hidden',
            border: '1px solid var(--border)',
          }}
          aria-hidden="true"
        >
          {card.preview.map((hex, i) => (
            <div
              key={i}
              style={{ flex: 1, background: hex }}
              title={hex}
            />
          ))}
        </div>
      )}

      {/* Description / a11y warning */}
      <div style={{ fontSize: 11, color: 'var(--muted)', lineHeight: 1.4 }}>
        {card.description}
      </div>

      {card.accessibilityWarning && (
        <div
          role="status"
          style={{
            fontSize: 10,
            color: 'var(--yellow)',
            background: 'var(--surface-2)',
            border: '1px solid var(--yellow)',
            borderRadius: 4,
            padding: '3px 6px',
          }}
          title="This theme has color combinations below the WCAG AA 4.5:1 threshold"
        >
          ⚠ {card.accessibilityWarning}
        </div>
      )}

      {/* Custom theme controls */}
      {(onEdit || onDelete) && (
        <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
          {onEdit && (
            <button
              onClick={e => {
                e.stopPropagation();
                onEdit();
              }}
              style={controlBtn}
            >
              Edit
            </button>
          )}
          {onDelete && (
            <button
              onClick={e => {
                e.stopPropagation();
                onDelete();
              }}
              style={{ ...controlBtn, color: 'var(--red)' }}
            >
              Delete
            </button>
          )}
        </div>
      )}
    </div>
  );
}

const controlBtn: CSSProperties = {
  background: 'var(--surface-2)',
  border: '1px solid var(--border)',
  borderRadius: 4,
  color: 'var(--muted)',
  fontSize: 11,
  padding: '3px 8px',
  cursor: 'pointer',
};

export default ThemePicker;

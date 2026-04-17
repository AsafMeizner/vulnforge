// Shared types for the theming subsystem.
//
// A ThemeDefinition is a fully-specified set of CSS custom properties that
// get written to `document.documentElement.style` when the theme is applied.
// Every built-in theme MUST define the same set of variable keys so switching
// between them is smooth with no "half-applied" flashes.

export type ThemeMode = 'light' | 'dark';

export interface ThemeDefinition {
  /** Stable identifier, kebab-case. Used as the localStorage value. */
  id: string;
  /** Human-readable label shown in the picker. */
  label: string;
  /** Primary mode; used by system-preference auto-selection. */
  mode: ThemeMode;
  /** One-sentence description shown as a tooltip on the card. */
  description: string;
  /**
   * Preview string — a compact representation of the main palette.
   * Currently formatted as a `|`-joined hex strip of the card's key colors:
   *   "bg|surface|text|accent|border" (5 hex codes joined with `|`).
   * Consumers split and render as a swatch row.
   */
  preview: string;
  /** The CSS custom property map applied to :root. Keys include the leading `--`. */
  variables: Record<string, string>;
}

/**
 * Canonical list of every CSS variable a theme must define. Extracted from
 * `src/index.css` plus semantic aliases for severity/accent that new code
 * should prefer over raw color names.
 *
 * Order is stable and used by tests (`themes.test.ts`) to verify each theme
 * covers the full set.
 */
export const THEME_VARIABLE_KEYS = [
  // Surface layers
  '--bg',
  '--surface',
  '--surface-2',
  '--border',
  // Text
  '--text',
  '--muted',
  // Named palette (current usage across the app)
  '--blue',
  '--green',
  '--red',
  '--orange',
  '--yellow',
  '--purple',
  '--pink',
  // Semantic aliases (preferred for new code; point at the named palette)
  '--accent',
  '--critical',
  '--high',
  '--medium',
  '--low',
  '--info',
  // Accessibility: focus ring color (themes may override for high-contrast)
  '--focus-ring',
] as const;

export type ThemeVariableKey = (typeof THEME_VARIABLE_KEYS)[number];

/**
 * Build a preview hex strip from a partial variables map. All entries must
 * resolve to hex codes — if a theme uses rgb() or named colors, convert
 * upstream.
 */
export function buildPreview(vars: Record<string, string>): string {
  return [
    vars['--bg'],
    vars['--surface'],
    vars['--text'],
    vars['--accent'] ?? vars['--blue'],
    vars['--border'],
  ].join('|');
}

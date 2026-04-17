// Theme module entry point — what integrators import.
//
// Usage:
//   import { THEMES, ThemeProvider, applyTheme } from '@/themes';
//   applyTheme('dracula');
//
// All state mutation lives in `applyTheme`; the ThemeProvider is a thin
// wrapper that keeps React state in sync with localStorage + the DOM.

import type { ThemeDefinition } from './types';
import { darkTheme } from './dark';
import { lightTheme } from './light';
import { solarizedDarkTheme } from './solarized-dark';
import { solarizedLightTheme } from './solarized-light';
import { draculaTheme } from './dracula';
import { nordTheme } from './nord';
import { monokaiTheme } from './monokai';
import { gruvboxDarkTheme } from './gruvbox-dark';
import { highContrastTheme } from './high-contrast';

export type { ThemeDefinition, ThemeMode, ThemeVariableKey } from './types';
export { THEME_VARIABLE_KEYS, buildPreview } from './types';
export {
  getContrastRatio,
  relativeLuminance,
  checkThemeAccessibility,
  parseHex,
  WCAG_AA_NORMAL,
  WCAG_AAA_NORMAL,
} from './contrast';
export type { ContrastPair, AccessibilityReport } from './contrast';
export { ThemeProvider, useTheme } from './ThemeProvider';

/** localStorage key for the user's selected theme id (or "auto"). */
export const THEME_STORAGE_KEY = 'vulnforge.theme';
/** localStorage key for user-authored custom themes (serialised array). */
export const CUSTOM_THEMES_STORAGE_KEY = 'vulnforge.themes.custom';

/**
 * Every built-in theme, keyed by id. Custom user themes live in localStorage
 * and are merged in by the ThemePicker/Editor components at runtime.
 */
export const THEMES: Record<string, ThemeDefinition> = {
  [darkTheme.id]: darkTheme,
  [lightTheme.id]: lightTheme,
  [solarizedDarkTheme.id]: solarizedDarkTheme,
  [solarizedLightTheme.id]: solarizedLightTheme,
  [draculaTheme.id]: draculaTheme,
  [nordTheme.id]: nordTheme,
  [monokaiTheme.id]: monokaiTheme,
  [gruvboxDarkTheme.id]: gruvboxDarkTheme,
  [highContrastTheme.id]: highContrastTheme,
};

/** Default theme id when none is persisted and system preference is unknown. */
export const DEFAULT_THEME_ID = darkTheme.id;

/**
 * Apply a theme to `document.documentElement` by writing each CSS variable
 * with `setProperty`. Safe to call in any environment — when `document` is
 * undefined (SSR / test-worker without JSDOM) it becomes a no-op.
 *
 * The theme lookup consults `extraThemes` first, then the built-in `THEMES`
 * map. This lets callers pass user-authored custom themes without having
 * to mutate the global registry.
 *
 * @returns the ThemeDefinition that was applied, or null if id was unknown.
 */
export function applyTheme(
  id: string,
  extraThemes?: Record<string, ThemeDefinition>
): ThemeDefinition | null {
  const theme = (extraThemes && extraThemes[id]) || THEMES[id] || null;
  if (!theme) return null;

  // Guarded for SSR / Node test environments.
  if (typeof document !== 'undefined' && document.documentElement) {
    const root = document.documentElement;
    for (const [key, value] of Object.entries(theme.variables)) {
      root.style.setProperty(key, value);
    }
    // Expose a data attribute for CSS selectors that need to vary by theme.
    root.setAttribute('data-theme', theme.id);
    root.setAttribute('data-theme-mode', theme.mode);
    // color-scheme hint so form controls / scrollbars pick correct defaults.
    root.style.setProperty('color-scheme', theme.mode);
  }

  return theme;
}

/**
 * Read the currently-applied theme id from the DOM. Falls back to the
 * persisted value, then to DEFAULT_THEME_ID. Returns null if no DOM is
 * available and nothing is persisted.
 */
export function getCurrentTheme(): string | null {
  if (typeof document !== 'undefined' && document.documentElement) {
    const attr = document.documentElement.getAttribute('data-theme');
    if (attr && THEMES[attr]) return attr;
  }
  if (typeof localStorage !== 'undefined') {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored && (stored === 'auto' || THEMES[stored])) return stored;
  }
  return DEFAULT_THEME_ID;
}

/**
 * Detect the user's preferred theme mode from the OS / browser via the
 * prefers-color-scheme media query. Returns a concrete theme id (the
 * default light or default dark), never "auto".
 */
export function detectPreferredTheme(): string {
  if (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function'
  ) {
    try {
      if (window.matchMedia('(prefers-color-scheme: light)').matches) {
        return lightTheme.id;
      }
      if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return darkTheme.id;
      }
    } catch {
      // matchMedia can throw in some embedded browsers — fall through.
    }
  }
  return DEFAULT_THEME_ID;
}

/**
 * Load user-authored custom themes from localStorage. Returns an empty
 * record on any parse failure so callers can always iterate safely.
 */
export function loadCustomThemes(): Record<string, ThemeDefinition> {
  if (typeof localStorage === 'undefined') return {};
  const raw = localStorage.getItem(CUSTOM_THEMES_STORAGE_KEY);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return {};
    const out: Record<string, ThemeDefinition> = {};
    for (const t of parsed) {
      if (t && typeof t === 'object' && typeof t.id === 'string' && t.variables) {
        out[t.id] = t as ThemeDefinition;
      }
    }
    return out;
  } catch {
    return {};
  }
}

/** Persist user-authored custom themes back to localStorage. */
export function saveCustomThemes(themes: Record<string, ThemeDefinition>): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(
    CUSTOM_THEMES_STORAGE_KEY,
    JSON.stringify(Object.values(themes))
  );
}

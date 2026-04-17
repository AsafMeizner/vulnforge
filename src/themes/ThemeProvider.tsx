import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import type { ThemeDefinition } from './types';
import {
  THEMES,
  DEFAULT_THEME_ID,
  THEME_STORAGE_KEY,
  applyTheme as applyThemeGlobal,
  detectPreferredTheme,
  loadCustomThemes,
  saveCustomThemes,
} from './index';

// ThemeProvider — a React context over the imperative applyTheme() helper.
//
// State model:
//   selectedId      — what the user chose (may be "auto")
//   resolvedId      — the concrete theme id that's actually on screen
//   customThemes    — user-authored themes loaded from localStorage
//
// Effects:
//   1. On mount, resolve selectedId (possibly "auto") to a concrete theme
//      and apply it.
//   2. When selectedId === "auto", subscribe to `prefers-color-scheme` and
//      re-apply when the system preference changes.
//   3. Persist selectedId to localStorage whenever it changes.

export interface ThemeContextValue {
  /** The id the user picked. May be "auto". */
  selectedId: string;
  /** Concrete id of the theme currently applied to the DOM. Never "auto". */
  resolvedId: string;
  /** Full definition of the currently-applied theme. */
  theme: ThemeDefinition;
  /** All themes available — built-in + custom. */
  allThemes: Record<string, ThemeDefinition>;
  /** User-authored themes only. */
  customThemes: Record<string, ThemeDefinition>;
  /** Whether the user has chosen "auto" (follow system). */
  isAuto: boolean;
  /** Switch to a theme id, or "auto" to follow system preference. */
  setTheme: (id: string) => void;
  /** Save a user-authored theme (overwrites by id). */
  saveCustomTheme: (theme: ThemeDefinition) => void;
  /** Remove a user-authored theme. If active, falls back to default. */
  deleteCustomTheme: (id: string) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

/** Pull the user's persisted choice, or null if nothing is stored. */
function readStoredChoice(): string | null {
  if (typeof localStorage === 'undefined') return null;
  try {
    return localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStoredChoice(id: string): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(THEME_STORAGE_KEY, id);
  } catch {
    // storage disabled / quota exceeded — state still works in-memory.
  }
}

/** Resolve a possibly-"auto" id to a concrete built-in or custom theme id. */
export function resolveThemeId(
  selectedId: string,
  registry: Record<string, ThemeDefinition>
): string {
  if (selectedId === 'auto') return detectPreferredTheme();
  if (registry[selectedId]) return selectedId;
  return DEFAULT_THEME_ID;
}

export interface ThemeProviderProps {
  children: ReactNode;
  /** Override the initial selected id (useful for tests). */
  initialTheme?: string;
  /**
   * If true, do NOT read/write localStorage. Useful for tests and for
   * embedded usage where persistence is unwanted.
   */
  ephemeral?: boolean;
}

export function ThemeProvider({
  children,
  initialTheme,
  ephemeral = false,
}: ThemeProviderProps) {
  const [customThemes, setCustomThemes] = useState<Record<string, ThemeDefinition>>(
    () => (ephemeral ? {} : loadCustomThemes())
  );

  const allThemes = useMemo(
    () => ({ ...THEMES, ...customThemes }),
    [customThemes]
  );

  const [selectedId, setSelectedId] = useState<string>(() => {
    if (initialTheme) return initialTheme;
    if (!ephemeral) {
      const stored = readStoredChoice();
      if (stored) return stored;
    }
    return DEFAULT_THEME_ID;
  });

  const resolvedId = useMemo(
    () => resolveThemeId(selectedId, allThemes),
    [selectedId, allThemes]
  );

  // Apply the resolved theme whenever it changes. Also runs on mount, which
  // is what fulfils N3.b ("applies CSS vars on document.documentElement").
  useEffect(() => {
    applyThemeGlobal(resolvedId, customThemes);
  }, [resolvedId, customThemes]);

  // Persist user choice (including "auto").
  useEffect(() => {
    if (ephemeral) return;
    writeStoredChoice(selectedId);
  }, [selectedId, ephemeral]);

  // When following system preference, react to OS dark/light changes.
  useEffect(() => {
    if (selectedId !== 'auto') return;
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }

    const darkMql = window.matchMedia('(prefers-color-scheme: dark)');
    const lightMql = window.matchMedia('(prefers-color-scheme: light)');

    const reapply = () => {
      // Re-resolve and apply; we don't change selectedId itself.
      const nextId = resolveThemeId('auto', allThemes);
      applyThemeGlobal(nextId, customThemes);
    };

    // addEventListener is the modern API; older Safari only supported addListener.
    const attach = (mql: MediaQueryList) => {
      if (typeof mql.addEventListener === 'function') {
        mql.addEventListener('change', reapply);
        return () => mql.removeEventListener('change', reapply);
      }
      // Fallback for legacy browsers.
      const legacy = mql as MediaQueryList & {
        addListener?: (cb: (e: MediaQueryListEvent) => void) => void;
        removeListener?: (cb: (e: MediaQueryListEvent) => void) => void;
      };
      legacy.addListener?.(reapply);
      return () => legacy.removeListener?.(reapply);
    };

    const detachDark = attach(darkMql);
    const detachLight = attach(lightMql);
    return () => {
      detachDark?.();
      detachLight?.();
    };
  }, [selectedId, allThemes, customThemes]);

  const setTheme = useCallback((id: string) => {
    setSelectedId(id);
  }, []);

  const saveCustomTheme = useCallback(
    (theme: ThemeDefinition) => {
      setCustomThemes(prev => {
        const next = { ...prev, [theme.id]: theme };
        if (!ephemeral) saveCustomThemes(next);
        return next;
      });
    },
    [ephemeral]
  );

  const deleteCustomTheme = useCallback(
    (id: string) => {
      setCustomThemes(prev => {
        if (!prev[id]) return prev;
        const next = { ...prev };
        delete next[id];
        if (!ephemeral) saveCustomThemes(next);
        return next;
      });
      // If the user is currently on the deleted theme, fall back gracefully.
      setSelectedId(curr => (curr === id ? DEFAULT_THEME_ID : curr));
    },
    [ephemeral]
  );

  const value: ThemeContextValue = useMemo(
    () => ({
      selectedId,
      resolvedId,
      theme: allThemes[resolvedId] ?? THEMES[DEFAULT_THEME_ID],
      allThemes,
      customThemes,
      isAuto: selectedId === 'auto',
      setTheme,
      saveCustomTheme,
      deleteCustomTheme,
    }),
    [selectedId, resolvedId, allThemes, customThemes, setTheme, saveCustomTheme, deleteCustomTheme]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

/**
 * Hook to access the current theme + controls.
 * Throws if called outside a ThemeProvider — matches the usual React hook
 * contract and surfaces integration bugs early.
 */
export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error('useTheme must be called inside <ThemeProvider>');
  }
  return ctx;
}

/**
 * Shortcut registry consumed by the cheatsheet modal.
 *
 * Shortcuts are sourced by reading the canonical keybinding handlers in
 * `src/App.tsx` and the individual page components; this file is a
 * human-friendly projection intended for display only. Bindings are NOT
 * registered from here.
 */

export interface ShortcutEntry {
  /** Display form of the keystroke, e.g. "Ctrl+K" or "?". */
  keys: string;
  /** Human-readable description shown next to the keystroke. */
  label: string;
}

export interface ShortcutCategory {
  /** Category heading — rendered as a column header. */
  title: string;
  entries: ShortcutEntry[];
}

export const SHORTCUT_CATEGORIES: ShortcutCategory[] = [
  {
    title: 'Navigation',
    entries: [
      { keys: 'Ctrl+K', label: 'Open command palette (jump anywhere)' },
      { keys: '/', label: 'Focus the global search box' },
      { keys: 'Esc', label: 'Close modal / clear search' },
      { keys: 'g then d', label: 'Go to Dashboard (command palette)' },
      { keys: 'g then f', label: 'Go to Findings (command palette)' },
      { keys: 'g then s', label: 'Go to Scanner (command palette)' },
    ],
  },
  {
    title: 'Scanning',
    entries: [
      { keys: 'Enter', label: 'Start scan (when focused on Start button)' },
      { keys: 'Ctrl+Enter', label: 'Start scan from any input on Scanner page' },
      { keys: 'Esc', label: 'Cancel scan confirmation dialog' },
    ],
  },
  {
    title: 'Findings review',
    entries: [
      { keys: 'j', label: 'Next finding' },
      { keys: 'k', label: 'Previous finding' },
      { keys: 'Enter', label: 'Open finding detail' },
      { keys: 'a', label: 'Accept current finding (Review queue)' },
      { keys: 'r', label: 'Reject current finding (Review queue)' },
      { keys: 's', label: 'Skip current finding (Review queue)' },
    ],
  },
  {
    title: 'AI chat',
    entries: [
      { keys: 'Ctrl+Enter', label: 'Send chat message' },
      { keys: 'Up arrow', label: 'Recall previous prompt' },
      { keys: 'Esc', label: 'Cancel streaming response' },
    ],
  },
  {
    title: 'Command palette',
    entries: [
      { keys: 'Ctrl+K', label: 'Open command palette' },
      { keys: 'Up / Down', label: 'Move selection' },
      { keys: 'Enter', label: 'Execute selected command' },
      { keys: 'Esc', label: 'Close command palette' },
    ],
  },
];

/**
 * Flat lookup — rarely needed but handy for tests.
 */
export function allShortcuts(): ShortcutEntry[] {
  return SHORTCUT_CATEGORIES.flatMap(c => c.entries);
}

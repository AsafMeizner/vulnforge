import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// Formalization of the default dark theme currently defined in src/index.css.
// Values are copied verbatim; semantic aliases point at the named palette.
const variables: Record<string, string> = {
  '--bg': '#0d1117',
  '--surface': '#161b22',
  '--surface-2': '#1c2128',
  '--border': '#21262d',
  '--text': '#c9d1d9',
  '--muted': '#8b949e',
  '--blue': '#58a6ff',
  '--green': '#3fb950',
  '--red': '#f85149',
  '--orange': '#db6d28',
  '--yellow': '#d29922',
  '--purple': '#a371f7',
  '--pink': '#f778ba',
  // Semantic aliases — kept in sync with the named palette.
  '--accent': '#58a6ff',
  '--critical': '#f85149',
  '--high': '#db6d28',
  '--medium': '#d29922',
  '--low': '#3fb950',
  '--info': '#58a6ff',
  '--focus-ring': '#58a6ff',
};

export const darkTheme: ThemeDefinition = {
  id: 'dark',
  label: 'Dark (default)',
  mode: 'dark',
  description: 'GitHub-inspired dark theme — the VulnForge default.',
  preview: buildPreview(variables),
  variables,
};

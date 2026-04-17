import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// Monokai — classic Sublime-era palette. Canonical values from the original
// Wimer Hazenberg scheme; warm accents on a dark olive ground.
const variables: Record<string, string> = {
  '--bg': '#272822',
  '--surface': '#2d2e27',
  '--surface-2': '#3e3d32',
  '--border': '#49483e',
  '--text': '#f8f8f2',
  '--muted': '#75715e',
  '--blue': '#66d9ef',
  '--green': '#a6e22e',
  '--red': '#f92672',
  '--orange': '#fd971f',
  '--yellow': '#e6db74',
  '--purple': '#ae81ff',
  '--pink': '#f92672',
  '--accent': '#a6e22e',
  '--critical': '#f92672',
  '--high': '#fd971f',
  '--medium': '#e6db74',
  '--low': '#a6e22e',
  '--info': '#66d9ef',
  '--focus-ring': '#a6e22e',
};

export const monokaiTheme: ThemeDefinition = {
  id: 'monokai',
  label: 'Monokai',
  mode: 'dark',
  description: 'Classic Sublime-era palette — warm neon accents on dark olive.',
  preview: buildPreview(variables),
  variables,
};

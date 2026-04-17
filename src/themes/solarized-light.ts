import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// Solarized Light — same accent palette as the dark variant, light base.
const variables: Record<string, string> = {
  '--bg': '#fdf6e3',         // base3
  '--surface': '#eee8d5',    // base2
  '--surface-2': '#e6dfc8',
  '--border': '#cdc7b3',
  '--text': '#586e75',       // base01 — strong on base3 (≈ 10:1)
  '--muted': '#93a1a1',      // base1
  '--blue': '#268bd2',
  '--green': '#859900',
  '--red': '#dc322f',
  '--orange': '#cb4b16',
  '--yellow': '#b58900',
  '--purple': '#6c71c4',
  '--pink': '#d33682',
  '--accent': '#268bd2',
  '--critical': '#dc322f',
  '--high': '#cb4b16',
  '--medium': '#b58900',
  '--low': '#859900',
  '--info': '#2aa198',
  '--focus-ring': '#268bd2',
};

export const solarizedLightTheme: ThemeDefinition = {
  id: 'solarized-light',
  label: 'Solarized Light',
  mode: 'light',
  description: 'Warm cream-and-sage light palette by Ethan Schoonover.',
  preview: buildPreview(variables),
  variables,
};

import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// Solarized Dark by Ethan Schoonover. Canonical base values; selective
// brightening of text (base1 → #93a1a1) for improved contrast.
const variables: Record<string, string> = {
  '--bg': '#002b36',         // base03
  '--surface': '#073642',    // base02
  '--surface-2': '#0c4551',
  '--border': '#1d5763',
  '--text': '#93a1a1',       // base1
  '--muted': '#657b83',      // base00
  '--blue': '#268bd2',
  '--green': '#859900',
  '--red': '#dc322f',
  '--orange': '#cb4b16',
  '--yellow': '#b58900',
  '--purple': '#6c71c4',     // violet
  '--pink': '#d33682',       // magenta
  '--accent': '#268bd2',
  '--critical': '#dc322f',
  '--high': '#cb4b16',
  '--medium': '#b58900',
  '--low': '#859900',
  '--info': '#2aa198',       // cyan (info-style accent)
  '--focus-ring': '#268bd2',
};

export const solarizedDarkTheme: ThemeDefinition = {
  id: 'solarized-dark',
  label: 'Solarized Dark',
  mode: 'dark',
  description: 'Ethan Schoonover\'s Solarized palette — precise color relationships for long coding sessions.',
  preview: buildPreview(variables),
  variables,
};

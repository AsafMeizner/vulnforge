import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// Gruvbox Dark (hard) — by Pavel Pertsev. Retro-groove warm palette.
const variables: Record<string, string> = {
  '--bg': '#1d2021',         // bg0_h (hard)
  '--surface': '#282828',    // bg0
  '--surface-2': '#3c3836',  // bg1
  '--border': '#504945',     // bg2
  '--text': '#ebdbb2',       // fg1
  '--muted': '#a89984',      // fg4
  '--blue': '#83a598',
  '--green': '#b8bb26',
  '--red': '#fb4934',
  '--orange': '#fe8019',
  '--yellow': '#fabd2f',
  '--purple': '#d3869b',
  '--pink': '#d3869b',
  '--accent': '#fabd2f',
  '--critical': '#fb4934',
  '--high': '#fe8019',
  '--medium': '#fabd2f',
  '--low': '#b8bb26',
  '--info': '#83a598',
  '--focus-ring': '#fabd2f',
};

export const gruvboxDarkTheme: ThemeDefinition = {
  id: 'gruvbox-dark',
  label: 'Gruvbox Dark',
  mode: 'dark',
  description: 'Retro-groove warm earth tones by Pavel Pertsev.',
  preview: buildPreview(variables),
  variables,
};

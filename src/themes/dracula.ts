import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// Dracula — https://draculatheme.com/contribute (official spec palette).
const variables: Record<string, string> = {
  '--bg': '#282a36',         // background
  '--surface': '#343746',    // current line
  '--surface-2': '#44475a',  // selection
  '--border': '#4a4d66',
  '--text': '#f8f8f2',       // foreground
  '--muted': '#6272a4',      // comment
  '--blue': '#8be9fd',       // cyan
  '--green': '#50fa7b',
  '--red': '#ff5555',
  '--orange': '#ffb86c',
  '--yellow': '#f1fa8c',
  '--purple': '#bd93f9',
  '--pink': '#ff79c6',
  '--accent': '#bd93f9',
  '--critical': '#ff5555',
  '--high': '#ffb86c',
  '--medium': '#f1fa8c',
  '--low': '#50fa7b',
  '--info': '#8be9fd',
  '--focus-ring': '#ff79c6',
};

export const draculaTheme: ThemeDefinition = {
  id: 'dracula',
  label: 'Dracula',
  mode: 'dark',
  description: 'Official Dracula palette — vibrant, high-saturation accents against deep navy.',
  preview: buildPreview(variables),
  variables,
};

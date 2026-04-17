import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// High-contrast (dark) accessibility theme. Designed to meet WCAG 2.1 AAA
// on every semantic color against every surface layer:
//   - Text (#ffffff) on --bg / --surface / --surface-2 ≥ 16:1
//   - Every colored token (blue, red, green, …) on --bg or --surface-2 ≥ 7:1
//   - Focus ring is a bright accent distinct from text/background
//
// Semantic color selection (contrast against #1a1a1a, the dimmest surface;
// all are higher against pure-black --bg):
//   #ffffff (text)    ≈ 16.99 : 1
//   #d0d0d0 (muted)   ≈ 11.03 : 1
//   #ffff00 (yellow)  ≈ 15.82 : 1
//   #99ff99 (green)   ≈ 13.12 : 1
//   #ff9999 (red)     ≈  8.31 : 1
//   #66ccff (blue)    ≈  9.42 : 1
//   #ff9966 (orange)  ≈  8.09 : 1
//   #ff80ff (pink)    ≈  7.90 : 1
//   #cc99ff (purple)  ≈  7.74 : 1
const variables: Record<string, string> = {
  '--bg': '#000000',
  '--surface': '#000000',
  '--surface-2': '#1a1a1a',
  '--border': '#ffffff',
  '--text': '#ffffff',
  '--muted': '#d0d0d0',
  '--blue': '#66ccff',
  '--green': '#99ff99',
  '--red': '#ff9999',
  '--orange': '#ff9966',
  '--yellow': '#ffff00',
  '--purple': '#cc99ff',
  '--pink': '#ff80ff',
  '--accent': '#ffff00',
  '--critical': '#ff9999',
  '--high': '#ff9966',
  '--medium': '#ffff00',
  '--low': '#99ff99',
  '--info': '#66ccff',
  '--focus-ring': '#ffff00',
};

export const highContrastTheme: ThemeDefinition = {
  id: 'high-contrast',
  label: 'High Contrast',
  mode: 'dark',
  description: 'WCAG AAA-compliant accessibility theme — 7:1+ contrast on every text/background combo, explicit yellow focus rings.',
  preview: buildPreview(variables),
  variables,
};

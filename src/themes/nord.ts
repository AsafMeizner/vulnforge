import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// Nord — https://www.nordtheme.com. Arctic, bluish palette with muted accents.
const variables: Record<string, string> = {
  '--bg': '#2e3440',         // nord0 (Polar Night)
  '--surface': '#3b4252',    // nord1
  '--surface-2': '#434c5e',  // nord2
  '--border': '#4c566a',     // nord3
  '--text': '#eceff4',       // nord6 (Snow Storm)
  '--muted': '#d8dee9',      // nord4
  '--blue': '#88c0d0',       // nord8 (Frost)
  '--green': '#a3be8c',      // nord14 (Aurora)
  '--red': '#bf616a',        // nord11
  '--orange': '#d08770',     // nord12
  '--yellow': '#ebcb8b',     // nord13
  '--purple': '#b48ead',     // nord15
  '--pink': '#b48ead',
  '--accent': '#88c0d0',
  '--critical': '#bf616a',
  '--high': '#d08770',
  '--medium': '#ebcb8b',
  '--low': '#a3be8c',
  '--info': '#81a1c1',       // nord9
  '--focus-ring': '#88c0d0',
};

export const nordTheme: ThemeDefinition = {
  id: 'nord',
  label: 'Nord',
  mode: 'dark',
  description: 'Arctic, bluish palette inspired by the North — clean and calm.',
  preview: buildPreview(variables),
  variables,
};

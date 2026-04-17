import type { ThemeDefinition } from './types';
import { buildPreview } from './types';

// Light theme — GitHub-style light palette. Kept WCAG AA-friendly for body
// text by using #1f2328 on #ffffff (contrast ratio ≈ 16.1:1).
const variables: Record<string, string> = {
  '--bg': '#ffffff',
  '--surface': '#f6f8fa',
  '--surface-2': '#eaeef2',
  '--border': '#d0d7de',
  '--text': '#1f2328',
  '--muted': '#656d76',
  '--blue': '#0969da',
  '--green': '#1a7f37',
  '--red': '#cf222e',
  '--orange': '#bc4c00',
  '--yellow': '#9a6700',
  '--purple': '#8250df',
  '--pink': '#bf3989',
  '--accent': '#0969da',
  '--critical': '#cf222e',
  '--high': '#bc4c00',
  '--medium': '#9a6700',
  '--low': '#1a7f37',
  '--info': '#0969da',
  '--focus-ring': '#0969da',
};

export const lightTheme: ThemeDefinition = {
  id: 'light',
  label: 'Light',
  mode: 'light',
  description: 'Clean white theme with GitHub-style accents for bright environments.',
  preview: buildPreview(variables),
  variables,
};

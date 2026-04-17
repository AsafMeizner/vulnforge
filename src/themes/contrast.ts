// WCAG 2.1 contrast computations for theme accessibility checking.
//
// Reference: https://www.w3.org/WAI/WCAG21/Techniques/general/G18
//   relative luminance L = 0.2126*R + 0.7152*G + 0.0722*B
//   where each channel is linearised as:
//     c_srgb <= 0.03928 ? c_srgb/12.92 : ((c_srgb+0.055)/1.055)^2.4
//   contrast = (L_lighter + 0.05) / (L_darker + 0.05)
//
// All inputs are 6-digit hex strings ("#rrggbb"). 3-digit ("#abc") is
// expanded. Alpha channels are ignored.

import type { ThemeDefinition } from './types';

// WCAG 2.1 thresholds for normal body text.
export const WCAG_AA_NORMAL = 4.5;
export const WCAG_AAA_NORMAL = 7.0;

/** Parse a hex color string into 0-255 RGB channels. Throws on malformed input. */
export function parseHex(hex: string): { r: number; g: number; b: number } {
  if (typeof hex !== 'string') throw new Error(`parseHex: expected string, got ${typeof hex}`);
  let h = hex.trim().replace(/^#/, '');
  if (h.length === 3) {
    h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
  }
  if (!/^[0-9a-fA-F]{6}$/.test(h)) {
    throw new Error(`parseHex: invalid hex color "${hex}"`);
  }
  return {
    r: parseInt(h.slice(0, 2), 16),
    g: parseInt(h.slice(2, 4), 16),
    b: parseInt(h.slice(4, 6), 16),
  };
}

/** Linearise a single sRGB channel (0-255) per WCAG formula. */
function lin(c255: number): number {
  const c = c255 / 255;
  return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

/** Relative luminance of a hex color, per WCAG 2.1. */
export function relativeLuminance(hex: string): number {
  const { r, g, b } = parseHex(hex);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/**
 * WCAG contrast ratio between two colors. Always >= 1; symmetric.
 * Returns 21 for pure-black vs pure-white.
 */
export function getContrastRatio(fgHex: string, bgHex: string): number {
  const lFg = relativeLuminance(fgHex);
  const lBg = relativeLuminance(bgHex);
  const L1 = Math.max(lFg, lBg);
  const L2 = Math.min(lFg, lBg);
  return (L1 + 0.05) / (L2 + 0.05);
}

/** Pairs audited by `checkThemeAccessibility`. Each is "fg-on-bg". */
export interface ContrastPair {
  fg: string;
  bg: string;
  ratio: number;
  passesAA: boolean;
  passesAAA: boolean;
}

export interface AccessibilityReport {
  AA: boolean;
  AAA: boolean;
  failures: string[];
  pairs: ContrastPair[];
}

/**
 * Audit a theme's text-bearing variable pairs against WCAG 2.1 AA/AAA.
 *
 * Checked pairs (each foreground on each surface layer it realistically
 * shows up against):
 *   --text on --bg / --surface / --surface-2
 *   --muted on --bg / --surface / --surface-2
 *   --blue, --green, --red, --orange, --yellow, --purple, --pink on --bg
 *
 * Semantic aliases (--critical / --high / ...) are not re-checked
 * separately — they always equal one of the named-palette entries.
 */
export function checkThemeAccessibility(theme: ThemeDefinition): AccessibilityReport {
  const v = theme.variables;
  const surfaces: Array<[string, string]> = [
    ['--bg', v['--bg']],
    ['--surface', v['--surface']],
    ['--surface-2', v['--surface-2']],
  ];
  const textForegrounds: Array<[string, string]> = [
    ['--text', v['--text']],
    ['--muted', v['--muted']],
  ];
  const paletteForegrounds: Array<[string, string]> = [
    ['--blue', v['--blue']],
    ['--green', v['--green']],
    ['--red', v['--red']],
    ['--orange', v['--orange']],
    ['--yellow', v['--yellow']],
    ['--purple', v['--purple']],
    ['--pink', v['--pink']],
  ];

  const pairs: ContrastPair[] = [];
  const failures: string[] = [];
  let aa = true;
  let aaa = true;

  const check = (fgKey: string, fgVal: string, bgKey: string, bgVal: string) => {
    const ratio = getContrastRatio(fgVal, bgVal);
    const passesAA = ratio >= WCAG_AA_NORMAL;
    const passesAAA = ratio >= WCAG_AAA_NORMAL;
    pairs.push({ fg: fgKey, bg: bgKey, ratio, passesAA, passesAAA });
    if (!passesAA) {
      aa = false;
      failures.push(`${fgKey} on ${bgKey}: ${ratio.toFixed(2)}:1 (fails AA ${WCAG_AA_NORMAL}:1)`);
    }
    if (!passesAAA) {
      aaa = false;
    }
  };

  // Text/muted against every surface layer.
  for (const [fgKey, fgVal] of textForegrounds) {
    for (const [bgKey, bgVal] of surfaces) {
      check(fgKey, fgVal, bgKey, bgVal);
    }
  }

  // Palette colors against bg and surface-2 (the darkest/lightest surfaces);
  // these are the realistic combinations where colored tokens appear as text.
  for (const [fgKey, fgVal] of paletteForegrounds) {
    check(fgKey, fgVal, '--bg', v['--bg']);
    check(fgKey, fgVal, '--surface-2', v['--surface-2']);
  }

  return { AA: aa, AAA: aaa, failures, pairs };
}

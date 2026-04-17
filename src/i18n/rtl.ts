/**
 * RTL language helpers.
 *
 * We keep this as a standalone module so both the i18next init (see
 * `./index.ts`) and the language switcher can call `applyDocumentDirection`
 * without pulling the rest of the i18n stack into their bundle.
 */

export type Direction = 'ltr' | 'rtl';

/**
 * Languages written right-to-left. Extend as new RTL locales are added.
 */
export const RTL_LANGUAGES = new Set<string>(['ar', 'he', 'fa', 'ur']);

/**
 * Map a BCP-47 language tag (or bare 2-letter code) to its writing direction.
 * Matching is done on the primary subtag (first 2 chars, lowercase) so that
 * both `ar` and `ar-EG` yield `'rtl'`.
 */
export function getLanguageDirection(lang: string | undefined | null): Direction {
  if (!lang) return 'ltr';
  const primary = String(lang).toLowerCase().split('-')[0];
  return RTL_LANGUAGES.has(primary) ? 'rtl' : 'ltr';
}

/**
 * Set `document.dir` to the direction that matches `lang`. No-op if
 * `document` is not defined (SSR / test environments without a DOM).
 * Returns the applied direction so callers can log / assert.
 */
export function applyDocumentDirection(lang: string): Direction {
  const dir = getLanguageDirection(lang);
  if (typeof document !== 'undefined' && document) {
    document.dir = dir;
    // Also set `lang` attribute on <html> so assistive tech picks up the change.
    if (document.documentElement) {
      document.documentElement.lang = lang;
      document.documentElement.dir = dir;
    }
  }
  return dir;
}

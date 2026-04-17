/**
 * VulnForge i18next setup.
 *
 * Why i18next:
 * - Mature, battle-tested, browser-native.
 * - Supports namespaces (we use 'common' + per-page 'pages/<name>').
 * - Interpolation, plurals, formatters all built in.
 * - First-class React bindings via react-i18next.
 *
 * Language detection order: localStorage 'vulnforge.lang' → navigator → fallback 'en'.
 *
 * CSS / RTL note for future devs:
 * When styling components that must mirror under RTL (Arabic, Hebrew), prefer
 * CSS logical properties over physical left/right:
 *   - margin-inline-start / margin-inline-end  (not margin-left / margin-right)
 *   - padding-inline-start / padding-inline-end
 *   - border-inline-start / border-inline-end
 *   - inset-inline-start / inset-inline-end   (not left / right)
 *   - text-align: start / end                 (not left / right)
 * Use `:dir(rtl)` selector when a property has no logical counterpart.
 * `document.dir` is set automatically on language change — see `rtl.ts`.
 */

import i18next, { type InitOptions } from 'i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from 'react-i18next';

import manifest from '../locales/manifest.json' with { type: 'json' };

import enCommon from '../locales/en/common.json' with { type: 'json' };
import enDashboard from '../locales/en/pages/dashboard.json' with { type: 'json' };
import enFindings from '../locales/en/pages/findings.json' with { type: 'json' };
import enScanner from '../locales/en/pages/scanner.json' with { type: 'json' };
import enProjects from '../locales/en/pages/projects.json' with { type: 'json' };
import enTools from '../locales/en/pages/tools.json' with { type: 'json' };
import enChecklists from '../locales/en/pages/checklists.json' with { type: 'json' };
import enAi from '../locales/en/pages/ai.json' with { type: 'json' };
import enPlugins from '../locales/en/pages/plugins.json' with { type: 'json' };
import enSettings from '../locales/en/pages/settings.json' with { type: 'json' };
import enHunt from '../locales/en/pages/hunt.json' with { type: 'json' };
import enReview from '../locales/en/pages/review.json' with { type: 'json' };
import enRuntime from '../locales/en/pages/runtime.json' with { type: 'json' };
import enHistory from '../locales/en/pages/history.json' with { type: 'json' };
import enExploits from '../locales/en/pages/exploits.json' with { type: 'json' };
import enInvestigate from '../locales/en/pages/investigate.json' with { type: 'json' };
import enDisclosure from '../locales/en/pages/disclosure.json' with { type: 'json' };
import enAudit from '../locales/en/pages/audit.json' with { type: 'json' };

import esCommon from '../locales/es/common.json' with { type: 'json' };
import esDashboard from '../locales/es/pages/dashboard.json' with { type: 'json' };
import esFindings from '../locales/es/pages/findings.json' with { type: 'json' };
import esScanner from '../locales/es/pages/scanner.json' with { type: 'json' };
import esSettings from '../locales/es/pages/settings.json' with { type: 'json' };

import frCommon from '../locales/fr/common.json' with { type: 'json' };
import frDashboard from '../locales/fr/pages/dashboard.json' with { type: 'json' };
import frFindings from '../locales/fr/pages/findings.json' with { type: 'json' };
import frScanner from '../locales/fr/pages/scanner.json' with { type: 'json' };
import frSettings from '../locales/fr/pages/settings.json' with { type: 'json' };

import deCommon from '../locales/de/common.json' with { type: 'json' };
import deDashboard from '../locales/de/pages/dashboard.json' with { type: 'json' };
import deFindings from '../locales/de/pages/findings.json' with { type: 'json' };
import deScanner from '../locales/de/pages/scanner.json' with { type: 'json' };
import deSettings from '../locales/de/pages/settings.json' with { type: 'json' };

import jaCommon from '../locales/ja/common.json' with { type: 'json' };
import zhCommon from '../locales/zh/common.json' with { type: 'json' };
import arCommon from '../locales/ar/common.json' with { type: 'json' };
import heCommon from '../locales/he/common.json' with { type: 'json' };

import { applyDocumentDirection } from './rtl.js';

export const STORAGE_KEY = 'vulnforge.lang';
export const FALLBACK_LNG = 'en';

export const SUPPORTED_LANGUAGES = manifest.map((m) => m.code);

export const NAMESPACES = [
  'common',
  'pages/dashboard',
  'pages/findings',
  'pages/scanner',
  'pages/projects',
  'pages/tools',
  'pages/checklists',
  'pages/ai',
  'pages/plugins',
  'pages/settings',
  'pages/hunt',
  'pages/review',
  'pages/runtime',
  'pages/history',
  'pages/exploits',
  'pages/investigate',
  'pages/disclosure',
  'pages/audit',
] as const;

export const DEFAULT_NS = 'common';

const resources = {
  en: {
    common: enCommon,
    'pages/dashboard': enDashboard,
    'pages/findings': enFindings,
    'pages/scanner': enScanner,
    'pages/projects': enProjects,
    'pages/tools': enTools,
    'pages/checklists': enChecklists,
    'pages/ai': enAi,
    'pages/plugins': enPlugins,
    'pages/settings': enSettings,
    'pages/hunt': enHunt,
    'pages/review': enReview,
    'pages/runtime': enRuntime,
    'pages/history': enHistory,
    'pages/exploits': enExploits,
    'pages/investigate': enInvestigate,
    'pages/disclosure': enDisclosure,
    'pages/audit': enAudit,
  },
  es: {
    common: esCommon,
    'pages/dashboard': esDashboard,
    'pages/findings': esFindings,
    'pages/scanner': esScanner,
    'pages/settings': esSettings,
  },
  fr: {
    common: frCommon,
    'pages/dashboard': frDashboard,
    'pages/findings': frFindings,
    'pages/scanner': frScanner,
    'pages/settings': frSettings,
  },
  de: {
    common: deCommon,
    'pages/dashboard': deDashboard,
    'pages/findings': deFindings,
    'pages/scanner': deScanner,
    'pages/settings': deSettings,
  },
  ja: { common: jaCommon },
  zh: { common: zhCommon },
  ar: { common: arCommon },
  he: { common: heCommon },
};

/**
 * Build the i18next init options. Extracted so tests can construct a
 * fresh instance with overrides without relying on module-load order.
 */
export function buildInitOptions(overrides: Partial<InitOptions> = {}): InitOptions {
  return {
    resources,
    fallbackLng: FALLBACK_LNG,
    supportedLngs: SUPPORTED_LANGUAGES,
    defaultNS: DEFAULT_NS,
    ns: Array.from(NAMESPACES),
    interpolation: {
      escapeValue: false, // React already escapes
    },
    detection: {
      order: ['localStorage', 'navigator', 'htmlTag'],
      lookupLocalStorage: STORAGE_KEY,
      caches: ['localStorage'],
    },
    returnNull: false,
    react: {
      useSuspense: true,
    },
    ...overrides,
  };
}

/**
 * Detect the initial language with a deterministic precedence:
 *   1. localStorage[STORAGE_KEY]
 *   2. navigator.language (first 2 chars; matched against SUPPORTED_LANGUAGES)
 *   3. FALLBACK_LNG
 *
 * Exported so tests can assert the detector logic without instantiating i18next.
 */
export function detectInitialLanguage(env?: {
  localStorage?: Pick<Storage, 'getItem'>;
  navigator?: { language?: string; languages?: readonly string[] };
}): string {
  const ls = env?.localStorage ?? (typeof localStorage !== 'undefined' ? localStorage : undefined);
  const nav = env?.navigator ?? (typeof navigator !== 'undefined' ? navigator : undefined);

  if (ls) {
    try {
      const stored = ls.getItem(STORAGE_KEY);
      if (stored && SUPPORTED_LANGUAGES.includes(stored)) {
        return stored;
      }
    } catch {
      // swallow — some sandboxed environments throw on storage access
    }
  }

  if (nav) {
    const candidates: string[] = [];
    if (nav.language) candidates.push(nav.language);
    if (nav.languages) candidates.push(...nav.languages);
    for (const lang of candidates) {
      const short = lang.toLowerCase().split('-')[0];
      if (SUPPORTED_LANGUAGES.includes(short)) {
        return short;
      }
    }
  }

  return FALLBACK_LNG;
}

let initialized = false;

/**
 * Idempotent initializer. Call once at app boot (from I18nProvider).
 * Safe to call multiple times — subsequent calls are no-ops.
 */
export async function initI18n(overrides: Partial<InitOptions> = {}): Promise<typeof i18next> {
  if (initialized) return i18next;
  initialized = true;

  const lng = overrides.lng ?? detectInitialLanguage();

  await i18next
    .use(LanguageDetector)
    .use(initReactI18next)
    .init(buildInitOptions({ lng, ...overrides }));

  // Sync document.dir with initial language.
  applyDocumentDirection(i18next.language || lng);

  // Keep document.dir in sync on subsequent changes.
  i18next.on('languageChanged', (newLang: string) => {
    applyDocumentDirection(newLang);
  });

  return i18next;
}

export { i18next };
export default i18next;

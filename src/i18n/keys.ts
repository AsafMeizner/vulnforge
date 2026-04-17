/**
 * Central registry of translation keys used across VulnForge.
 *
 * This file is the source of truth for `t()` call sites: importing from here
 * gives type safety and a grep-friendly audit trail of every i18n key.
 *
 * Keys are namespaced with `<ns>:<path>` — `ns` being one of the namespaces
 * declared in `src/i18n/index.ts`. The string values are literal templates
 * passed to `t()` and must match entries in the corresponding JSON bundles.
 */

export const KEYS = {
  // common namespace
  common: {
    appName: 'common:appName',
    nav: {
      dashboard: 'common:nav.dashboard',
      findings: 'common:nav.findings',
      scanner: 'common:nav.scanner',
      projects: 'common:nav.projects',
      tools: 'common:nav.tools',
      checklists: 'common:nav.checklists',
      ai: 'common:nav.ai',
      plugins: 'common:nav.plugins',
      settings: 'common:nav.settings',
      hunt: 'common:nav.hunt',
      review: 'common:nav.review',
      runtime: 'common:nav.runtime',
      history: 'common:nav.history',
      exploits: 'common:nav.exploits',
      investigate: 'common:nav.investigate',
      disclosure: 'common:nav.disclosure',
      audit: 'common:nav.audit',
    },
    buttons: {
      save: 'common:buttons.save',
      cancel: 'common:buttons.cancel',
      delete: 'common:buttons.delete',
      export: 'common:buttons.export',
      refresh: 'common:buttons.refresh',
      close: 'common:buttons.close',
      confirm: 'common:buttons.confirm',
      edit: 'common:buttons.edit',
      add: 'common:buttons.add',
      run: 'common:buttons.run',
      retry: 'common:buttons.retry',
      apply: 'common:buttons.apply',
    },
    severity: {
      critical: 'common:severity.critical',
      high: 'common:severity.high',
      medium: 'common:severity.medium',
      low: 'common:severity.low',
      info: 'common:severity.info',
    },
    status: {
      pending: 'common:status.pending',
      verified: 'common:status.verified',
      rejected: 'common:status.rejected',
      accepted: 'common:status.accepted',
      running: 'common:status.running',
      failed: 'common:status.failed',
      queued: 'common:status.queued',
      completed: 'common:status.completed',
    },
    errors: {
      generic: 'common:errors.generic',
      network: 'common:errors.network',
      unauthorized: 'common:errors.unauthorized',
      notFound: 'common:errors.notFound',
      validation: 'common:errors.validation',
    },
    empty: {
      noData: 'common:empty.noData',
      noResults: 'common:empty.noResults',
    },
  },

  // page namespaces — only the title + a marker key per page. Pages add more
  // entries locally as they grow.
  pages: {
    dashboard: {
      title: 'pages/dashboard:title',
      subtitle: 'pages/dashboard:subtitle',
    },
    findings: {
      title: 'pages/findings:title',
      subtitle: 'pages/findings:subtitle',
    },
    scanner: {
      title: 'pages/scanner:title',
      subtitle: 'pages/scanner:subtitle',
    },
    projects: {
      title: 'pages/projects:title',
      subtitle: 'pages/projects:subtitle',
    },
    tools: {
      title: 'pages/tools:title',
      subtitle: 'pages/tools:subtitle',
    },
    checklists: {
      title: 'pages/checklists:title',
      subtitle: 'pages/checklists:subtitle',
    },
    ai: {
      title: 'pages/ai:title',
      subtitle: 'pages/ai:subtitle',
    },
    plugins: {
      title: 'pages/plugins:title',
      subtitle: 'pages/plugins:subtitle',
    },
    settings: {
      title: 'pages/settings:title',
      language: 'pages/settings:language',
      theme: 'pages/settings:theme',
    },
    hunt: {
      title: 'pages/hunt:title',
      subtitle: 'pages/hunt:subtitle',
    },
    review: {
      title: 'pages/review:title',
      subtitle: 'pages/review:subtitle',
    },
    runtime: {
      title: 'pages/runtime:title',
      subtitle: 'pages/runtime:subtitle',
    },
    history: {
      title: 'pages/history:title',
      subtitle: 'pages/history:subtitle',
    },
    exploits: {
      title: 'pages/exploits:title',
      subtitle: 'pages/exploits:subtitle',
    },
    investigate: {
      title: 'pages/investigate:title',
      subtitle: 'pages/investigate:subtitle',
    },
    disclosure: {
      title: 'pages/disclosure:title',
      subtitle: 'pages/disclosure:subtitle',
    },
    audit: {
      title: 'pages/audit:title',
      subtitle: 'pages/audit:subtitle',
    },
  },
} as const;

/**
 * Recursive flatten type: unions every leaf string literal in the nested const.
 */
type LeafValues<T> = T extends string
  ? T
  : T extends readonly unknown[]
    ? LeafValues<T[number]>
    : T extends object
      ? { [K in keyof T]: LeafValues<T[K]> }[keyof T]
      : never;

/**
 * All valid translation key strings as a union — `t(key)` call sites can
 * accept a `TranslationKey` parameter for full type safety.
 */
export type TranslationKey = LeafValues<typeof KEYS>;

/**
 * Flatten the nested `KEYS` object to a flat array — handy for tests that
 * want to assert every key has a value in `en/common.json`.
 */
export function flattenKeys(obj: unknown = KEYS, out: string[] = []): string[] {
  if (typeof obj === 'string') {
    out.push(obj);
    return out;
  }
  if (obj && typeof obj === 'object') {
    for (const v of Object.values(obj as Record<string, unknown>)) {
      flattenKeys(v, out);
    }
  }
  return out;
}

export default KEYS;

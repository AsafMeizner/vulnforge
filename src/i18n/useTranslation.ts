/**
 * Project-scoped `useTranslation` re-export.
 *
 * Why wrap the react-i18next hook:
 * 1. One import path for the whole app (`@/i18n/useTranslation`) — makes
 *    future swaps or instrumentation straightforward.
 * 2. We pre-declare our namespaces so callers get better autocomplete
 *    without repeating them at every call site.
 * 3. Provides a `useT(ns)` convenience that narrows to a single namespace.
 *
 * All options accepted by react-i18next's `useTranslation` are forwarded.
 */

import {
  useTranslation as useReactI18NextTranslation,
  type UseTranslationOptions,
  type UseTranslationResponse,
  Trans,
} from 'react-i18next';

export type Namespace =
  | 'common'
  | 'pages/dashboard'
  | 'pages/findings'
  | 'pages/scanner'
  | 'pages/projects'
  | 'pages/tools'
  | 'pages/checklists'
  | 'pages/ai'
  | 'pages/plugins'
  | 'pages/settings'
  | 'pages/hunt'
  | 'pages/review'
  | 'pages/runtime'
  | 'pages/history'
  | 'pages/exploits'
  | 'pages/investigate'
  | 'pages/disclosure'
  | 'pages/audit';

/**
 * Project default: `useTranslation()` gives you the `common` namespace with
 * access to any other namespace via `t('pages/settings:title')`.
 */
export function useTranslation<Ns extends Namespace | readonly Namespace[] = 'common'>(
  ns?: Ns,
  options?: UseTranslationOptions<undefined>,
): UseTranslationResponse<Ns extends readonly string[] ? Ns[number] : Ns extends string ? Ns : 'common', undefined> {
  // react-i18next's generics accept (ns, options) directly; cast is safe because
  // we mirror its signature.
  return useReactI18NextTranslation(ns as unknown as Namespace, options) as unknown as UseTranslationResponse<
    Ns extends readonly string[] ? Ns[number] : Ns extends string ? Ns : 'common',
    undefined
  >;
}

/**
 * Convenience: single-namespace shorthand.
 *   const t = useT('pages/settings');
 *   t('title'); // resolves against pages/settings
 */
export function useT<Ns extends Namespace>(ns: Ns) {
  const { t } = useReactI18NextTranslation(ns);
  return t;
}

export { Trans };
export default useTranslation;

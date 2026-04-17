/**
 * <I18nProvider> — app-level wrapper that bootstraps i18next, then hands its
 * instance to react-i18next. Suspense fallback covers lazy namespace loads.
 *
 * The integrator wraps `<App />` in this provider (see `src/App.tsx` after
 * the integration phase). In tests, the underlying i18next instance can be
 * primed synchronously and passed through `instance` to avoid Suspense.
 */

import { Suspense, useEffect, useState, type ReactNode } from 'react';
import { I18nextProvider } from 'react-i18next';
import type { i18n as I18nInstance } from 'i18next';

import i18next, { initI18n } from './index.js';

export interface I18nProviderProps {
  children: ReactNode;
  /** Optional pre-initialized i18next instance (tests / Storybook). */
  instance?: I18nInstance;
  /** Optional Suspense fallback shown while bundles load. */
  fallback?: ReactNode;
}

const DefaultFallback = (
  <div
    role="status"
    aria-live="polite"
    style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      fontFamily: 'system-ui, sans-serif',
      color: 'var(--text, #888)',
    }}
  >
    Loading…
  </div>
);

export function I18nProvider({
  children,
  instance,
  fallback = DefaultFallback,
}: I18nProviderProps) {
  // If the caller supplies an instance, trust it. Otherwise run the lazy init.
  const [ready, setReady] = useState<boolean>(Boolean(instance));

  useEffect(() => {
    if (instance) return;
    let cancelled = false;
    initI18n()
      .then(() => {
        if (!cancelled) setReady(true);
      })
      .catch((err) => {
        // eslint-disable-next-line no-console
        console.error('[i18n] initialization failed', err);
        if (!cancelled) setReady(true); // still render — fallback strings will leak through
      });
    return () => {
      cancelled = true;
    };
  }, [instance]);

  const i18n = instance ?? i18next;

  if (!ready) {
    return <>{fallback}</>;
  }

  return (
    <I18nextProvider i18n={i18n}>
      <Suspense fallback={fallback}>{children}</Suspense>
    </I18nextProvider>
  );
}

export default I18nProvider;

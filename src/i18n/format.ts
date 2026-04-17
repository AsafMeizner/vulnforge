/**
 * Locale-aware formatting helpers built on the standard `Intl` API.
 *
 * Usage:
 *   import { formatDate, formatNumber, formatRelative } from './format.js';
 *   formatDate(new Date(), { dateStyle: 'medium' }, 'fr');
 *   formatNumber(1234.5, { style: 'currency', currency: 'EUR' }, 'de');
 *
 * React components should prefer the `useFormat()` hook, which binds the
 * formatters to the currently active i18next locale.
 */

import { useTranslation } from 'react-i18next';

export type DateInput = Date | number | string;

function toDate(input: DateInput): Date {
  if (input instanceof Date) return input;
  if (typeof input === 'number') return new Date(input);
  return new Date(input);
}

/**
 * Format an absolute date using `Intl.DateTimeFormat`.
 * Defaults: dateStyle 'medium', timeStyle omitted.
 */
export function formatDate(
  date: DateInput,
  opts: Intl.DateTimeFormatOptions = {},
  locale?: string,
): string {
  const d = toDate(date);
  if (Number.isNaN(d.getTime())) return '';
  const options: Intl.DateTimeFormatOptions = {
    dateStyle: 'medium',
    ...opts,
  };
  return new Intl.DateTimeFormat(locale, options).format(d);
}

/**
 * Format a number using `Intl.NumberFormat`. When no options are supplied the
 * result is plain (grouped) numeric; pass `{ style: 'currency', currency }`
 * for money, or `{ style: 'percent' }` for percentages.
 */
export function formatNumber(
  n: number,
  opts: Intl.NumberFormatOptions = {},
  locale?: string,
): string {
  if (!Number.isFinite(n)) return '';
  return new Intl.NumberFormat(locale, opts).format(n);
}

/**
 * Format a timestamp as a relative string ("3 minutes ago", "in 2 days").
 * Picks the largest meaningful unit automatically.
 */
export function formatRelative(
  date: DateInput,
  opts: Intl.RelativeTimeFormatOptions = { numeric: 'auto' },
  locale?: string,
  now: DateInput = new Date(),
): string {
  const d = toDate(date);
  const ref = toDate(now);
  if (Number.isNaN(d.getTime()) || Number.isNaN(ref.getTime())) return '';

  const diffMs = d.getTime() - ref.getTime();
  const diffSec = diffMs / 1000;

  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['year', 60 * 60 * 24 * 365],
    ['month', 60 * 60 * 24 * 30],
    ['week', 60 * 60 * 24 * 7],
    ['day', 60 * 60 * 24],
    ['hour', 60 * 60],
    ['minute', 60],
    ['second', 1],
  ];

  const rtf = new Intl.RelativeTimeFormat(locale, opts);
  for (const [unit, inSeconds] of units) {
    if (Math.abs(diffSec) >= inSeconds || unit === 'second') {
      const value = Math.round(diffSec / inSeconds);
      return rtf.format(value, unit);
    }
  }
  return rtf.format(0, 'second');
}

export interface FormatApi {
  locale: string;
  formatDate: (date: DateInput, opts?: Intl.DateTimeFormatOptions) => string;
  formatNumber: (n: number, opts?: Intl.NumberFormatOptions) => string;
  formatRelative: (date: DateInput, opts?: Intl.RelativeTimeFormatOptions, now?: DateInput) => string;
}

/**
 * React hook that returns formatters bound to the currently active locale
 * (driven by i18next). Re-renders automatically on language change because
 * `useTranslation` subscribes to i18next events.
 */
export function useFormat(): FormatApi {
  const { i18n } = useTranslation();
  const locale = i18n.language || 'en';
  return {
    locale,
    formatDate: (date, opts) => formatDate(date, opts, locale),
    formatNumber: (n, opts) => formatNumber(n, opts, locale),
    formatRelative: (date, opts, now) => formatRelative(date, opts, locale, now),
  };
}

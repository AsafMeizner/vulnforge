/**
 * Tutorial (guided-tour) provider.
 *
 * Exposes a `useTutorial()` hook that lets any component start, advance,
 * rewind, skip or complete the active tour. Completed tours are recorded in
 * `localStorage['vulnforge.tutorials.completed']` so they do not re-launch
 * automatically.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { getTour, type TourDefinition, type TourStep } from '@/lib/tours';

export const COMPLETED_TOURS_KEY = 'vulnforge.tutorials.completed';

export interface TutorialState {
  /** Whether a tour is currently playing. */
  active: boolean;
  /** Active tour ID or `null`. */
  currentTour: string | null;
  /** Zero-based index of the current step. */
  step: number;
  /** Resolved definition of the active tour (or `null`). */
  tour: TourDefinition | null;
  /** Resolved current step (or `null`). */
  currentStep: TourStep | null;
  /** Stable list of completed tour IDs. */
  completed: string[];
}

export interface TutorialApi extends TutorialState {
  start: (tourId: string) => boolean;
  next: () => void;
  prev: () => void;
  skip: () => void;
  complete: () => void;
  isCompleted: (tourId: string) => boolean;
  resetCompleted: () => void;
}

const TutorialContext = createContext<TutorialApi | null>(null);

/**
 * Safely read the completed-tours list from localStorage. Never throws.
 */
export function loadCompleted(): string[] {
  try {
    const raw = (typeof localStorage !== 'undefined' && localStorage.getItem(COMPLETED_TOURS_KEY)) || null;
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((x): x is string => typeof x === 'string');
  } catch {
    return [];
  }
}

/**
 * Persist the completed-tours list. Never throws.
 */
export function saveCompleted(ids: string[]): void {
  try {
    if (typeof localStorage === 'undefined') return;
    localStorage.setItem(COMPLETED_TOURS_KEY, JSON.stringify(Array.from(new Set(ids))));
  } catch {
    /* ignore quota/security errors — best-effort */
  }
}

export interface TutorialProviderProps {
  children: ReactNode;
  /** Override the tour registry (primarily for tests). */
  registry?: (id: string) => TourDefinition | null;
}

export function TutorialProvider({ children, registry = getTour }: TutorialProviderProps) {
  const [active, setActive] = useState(false);
  const [currentTour, setCurrentTour] = useState<string | null>(null);
  const [step, setStep] = useState(0);
  const [completed, setCompleted] = useState<string[]>(() => loadCompleted());

  const tour = useMemo(
    () => (currentTour ? registry(currentTour) : null),
    [currentTour, registry],
  );

  const currentStep: TourStep | null = useMemo(() => {
    if (!tour) return null;
    if (step < 0 || step >= tour.steps.length) return null;
    return tour.steps[step];
  }, [tour, step]);

  const markCompleted = useCallback((id: string) => {
    setCompleted(prev => {
      if (prev.includes(id)) return prev;
      const next = [...prev, id];
      saveCompleted(next);
      return next;
    });
  }, []);

  const start = useCallback<TutorialApi['start']>(
    (tourId: string) => {
      const def = registry(tourId);
      if (!def || def.steps.length === 0) return false;
      setCurrentTour(tourId);
      setStep(0);
      setActive(true);
      return true;
    },
    [registry],
  );

  const next = useCallback<TutorialApi['next']>(() => {
    if (!tour) return;
    setStep(prev => {
      if (prev + 1 >= tour.steps.length) {
        // Auto-complete on next-past-end.
        markCompleted(tour.id);
        setActive(false);
        setCurrentTour(null);
        return 0;
      }
      return prev + 1;
    });
  }, [tour, markCompleted]);

  const prev = useCallback<TutorialApi['prev']>(() => {
    setStep(p => Math.max(0, p - 1));
  }, []);

  const skip = useCallback<TutorialApi['skip']>(() => {
    setActive(false);
    setCurrentTour(null);
    setStep(0);
  }, []);

  const complete = useCallback<TutorialApi['complete']>(() => {
    if (currentTour) markCompleted(currentTour);
    setActive(false);
    setCurrentTour(null);
    setStep(0);
  }, [currentTour, markCompleted]);

  const isCompleted = useCallback<TutorialApi['isCompleted']>(
    (id: string) => completed.includes(id),
    [completed],
  );

  const resetCompleted = useCallback<TutorialApi['resetCompleted']>(() => {
    setCompleted([]);
    saveCompleted([]);
  }, []);

  // Sync state from storage if another tab mutates it.
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const onStorage = (e: StorageEvent) => {
      if (e.key === COMPLETED_TOURS_KEY) setCompleted(loadCompleted());
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const api = useMemo<TutorialApi>(
    () => ({
      active,
      currentTour,
      step,
      tour,
      currentStep,
      completed,
      start,
      next,
      prev,
      skip,
      complete,
      isCompleted,
      resetCompleted,
    }),
    [
      active,
      currentTour,
      step,
      tour,
      currentStep,
      completed,
      start,
      next,
      prev,
      skip,
      complete,
      isCompleted,
      resetCompleted,
    ],
  );

  return <TutorialContext.Provider value={api}>{children}</TutorialContext.Provider>;
}

export function useTutorial(): TutorialApi {
  const ctx = useContext(TutorialContext);
  if (!ctx) {
    throw new Error('useTutorial must be used inside a <TutorialProvider>.');
  }
  return ctx;
}

/** Convenience hook — returns `null` when no provider is mounted. */
export function useTutorialOptional(): TutorialApi | null {
  return useContext(TutorialContext);
}

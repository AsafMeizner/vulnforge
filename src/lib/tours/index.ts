/**
 * Tour registry — maps tour IDs to their step definitions.
 *
 * New tours should be added as their own module and registered in the
 * TOURS object below. The IDs here are the stable values persisted in
 * `localStorage['vulnforge.tutorials.completed']`.
 */
import dashboardTour from './dashboard';
import firstScanTour from './first-scan';
import findingsTour from './findings';
import aiRoutingTour from './ai-routing';

export type TourPlacement = 'top' | 'bottom' | 'left' | 'right';

export interface TourStep {
  /** CSS selector — typically `[data-tour-id="…"]`. */
  target: string;
  /** Heading shown at the top of the step popover. */
  title: string;
  /** Description body (plain text; no HTML). */
  body: string;
  /** Optional placement relative to the target. Defaults to `bottom`. */
  placement?: TourPlacement;
}

export interface TourDefinition {
  /** Stable identifier — persisted in localStorage on completion. */
  id: string;
  /** Human-readable title (shown on the picker). */
  title: string;
  /** One-liner summary shown on the tour picker. */
  description?: string;
  /** Ordered list of steps. */
  steps: TourStep[];
}

export const TOURS: Record<string, TourDefinition> = {
  [dashboardTour.id]: dashboardTour,
  [firstScanTour.id]: firstScanTour,
  [findingsTour.id]: findingsTour,
  [aiRoutingTour.id]: aiRoutingTour,
};

export function getTour(id: string): TourDefinition | null {
  return TOURS[id] || null;
}

export function listTours(): TourDefinition[] {
  return Object.values(TOURS);
}

export { dashboardTour, firstScanTour, findingsTour, aiRoutingTour };

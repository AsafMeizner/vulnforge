/**
 * Tutorial overlay — the visible component that renders the active tour.
 *
 * Mount exactly once, near the root, after a `TutorialProvider` is in scope.
 * The overlay is a no-op when no tour is active.
 *
 * The overlay:
 *   - dims the page with a semi-transparent layer
 *   - highlights the target element referenced by the active step
 *   - renders a popover (title, body, prev/next/skip + step counter)
 *   - handles ← → arrow keys and Esc
 */
import { useCallback, useEffect, useLayoutEffect, useState } from 'react';
import { useTutorialOptional } from './TutorialProvider';
import type { TourPlacement } from '@/lib/tours';

const POPOVER_WIDTH = 340;
const POPOVER_OFFSET = 14;
const HIGHLIGHT_PADDING = 6;

interface Rect {
  top: number;
  left: number;
  width: number;
  height: number;
}

function rectOf(el: Element | null): Rect | null {
  if (!el) return null;
  const r = el.getBoundingClientRect();
  if (r.width === 0 && r.height === 0) return null;
  return { top: r.top, left: r.left, width: r.width, height: r.height };
}

function computePopoverPosition(
  target: Rect | null,
  placement: TourPlacement,
  viewport: { w: number; h: number },
): { top: number; left: number } {
  if (!target) {
    // No target: centered fallback.
    return {
      top: Math.max(24, viewport.h / 2 - 100),
      left: Math.max(24, viewport.w / 2 - POPOVER_WIDTH / 2),
    };
  }
  const estimatedHeight = 180;
  let top = target.top + target.height + POPOVER_OFFSET;
  let left = target.left;
  switch (placement) {
    case 'top':
      top = target.top - estimatedHeight - POPOVER_OFFSET;
      left = target.left + target.width / 2 - POPOVER_WIDTH / 2;
      break;
    case 'left':
      top = target.top + target.height / 2 - estimatedHeight / 2;
      left = target.left - POPOVER_WIDTH - POPOVER_OFFSET;
      break;
    case 'right':
      top = target.top + target.height / 2 - estimatedHeight / 2;
      left = target.left + target.width + POPOVER_OFFSET;
      break;
    case 'bottom':
    default:
      top = target.top + target.height + POPOVER_OFFSET;
      left = target.left + target.width / 2 - POPOVER_WIDTH / 2;
      break;
  }
  // Clamp inside viewport.
  top = Math.max(12, Math.min(viewport.h - estimatedHeight - 12, top));
  left = Math.max(12, Math.min(viewport.w - POPOVER_WIDTH - 12, left));
  return { top, left };
}

export function TutorialOverlay() {
  const ctx = useTutorialOptional();
  const [targetRect, setTargetRect] = useState<Rect | null>(null);
  const [viewport, setViewport] = useState(() => ({
    w: typeof window !== 'undefined' ? window.innerWidth : 1024,
    h: typeof window !== 'undefined' ? window.innerHeight : 768,
  }));

  const active = !!ctx?.active;
  const currentStep = ctx?.currentStep ?? null;
  const tour = ctx?.tour ?? null;
  const step = ctx?.step ?? 0;

  const next = ctx?.next;
  const prev = ctx?.prev;
  const skip = ctx?.skip;

  // Recompute the target rect whenever the step changes or the window resizes.
  const recompute = useCallback(() => {
    if (!active || !currentStep) {
      setTargetRect(null);
      return;
    }
    const el = document.querySelector(currentStep.target);
    setTargetRect(rectOf(el));
    setViewport({ w: window.innerWidth, h: window.innerHeight });
  }, [active, currentStep]);

  useLayoutEffect(() => {
    recompute();
  }, [recompute]);

  useEffect(() => {
    if (!active) return;
    const handler = () => recompute();
    window.addEventListener('resize', handler);
    window.addEventListener('scroll', handler, true);
    // Poll every 250 ms so the overlay follows lazy-rendered targets.
    const tid = window.setInterval(handler, 250);
    return () => {
      window.removeEventListener('resize', handler);
      window.removeEventListener('scroll', handler, true);
      window.clearInterval(tid);
    };
  }, [active, recompute]);

  // Keyboard navigation.
  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault();
        next?.();
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault();
        prev?.();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        skip?.();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [active, next, prev, skip]);

  if (!active || !tour || !currentStep) return null;

  const placement: TourPlacement = currentStep.placement ?? 'bottom';
  const popoverPos = computePopoverPosition(targetRect, placement, viewport);
  const isLast = step >= tour.steps.length - 1;

  return (
    <div
      data-testid="tutorial-overlay-root"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 2500,
        pointerEvents: 'none',
      }}
    >
      {/* Dim layer.
          When there's no target rect we cover the whole screen; when there
          is one we render four rectangles around it so the highlight shows
          through. */}
      {targetRect ? (
        <DimFrame rect={targetRect} />
      ) : (
        <div
          onClick={skip}
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.5)',
            pointerEvents: 'auto',
          }}
        />
      )}

      {/* Highlight ring around target. */}
      {targetRect && (
        <div
          style={{
            position: 'fixed',
            top: targetRect.top - HIGHLIGHT_PADDING,
            left: targetRect.left - HIGHLIGHT_PADDING,
            width: targetRect.width + HIGHLIGHT_PADDING * 2,
            height: targetRect.height + HIGHLIGHT_PADDING * 2,
            borderRadius: 8,
            boxShadow: '0 0 0 2px var(--blue), 0 0 24px 4px rgba(88,166,255,0.35)',
            pointerEvents: 'none',
            transition: 'top 0.15s, left 0.15s, width 0.15s, height 0.15s',
          }}
        />
      )}

      {/* Popover */}
      <div
        role="dialog"
        aria-labelledby="tutorial-overlay-title"
        style={{
          position: 'fixed',
          top: popoverPos.top,
          left: popoverPos.left,
          width: POPOVER_WIDTH,
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          borderRadius: 10,
          boxShadow: '0 14px 48px rgba(0,0,0,0.45)',
          padding: 18,
          color: 'var(--text)',
          pointerEvents: 'auto',
          zIndex: 2501,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 6 }}>
          <div
            id="tutorial-overlay-title"
            style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: 0.6 }}
          >
            {tour.title}
          </div>
          <div style={{ fontSize: 11, color: 'var(--muted)' }}>
            {step + 1} of {tour.steps.length}
          </div>
        </div>
        <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text)', marginBottom: 6 }}>
          {currentStep.title}
        </div>
        <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5, marginBottom: 16 }}>
          {currentStep.body}
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between' }}>
          <button
            type="button"
            onClick={() => skip?.()}
            style={secondaryBtnStyle}
          >
            Skip tour
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              onClick={() => prev?.()}
              disabled={step === 0}
              style={{ ...secondaryBtnStyle, opacity: step === 0 ? 0.5 : 1 }}
            >
              Previous
            </button>
            <button
              type="button"
              onClick={() => next?.()}
              style={primaryBtnStyle}
            >
              {isLast ? 'Finish' : 'Next'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Renders a 4-rectangle frame around the target so the target itself is
 * not dimmed. This keeps the "spotlight" effect without needing an SVG
 * mask or a CSS `clip-path` that Safari sometimes struggles with.
 */
function DimFrame({ rect }: { rect: Rect }) {
  const pad = HIGHLIGHT_PADDING;
  const common: React.CSSProperties = {
    position: 'fixed',
    background: 'rgba(0,0,0,0.5)',
    pointerEvents: 'auto',
  };
  return (
    <>
      <div style={{ ...common, top: 0, left: 0, width: '100%', height: rect.top - pad }} />
      <div
        style={{
          ...common,
          top: rect.top - pad,
          left: 0,
          width: rect.left - pad,
          height: rect.height + pad * 2,
        }}
      />
      <div
        style={{
          ...common,
          top: rect.top - pad,
          left: rect.left + rect.width + pad,
          right: 0,
          height: rect.height + pad * 2,
        }}
      />
      <div
        style={{
          ...common,
          top: rect.top + rect.height + pad,
          left: 0,
          width: '100%',
          bottom: 0,
        }}
      />
    </>
  );
}

const primaryBtnStyle: React.CSSProperties = {
  padding: '7px 14px',
  background: 'var(--blue)',
  color: 'var(--bg)',
  border: '1px solid var(--blue)',
  borderRadius: 6,
  fontSize: 12,
  fontWeight: 600,
  cursor: 'pointer',
};

const secondaryBtnStyle: React.CSSProperties = {
  padding: '7px 14px',
  background: 'transparent',
  color: 'var(--text)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  fontSize: 12,
  cursor: 'pointer',
};

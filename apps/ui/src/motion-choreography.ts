/**
 * @file apps/ui/src/motion-choreography.ts
 * @description Restraint-first Motion.dev choreography helpers for PatchCat Live (`apps/ui`).
 * Respects `prefers-reduced-motion: reduce`, runs only on live browser DOM elements,
 * and enhances already-visible UI without ever hiding content behind class triggers.
 */

import { animate, stagger } from 'motion';

const PRODUCT_EASE: [number, number, number, number] = [0.22, 1, 0.36, 1];

function canAnimateDom(): boolean {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return false;
  }
  if (
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  ) {
    return false;
  }
  return typeof Element !== 'undefined';
}

/**
 * Smooth 180ms precision shift when switching scenarios or refreshing audit panels.
 */
export function animateScenarioTransition(root: Element): void {
  if (!canAnimateDom()) return;
  try {
    const panels = Array.from(
      root.querySelectorAll('#panel-openui-brief, #panel-chainbreak, .dual-panels-grid > section')
    ).filter((el): el is HTMLElement => el instanceof HTMLElement);

    if (panels.length === 0) return;

    animate(
      panels,
      {
        opacity: [0.92, 1],
        transform: ['translateY(4px)', 'translateY(0px)'],
      },
      {
        duration: 0.18,
        delay: stagger(0.03),
        ease: PRODUCT_EASE,
      }
    );
  } catch {
    // Non-fatal in constrained headless environments
  }
}

/**
 * Draws the active unauthorized edge path smoothly along the SVG geometry.
 */
export function animateAttackPathDraw(root: Element): void {
  if (!canAnimateDom()) return;
  try {
    const paths = Array.from(
      root.querySelectorAll('.graph-edge-violation path')
    ).filter((el): el is SVGPathElement => el instanceof SVGPathElement);

    for (const pathEl of paths) {
      const length =
        typeof pathEl.getTotalLength === 'function'
          ? Math.max(80, Math.round(pathEl.getTotalLength()))
          : 220;
      pathEl.style.strokeDasharray = `${length}`;
      animate(
        pathEl,
        { strokeDashoffset: [length, 0] },
        { duration: 0.32, ease: PRODUCT_EASE }
      );
    }
  } catch {
    // Non-fatal fallback
  }
}

/**
 * Subtle list stagger capped at 8 rows (max ~240ms total cascade).
 */
export function animateStaggeredRows(root: Element, selector: string): void {
  if (!canAnimateDom()) return;
  try {
    const items = Array.from(root.querySelectorAll(selector))
      .slice(0, 8)
      .filter((el): el is HTMLElement => el instanceof HTMLElement);
    if (items.length === 0) return;

    animate(
      items,
      { opacity: [0.85, 1], transform: ['translateX(-3px)', 'translateX(0px)'] },
      { duration: 0.16, delay: stagger(0.025), ease: PRODUCT_EASE }
    );
  } catch {
    // Non-fatal
  }
}

/**
 * Crisp 160ms entrance for dialogs and drawers.
 */
export function animateOverlayEnter(root: Element, selector = '.modal-box'): void {
  if (!canAnimateDom()) return;
  try {
    const modal = root.querySelector(selector);
    if (!(modal instanceof HTMLElement)) return;
    animate(
      modal,
      { opacity: [0.88, 1], transform: ['scale(0.985)', 'scale(1)'] },
      { duration: 0.16, ease: PRODUCT_EASE }
    );
  } catch {
    // Non-fatal
  }
}

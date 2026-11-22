/**
 * @file apps/ui/src/patchcat-mascot.ts
 * @description Canonical PatchCat geometric vector mascot renderer and state-to-pose mapper
 * for ScriptKitty Live (`@script-kitty/ui`).
 *
 * Uses strict self-closing SVG child primitives (`<path ... />`, `<rect ... />`,
 * `<circle ... />`, `<polygon ... />`) so both live browser DOM and headless
 * HTML shim parsers (`MockElement`) parse the output cleanly.
 */

import type { MascotState } from './mascot3d.ts';

export type PatchCatPose =
  | 'idle'
  | 'scanning'
  | 'alert'
  | 'verified'
  | 'needs_review';

export const PATCHCAT_BRAND_PALETTE = {
  graphite: '#0C121A',
  graphitePlane: '#111C28',
  graphiteFacet: '#162330',
  slateBorder: '#273A4D',
  iceBlue: '#79B7F3',
  emerald: '#64CDB1',
  violet: '#A594F9',
  amber: '#EDBA6C',
  coral: '#F08589',
} as const;

interface PoseVisualSpec {
  readonly accent: string;
  readonly secondary: string;
  readonly defaultLabel: string;
  readonly eyesSvg: string;
  readonly shieldGlyphSvg: string;
}

const POSE_SPECS: Record<PatchCatPose, PoseVisualSpec> = {
  idle: {
    accent: PATCHCAT_BRAND_PALETTE.iceBlue,
    secondary: PATCHCAT_BRAND_PALETTE.violet,
    defaultLabel: 'PatchCat — Idle observant posture',
    eyesSvg: [
      `<polygon points="18.0,26.2 27.4,27.6 26.6,31.0 18.0,30.2" fill="${PATCHCAT_BRAND_PALETTE.iceBlue}" />`,
      `<polygon points="46.0,26.2 36.6,27.6 37.4,31.0 46.0,30.2" fill="${PATCHCAT_BRAND_PALETTE.iceBlue}" />`,
    ].join(''),
    shieldGlyphSvg: `<polygon points="32.0,46.0 35.5,49.5 32.0,53.0 28.5,49.5" fill="${PATCHCAT_BRAND_PALETTE.violet}" />`,
  },
  scanning: {
    accent: PATCHCAT_BRAND_PALETTE.iceBlue,
    secondary: PATCHCAT_BRAND_PALETTE.violet,
    defaultLabel: 'PatchCat — Scanning active telemetry',
    eyesSvg: [
      `<polygon points="17.8,26.8 24.8,27.1 24.8,29.6 18.0,29.4" fill="${PATCHCAT_BRAND_PALETTE.iceBlue}" />`,
      `<rect x="25.6" y="27.1" width="2.2" height="2.5" fill="${PATCHCAT_BRAND_PALETTE.violet}" />`,
      `<polygon points="36.2,27.1 43.4,26.8 43.4,29.4 36.2,29.6" fill="${PATCHCAT_BRAND_PALETTE.iceBlue}" />`,
      `<rect x="44.2" y="26.8" width="2.2" height="2.5" fill="${PATCHCAT_BRAND_PALETTE.violet}" />`,
    ].join(''),
    shieldGlyphSvg: [
      `<path d="M 27.8 49.4 L 32.0 52.8 L 36.2 49.4" fill="none" stroke="${PATCHCAT_BRAND_PALETTE.violet}" stroke-width="2" stroke-linecap="square" />`,
      `<path d="M 29.0 46.2 L 32.0 48.8 L 35.0 46.2" fill="none" stroke="${PATCHCAT_BRAND_PALETTE.iceBlue}" stroke-width="1.6" stroke-linecap="square" />`,
      `<path d="M 52.2 6.8 A 8.5 8.5 0 0 1 56.8 14.4" fill="none" stroke="${PATCHCAT_BRAND_PALETTE.violet}" stroke-width="1.8" stroke-linecap="square" />`,
      `<path d="M 54.6 4.4 A 11.5 11.5 0 0 1 59.8 14.0" fill="none" stroke="${PATCHCAT_BRAND_PALETTE.iceBlue}" stroke-width="1.4" stroke-linecap="square" stroke-opacity="0.7" />`,
    ].join(''),
  },
  alert: {
    accent: PATCHCAT_BRAND_PALETTE.coral,
    secondary: PATCHCAT_BRAND_PALETTE.coral,
    defaultLabel: 'PatchCat — Alert risk path detected',
    eyesSvg: [
      `<polygon points="17.6,24.8 28.0,28.4 26.8,31.6 17.8,28.6" fill="${PATCHCAT_BRAND_PALETTE.coral}" />`,
      `<polygon points="46.4,24.8 36.0,28.4 37.2,31.6 46.2,28.6" fill="${PATCHCAT_BRAND_PALETTE.coral}" />`,
    ].join(''),
    shieldGlyphSvg: [
      `<rect x="30.8" y="44.8" width="2.4" height="4.8" fill="${PATCHCAT_BRAND_PALETTE.coral}" />`,
      `<polygon points="32.0,51.0 33.6,52.6 32.0,54.2 30.4,52.6" fill="${PATCHCAT_BRAND_PALETTE.coral}" />`,
    ].join(''),
  },
  verified: {
    accent: PATCHCAT_BRAND_PALETTE.emerald,
    secondary: PATCHCAT_BRAND_PALETTE.emerald,
    defaultLabel: 'PatchCat — Verified clear posture',
    eyesSvg: [
      `<polygon points="18.2,27.0 27.2,27.2 26.6,30.4 18.4,30.2" fill="${PATCHCAT_BRAND_PALETTE.emerald}" />`,
      `<polygon points="45.8,27.0 36.8,27.2 37.4,30.4 45.6,30.2" fill="${PATCHCAT_BRAND_PALETTE.emerald}" />`,
    ].join(''),
    shieldGlyphSvg: `<path d="M 27.6 49.6 L 30.6 52.6 L 36.6 46.6" fill="none" stroke="${PATCHCAT_BRAND_PALETTE.emerald}" stroke-width="2.3" stroke-linecap="square" stroke-linejoin="miter" />`,
  },
  needs_review: {
    accent: PATCHCAT_BRAND_PALETTE.amber,
    secondary: PATCHCAT_BRAND_PALETTE.amber,
    defaultLabel: 'PatchCat — Needs human review',
    eyesSvg: [
      `<polygon points="18.0,26.8 27.2,27.2 26.6,30.4 18.2,30.2" fill="${PATCHCAT_BRAND_PALETTE.amber}" />`,
      `<polygon points="36.8,27.8 46.0,26.8 45.6,29.2 37.0,29.8" fill="${PATCHCAT_BRAND_PALETTE.amber}" />`,
    ].join(''),
    shieldGlyphSvg: [
      `<rect x="28.6" y="46.2" width="2.3" height="6.0" fill="${PATCHCAT_BRAND_PALETTE.amber}" />`,
      `<rect x="33.1" y="46.2" width="2.3" height="6.0" fill="${PATCHCAT_BRAND_PALETTE.amber}" />`,
    ].join(''),
  },
};

function escapeXmlAttribute(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function normalizePose(pose: PatchCatPose): PatchCatPose {
  if (
    pose === 'idle' ||
    pose === 'scanning' ||
    pose === 'alert' ||
    pose === 'verified' ||
    pose === 'needs_review'
  ) {
    return pose;
  }
  return 'idle';
}

/**
 * Maps the 4-state telemetry `MascotState` (plus optional human-review escalation)
 * into the 5-pose PatchCat visual identity system.
 *
 * Precedence:
 * 1. `scanning` stays `scanning` while active verification is running.
 * 2. `alert` stays `alert` when a confirmed path violation or gate rejection exists.
 * 3. `needsReview === true` promotes `idle` or `success` to `needs_review` (cannot mark verified while human review is pending).
 * 4. `success` maps to `verified`; `idle` maps to `idle`.
 */
export function mapMascotStateToPose(
  state: MascotState,
  needsReview: boolean = false
): PatchCatPose {
  if (state === 'scanning') {
    return 'scanning';
  }
  if (state === 'alert') {
    return 'alert';
  }
  if (needsReview) {
    return 'needs_review';
  }
  if (state === 'success') {
    return 'verified';
  }
  return 'idle';
}

/**
 * Renders the geometric PatchCat vector mascot for a given `PatchCatPose`
 * using strictly self-closing SVG child elements (`/>`).
 */
export function renderPatchCatSvg(
  pose: PatchCatPose,
  opts?: { size?: number; label?: string }
): string {
  const safePose = normalizePose(pose);
  const spec = POSE_SPECS[safePose];
  const size =
    typeof opts?.size === 'number' &&
    Number.isFinite(opts.size) &&
    opts.size > 0
      ? Math.round(opts.size)
      : 64;
  const label =
    typeof opts?.label === 'string' && opts.label.trim().length > 0
      ? opts.label.trim()
      : spec.defaultLabel;

  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="${size}" height="${size}" fill="none" role="img" aria-label="${escapeXmlAttribute(label)}" data-patchcat-pose="${safePose}">`,
    `<polygon points="15.8,39.4 26.0,42.0 32.0,42.6 38.0,42.0 48.2,39.4 49.6,47.4 32.0,59.0 14.4,47.4" fill="${PATCHCAT_BRAND_PALETTE.graphite}" stroke="${spec.accent}" stroke-width="2.1" stroke-linejoin="miter" stroke-miterlimit="2.5" />`,
    `<polygon points="20.4,43.2 32.0,45.0 43.6,43.2 44.6,47.2 32.0,55.8 19.4,47.2" fill="${PATCHCAT_BRAND_PALETTE.graphitePlane}" stroke="${spec.accent}" stroke-opacity="0.34" stroke-width="1" />`,
    `<path d="M 12.2 24.4 L 14.4 7.6 L 24.4 15.8 L 32.0 15.0 L 39.6 15.8 L 49.6 7.6 L 50.6 13.0 L 45.6 14.6 L 46.2 17.4 L 51.2 18.6 L 51.8 24.4 L 52.2 30.8 L 47.8 39.0 L 38.0 42.0 L 32.0 42.6 L 26.0 42.0 L 16.2 39.0 L 11.8 30.8 Z" fill="${PATCHCAT_BRAND_PALETTE.graphite}" />`,
    `<polygon points="16.0,12.8 21.8,17.4 15.4,22.0" fill="${PATCHCAT_BRAND_PALETTE.graphiteFacet}" />`,
    `<polygon points="46.8,12.4 42.0,17.2 48.0,21.8 48.2,19.8 44.0,18.2 44.0,14.2" fill="${PATCHCAT_BRAND_PALETTE.graphiteFacet}" />`,
    `<path d="M 24.4 15.8 L 32.0 19.8 L 39.6 15.8" fill="none" stroke="${spec.accent}" stroke-opacity="0.32" stroke-width="1.2" />`,
    `<path d="M 12.2 24.4 L 14.4 7.6 L 24.4 15.8 L 32.0 15.0 L 39.6 15.8 L 49.6 7.6 L 50.6 13.0 L 45.6 14.6 L 46.2 17.4 L 51.2 18.6 L 51.8 24.4 L 52.2 30.8 L 47.8 39.0 L 38.0 42.0 L 32.0 42.6 L 26.0 42.0 L 16.2 39.0 L 11.8 30.8 Z" fill="none" stroke="${spec.accent}" stroke-width="2.15" stroke-linejoin="miter" stroke-miterlimit="2.5" />`,
    spec.eyesSvg,
    `<polygon points="29.4,34.6 34.6,34.6 32.0,37.8" fill="${spec.accent}" />`,
    spec.shieldGlyphSvg,
    '</svg>',
  ].join('');
}

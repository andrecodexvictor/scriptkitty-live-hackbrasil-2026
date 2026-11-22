/**
 * @file apps/ui/src/mascot3d.ts
 * @description Precision geometric PatchCat telemetry canvas renderer (`MotionCatMascot3D`)
 * preserving the `MascotControllerHandle` API across `idle`, `scanning`, `alert`, and `success`
 * states while rendering the angular dark-graphite (`#0C121A`) + ice-blue (`#79B7F3`) /
 * emerald (`#64CDB1`) / violet (`#A594F9`) / amber (`#EDBA6C`) / coral (`#F08589`) PatchCat geometry.
 */

export type MascotState = 'idle' | 'scanning' | 'alert' | 'success';

interface MascotPalette {
  readonly surfaceTint: string;
  readonly outerRing: string;
  readonly primaryAccent: string;
  readonly secondaryAccent: string;
  readonly headFill: string;
  readonly facetFill: string;
  readonly shieldInnerFill: string;
}

export const PATCHCAT_CANVAS_COLORS = {
  graphite: '#0C121A',
  graphitePlane: '#111C28',
  graphiteFacet: '#162330',
  iceBlue: '#79B7F3',
  emerald: '#64CDB1',
  violet: '#A594F9',
  amber: '#EDBA6C',
  coral: '#F08589',
} as const;

export const PATCHCAT_REVIEW_PALETTE: MascotPalette = {
  surfaceTint: '#111C28',
  outerRing: 'rgba(237, 186, 108, 0.42)',
  primaryAccent: PATCHCAT_CANVAS_COLORS.amber,
  secondaryAccent: PATCHCAT_CANVAS_COLORS.amber,
  headFill: PATCHCAT_CANVAS_COLORS.graphite,
  facetFill: PATCHCAT_CANVAS_COLORS.graphiteFacet,
  shieldInnerFill: PATCHCAT_CANVAS_COLORS.graphitePlane,
};

const STATE_PALETTES: Record<MascotState, MascotPalette> = {
  idle: {
    surfaceTint: PATCHCAT_CANVAS_COLORS.graphitePlane,
    outerRing: 'rgba(121, 183, 243, 0.34)',
    primaryAccent: PATCHCAT_CANVAS_COLORS.iceBlue,
    secondaryAccent: PATCHCAT_CANVAS_COLORS.violet,
    headFill: PATCHCAT_CANVAS_COLORS.graphite,
    facetFill: PATCHCAT_CANVAS_COLORS.graphiteFacet,
    shieldInnerFill: PATCHCAT_CANVAS_COLORS.graphitePlane,
  },
  scanning: {
    surfaceTint: PATCHCAT_CANVAS_COLORS.graphitePlane,
    outerRing: 'rgba(165, 148, 249, 0.72)',
    primaryAccent: PATCHCAT_CANVAS_COLORS.iceBlue,
    secondaryAccent: PATCHCAT_CANVAS_COLORS.violet,
    headFill: PATCHCAT_CANVAS_COLORS.graphite,
    facetFill: PATCHCAT_CANVAS_COLORS.graphiteFacet,
    shieldInnerFill: PATCHCAT_CANVAS_COLORS.graphitePlane,
  },
  alert: {
    surfaceTint: PATCHCAT_CANVAS_COLORS.graphitePlane,
    outerRing: 'rgba(240, 133, 137, 0.78)',
    primaryAccent: PATCHCAT_CANVAS_COLORS.coral,
    secondaryAccent: PATCHCAT_CANVAS_COLORS.coral,
    headFill: PATCHCAT_CANVAS_COLORS.graphite,
    facetFill: PATCHCAT_CANVAS_COLORS.graphiteFacet,
    shieldInnerFill: PATCHCAT_CANVAS_COLORS.graphitePlane,
  },
  success: {
    surfaceTint: PATCHCAT_CANVAS_COLORS.graphitePlane,
    outerRing: 'rgba(100, 205, 177, 0.74)',
    primaryAccent: PATCHCAT_CANVAS_COLORS.emerald,
    secondaryAccent: PATCHCAT_CANVAS_COLORS.emerald,
    headFill: PATCHCAT_CANVAS_COLORS.graphite,
    facetFill: PATCHCAT_CANVAS_COLORS.graphiteFacet,
    shieldInnerFill: PATCHCAT_CANVAS_COLORS.graphitePlane,
  },
};

export interface MascotControllerHandle {
  setState(state: MascotState): void;
  getState(): MascotState;
  destroy(): void;
}

const SCALE = 1.9;
const ORIGIN_X = 32;
const ORIGIN_Y = 33.5;

function toCanvasX(svgX: number): number {
  return (svgX - ORIGIN_X) * SCALE;
}

function toCanvasY(svgY: number): number {
  return (svgY - ORIGIN_Y) * SCALE;
}

function traceClosedPolygon(
  ctx: CanvasRenderingContext2D,
  points: ReadonlyArray<readonly [number, number]>,
  offsetX = 0,
  offsetY = 0
): void {
  if (points.length === 0) return;
  ctx.beginPath();
  ctx.moveTo(toCanvasX(points[0][0]) + offsetX, toCanvasY(points[0][1]) + offsetY);
  for (let i = 1; i < points.length; i += 1) {
    ctx.lineTo(toCanvasX(points[i][0]) + offsetX, toCanvasY(points[i][1]) + offsetY);
  }
  ctx.closePath();
}

function tracePolyline(
  ctx: CanvasRenderingContext2D,
  points: ReadonlyArray<readonly [number, number]>
): void {
  if (points.length === 0) return;
  ctx.beginPath();
  ctx.moveTo(toCanvasX(points[0][0]), toCanvasY(points[0][1]));
  for (let i = 1; i < points.length; i += 1) {
    ctx.lineTo(toCanvasX(points[i][0]), toCanvasY(points[i][1]));
  }
}

const HEAD_OUTLINE: ReadonlyArray<readonly [number, number]> = [
  [12.2, 24.4],
  [14.4, 7.6],
  [24.4, 15.8],
  [32.0, 15.0],
  [39.6, 15.8],
  [49.6, 7.6],
  [50.6, 13.0],
  [45.6, 14.6],
  [46.2, 17.4],
  [51.2, 18.6],
  [51.8, 24.4],
  [52.2, 30.8],
  [47.8, 39.0],
  [38.0, 42.0],
  [32.0, 42.6],
  [26.0, 42.0],
  [16.2, 39.0],
  [11.8, 30.8],
];

const LEFT_EAR_FACET: ReadonlyArray<readonly [number, number]> = [
  [16.0, 12.8],
  [21.8, 17.4],
  [15.4, 22.0],
];

const RIGHT_EAR_FACET: ReadonlyArray<readonly [number, number]> = [
  [46.8, 12.4],
  [42.0, 17.2],
  [48.0, 21.8],
  [48.2, 19.8],
  [44.0, 18.2],
  [44.0, 14.2],
];

const SHIELD_COLLAR: ReadonlyArray<readonly [number, number]> = [
  [15.8, 39.4],
  [26.0, 42.0],
  [32.0, 42.6],
  [38.0, 42.0],
  [48.2, 39.4],
  [49.6, 47.4],
  [32.0, 59.0],
  [14.4, 47.4],
];

const SHIELD_INNER: ReadonlyArray<readonly [number, number]> = [
  [20.4, 43.2],
  [32.0, 45.0],
  [43.6, 43.2],
  [44.6, 47.2],
  [32.0, 55.8],
  [19.4, 47.2],
];

export class MotionCatMascot3D implements MascotControllerHandle {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D | null;
  private container: HTMLElement | null = null;
  private animId: number = 0;
  private mouseX: number = 0;
  private mouseY: number = 0;
  private state: MascotState = 'idle';
  private destroyed: boolean = false;
  private isDocumentVisible: boolean =
    typeof document !== 'undefined' ? !document.hidden : true;
  private isInViewport: boolean = true;
  private lastDrawTs: number = 0;
  private highFpsUntil: number = 0;
  private intersectionObserver: IntersectionObserver | null = null;
  private readonly onMouseMove: (e: MouseEvent) => void;
  private readonly onVisibilityChange: () => void;

  constructor(containerId: string, initialState: MascotState = 'idle') {
    const container =
      typeof document !== 'undefined' ? document.getElementById(containerId) : null;
    if (!container) {
      throw new Error(`Container ${containerId} not found`);
    }
    this.container = container;
    this.state = initialState;

    this.canvas = document.createElement('canvas');
    this.canvas.width = 160;
    this.canvas.height = 160;
    this.canvas.style.cursor = 'pointer';
    this.canvas.setAttribute('data-mascot-state', initialState);
    this.canvas.setAttribute('aria-hidden', 'true');
    container.appendChild(this.canvas);

    this.ctx =
      typeof this.canvas.getContext === 'function'
        ? this.canvas.getContext('2d')
        : null;

    this.onMouseMove = (e: MouseEvent) => {
      if (!this.shouldAnimate()) return;
      if (typeof this.canvas.getBoundingClientRect !== 'function') return;
      const rect = this.canvas.getBoundingClientRect();
      this.mouseX = (e.clientX - rect.left - rect.width / 2) / 14;
      this.mouseY = (e.clientY - rect.top - rect.height / 2) / 14;
      this.highFpsUntil = this.nowMs() + 650;
    };

    this.onVisibilityChange = () => {
      this.isDocumentVisible =
        typeof document !== 'undefined' ? !document.hidden : true;
      if (this.shouldAnimate()) {
        this.lastDrawTs = 0;
        this.highFpsUntil = this.nowMs() + 400;
        this.scheduleNextFrame();
      } else {
        this.pauseAnimation();
      }
    };

    this.bindEvents();
    this.drawFrame();
    this.scheduleNextFrame();
  }

  public getState(): MascotState {
    return this.state;
  }

  public setState(nextState: MascotState): void {
    this.state = nextState;
    this.highFpsUntil = this.nowMs() + 650;
    if (typeof this.canvas.setAttribute === 'function') {
      this.canvas.setAttribute('data-mascot-state', nextState);
    }
    if (this.container && typeof this.container.setAttribute === 'function') {
      this.container.setAttribute('data-mascot-state', nextState);
    }
    if (this.ctx) {
      this.drawFrame();
    }
    if (this.shouldAnimate() && !this.animId) {
      this.scheduleNextFrame();
    }
  }

  private nowMs(): number {
    return typeof performance !== 'undefined' && typeof performance.now === 'function'
      ? performance.now()
      : Date.now();
  }

  private prefersReducedMotion(): boolean {
    return (
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
    );
  }

  private shouldAnimate(): boolean {
    return (
      !this.destroyed &&
      Boolean(this.ctx) &&
      this.isDocumentVisible &&
      this.isInViewport &&
      !this.prefersReducedMotion()
    );
  }

  private pauseAnimation(): void {
    if (typeof cancelAnimationFrame === 'function' && this.animId) {
      cancelAnimationFrame(this.animId);
    }
    this.animId = 0;
  }

  private bindEvents(): void {
    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
      window.addEventListener('mousemove', this.onMouseMove, { passive: true });
    }
    if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
      document.addEventListener('visibilitychange', this.onVisibilityChange);
    }
    if (typeof IntersectionObserver === 'function') {
      this.intersectionObserver = new IntersectionObserver(
        (entries) => {
          const entry = entries[entries.length - 1];
          if (!entry) return;
          this.isInViewport = entry.isIntersecting;
          if (this.shouldAnimate()) {
            this.lastDrawTs = 0;
            this.scheduleNextFrame();
          } else {
            this.pauseAnimation();
          }
        },
        { threshold: 0.01 }
      );
      this.intersectionObserver.observe(this.canvas);
    }
  }

  private scheduleNextFrame(): void {
    if (this.destroyed || !this.ctx) return;
    if (!this.shouldAnimate()) {
      this.pauseAnimation();
      return;
    }
    if (this.animId) return;
    if (typeof requestAnimationFrame === 'function') {
      this.animId = requestAnimationFrame(this.animate);
    }
  }

  private animate = (nowTs: number): void => {
    this.animId = 0;
    if (!this.shouldAnimate()) {
      return;
    }
    const ts =
      typeof nowTs === 'number' && Number.isFinite(nowTs)
        ? nowTs
        : this.nowMs();
    const minIntervalMs =
      ts < this.highFpsUntil || this.state === 'scanning' ? 16 : 38;
    if (this.lastDrawTs === 0 || ts - this.lastDrawTs >= minIntervalMs) {
      this.lastDrawTs = ts;
      this.drawFrame();
    }
    if (typeof requestAnimationFrame === 'function' && this.shouldAnimate()) {
      this.animId = requestAnimationFrame(this.animate);
    }
  };

  private drawFrame(): void {
    const ctx = this.ctx;
    if (!ctx) return;

    const palette = STATE_PALETTES[this.state] ?? STATE_PALETTES.idle;
    const reduced = this.prefersReducedMotion();
    const speed = reduced ? 0 : this.state === 'scanning' ? 0.004 : 0.0018;
    const time = reduced ? 0 : Date.now() * speed;

    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    const centerX = 80;
    const centerY = 80 + (reduced ? 0 : Math.cos(time) * 1.1);

    // Crisp architectural outer framing ring (zero neon blur or radial glow slop)
    ctx.save();
    ctx.strokeStyle = palette.outerRing;
    ctx.lineWidth = 2;
    if (this.state === 'scanning') {
      const startAngle = (time * 2.1) % (Math.PI * 2);
      ctx.beginPath();
      ctx.arc(centerX, centerY, 64, startAngle, startAngle + Math.PI * 1.15);
      ctx.stroke();

      ctx.strokeStyle = palette.secondaryAccent;
      ctx.lineWidth = 1.6;
      ctx.beginPath();
      ctx.arc(centerX, centerY, 69, startAngle + Math.PI, startAngle + Math.PI * 1.55);
      ctx.stroke();
    } else {
      ctx.beginPath();
      ctx.arc(centerX, centerY, 64, 0, Math.PI * 2);
      ctx.stroke();
    }
    ctx.restore();

    // Precision angular PatchCat bust + shield collar
    ctx.save();
    ctx.translate(centerX, centerY);
    const pointerTilt = reduced
      ? 0
      : Math.max(-0.08, Math.min(0.08, this.mouseX * 0.01));
    const scanTilt =
      this.state === 'scanning' && !reduced ? Math.sin(time * 1.4) * 0.04 : 0;
    ctx.rotate(pointerTilt + scanTilt);

    // 1. Angular shield-shaped collar
    traceClosedPolygon(ctx, SHIELD_COLLAR);
    ctx.fillStyle = palette.headFill;
    ctx.fill();
    ctx.strokeStyle = palette.primaryAccent;
    ctx.lineWidth = 2.4;
    ctx.stroke();

    traceClosedPolygon(ctx, SHIELD_INNER);
    ctx.fillStyle = palette.shieldInnerFill;
    ctx.fill();
    ctx.strokeStyle = palette.outerRing;
    ctx.lineWidth = 1.1;
    ctx.stroke();

    // 2. Observant notched-ear head silhouette (fill first, facets inside, crisp outline on top)
    traceClosedPolygon(ctx, HEAD_OUTLINE);
    ctx.fillStyle = palette.headFill;
    ctx.fill();

    // Inner ear facets
    traceClosedPolygon(ctx, LEFT_EAR_FACET);
    ctx.fillStyle = palette.facetFill;
    ctx.fill();

    traceClosedPolygon(ctx, RIGHT_EAR_FACET);
    ctx.fillStyle = palette.facetFill;
    ctx.fill();

    // Subtle brow ridge hairline
    tracePolyline(ctx, [
      [24.4, 15.8],
      [32.0, 19.8],
      [39.6, 15.8],
    ]);
    ctx.strokeStyle = palette.outerRing;
    ctx.lineWidth = 1.25;
    ctx.stroke();

    traceClosedPolygon(ctx, HEAD_OUTLINE);
    ctx.strokeStyle = palette.primaryAccent;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // 3. Geometric eyes per functional state
    const eyeShiftX =
      this.state === 'scanning' && !reduced
        ? Math.sin(time * 2.4) * 2.2
        : reduced
          ? 0
          : Math.max(-1.4, Math.min(1.4, this.mouseX * 0.25));
    const eyeShiftY = reduced
      ? 0
      : Math.max(-1.0, Math.min(1.0, this.mouseY * 0.2));

    if (this.state === 'scanning') {
      ctx.fillStyle = palette.primaryAccent;
      traceClosedPolygon(
        ctx,
        [
          [17.8, 26.8],
          [24.8, 27.1],
          [24.8, 29.6],
          [18.0, 29.4],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
      traceClosedPolygon(
        ctx,
        [
          [36.2, 27.1],
          [43.4, 26.8],
          [43.4, 29.4],
          [36.2, 29.6],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();

      ctx.fillStyle = palette.secondaryAccent;
      traceClosedPolygon(
        ctx,
        [
          [25.6, 27.1],
          [27.8, 27.1],
          [27.8, 29.6],
          [25.6, 29.6],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
      traceClosedPolygon(
        ctx,
        [
          [44.2, 26.8],
          [46.4, 26.8],
          [46.4, 29.3],
          [44.2, 29.3],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
    } else if (this.state === 'alert') {
      ctx.fillStyle = palette.primaryAccent;
      traceClosedPolygon(
        ctx,
        [
          [17.6, 24.8],
          [28.0, 28.4],
          [26.8, 31.6],
          [17.8, 28.6],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
      traceClosedPolygon(
        ctx,
        [
          [46.4, 24.8],
          [36.0, 28.4],
          [37.2, 31.6],
          [46.2, 28.6],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
    } else if (this.state === 'success') {
      ctx.fillStyle = palette.primaryAccent;
      traceClosedPolygon(
        ctx,
        [
          [18.2, 27.0],
          [27.2, 27.2],
          [26.6, 30.4],
          [18.4, 30.2],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
      traceClosedPolygon(
        ctx,
        [
          [45.8, 27.0],
          [36.8, 27.2],
          [37.4, 30.4],
          [45.6, 30.2],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
    } else {
      ctx.fillStyle = palette.primaryAccent;
      traceClosedPolygon(
        ctx,
        [
          [18.0, 26.2],
          [27.4, 27.6],
          [26.6, 31.0],
          [18.0, 30.2],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
      traceClosedPolygon(
        ctx,
        [
          [46.0, 26.2],
          [36.6, 27.6],
          [37.4, 31.0],
          [46.0, 30.2],
        ],
        eyeShiftX,
        eyeShiftY
      );
      ctx.fill();
    }

    // 4. Nose wedge
    ctx.fillStyle = palette.primaryAccent;
    traceClosedPolygon(ctx, [
      [29.4, 34.6],
      [34.6, 34.6],
      [32.0, 37.8],
    ]);
    ctx.fill();

    // 5. Collar shield state glyph
    if (this.state === 'scanning') {
      ctx.strokeStyle = palette.secondaryAccent;
      ctx.lineWidth = 2.4;
      tracePolyline(ctx, [
        [27.8, 49.4],
        [32.0, 52.8],
        [36.2, 49.4],
      ]);
      ctx.stroke();

      ctx.strokeStyle = palette.primaryAccent;
      ctx.lineWidth = 2.0;
      tracePolyline(ctx, [
        [29.0, 46.2],
        [32.0, 48.8],
        [35.0, 46.2],
      ]);
      ctx.stroke();
    } else if (this.state === 'alert') {
      ctx.fillStyle = palette.primaryAccent;
      traceClosedPolygon(ctx, [
        [30.8, 44.8],
        [33.2, 44.8],
        [33.2, 49.6],
        [30.8, 49.6],
      ]);
      ctx.fill();
      traceClosedPolygon(ctx, [
        [32.0, 51.0],
        [33.6, 52.6],
        [32.0, 54.2],
        [30.4, 52.6],
      ]);
      ctx.fill();
    } else if (this.state === 'success') {
      ctx.strokeStyle = palette.primaryAccent;
      ctx.lineWidth = 2.8;
      tracePolyline(ctx, [
        [27.6, 49.6],
        [30.6, 52.6],
        [36.6, 46.6],
      ]);
      ctx.stroke();
    } else {
      ctx.fillStyle = palette.secondaryAccent;
      traceClosedPolygon(ctx, [
        [32.0, 46.0],
        [35.5, 49.5],
        [32.0, 53.0],
        [28.5, 49.5],
      ]);
      ctx.fill();
    }

    ctx.restore();
  }

  public destroy(): void {
    this.destroyed = true;
    this.pauseAnimation();
    if (typeof window !== 'undefined' && typeof window.removeEventListener === 'function') {
      window.removeEventListener('mousemove', this.onMouseMove);
    }
    if (typeof document !== 'undefined' && typeof document.removeEventListener === 'function') {
      document.removeEventListener('visibilitychange', this.onVisibilityChange);
    }
    if (this.intersectionObserver) {
      this.intersectionObserver.disconnect();
      this.intersectionObserver = null;
    }
    if (this.canvas.parentElement) {
      this.canvas.parentElement.removeChild(this.canvas);
    }
  }
}

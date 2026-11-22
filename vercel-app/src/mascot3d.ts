export type MascotState = 'idle' | 'scanning' | 'alert' | 'success';
export type PatchCatPose = 'idle' | 'scanning' | 'alert' | 'verified' | 'needs_review';

const PALETTE = {
  graphite: '#0C121A',
  graphitePlane: '#111C28',
  graphiteFacet: '#162330',
  iceBlue: '#79B7F3',
  emerald: '#64CDB1',
  violet: '#A594F9',
  amber: '#EDBA6C',
  coral: '#F08589',
} as const;

interface PoseSpec {
  accent: string;
  eyesSvg: string;
  shieldSvg: string;
}

const POSE_SPECS: Record<PatchCatPose, PoseSpec> = {
  idle: {
    accent: PALETTE.iceBlue,
    eyesSvg: `<polygon points="18.0,26.2 27.4,27.6 26.6,31.0 18.0,30.2" fill="${PALETTE.iceBlue}" /><polygon points="46.0,26.2 36.6,27.6 37.4,31.0 46.0,30.2" fill="${PALETTE.iceBlue}" />`,
    shieldSvg: `<polygon points="32.0,46.0 35.5,49.5 32.0,53.0 28.5,49.5" fill="${PALETTE.violet}" />`,
  },
  scanning: {
    accent: PALETTE.iceBlue,
    eyesSvg: `<polygon points="17.8,26.8 24.8,27.1 24.8,29.6 18.0,29.4" fill="${PALETTE.iceBlue}" /><rect x="25.6" y="27.1" width="2.2" height="2.5" fill="${PALETTE.violet}" /><polygon points="36.2,27.1 43.4,26.8 43.4,29.4 36.2,29.6" fill="${PALETTE.iceBlue}" /><rect x="44.2" y="26.8" width="2.2" height="2.5" fill="${PALETTE.violet}" />`,
    shieldSvg: `<path d="M 27.8 49.4 L 32.0 52.8 L 36.2 49.4" fill="none" stroke="${PALETTE.violet}" stroke-width="2" stroke-linecap="square" /><path d="M 52.2 6.8 A 8.5 8.5 0 0 1 56.8 14.4" fill="none" stroke="${PALETTE.violet}" stroke-width="1.8" stroke-linecap="square" />`,
  },
  alert: {
    accent: PALETTE.coral,
    eyesSvg: `<polygon points="17.6,24.8 28.0,28.4 26.8,31.6 17.8,28.6" fill="${PALETTE.coral}" /><polygon points="46.4,24.8 36.0,28.4 37.2,31.6 46.2,28.6" fill="${PALETTE.coral}" />`,
    shieldSvg: `<rect x="30.8" y="44.8" width="2.4" height="4.8" fill="${PALETTE.coral}" /><polygon points="32.0,51.0 33.6,52.6 32.0,54.2 30.4,52.6" fill="${PALETTE.coral}" />`,
  },
  verified: {
    accent: PALETTE.emerald,
    eyesSvg: `<polygon points="18.2,27.0 27.2,27.2 26.6,30.4 18.4,30.2" fill="${PALETTE.emerald}" /><polygon points="45.8,27.0 36.8,27.2 37.4,30.4 45.6,30.2" fill="${PALETTE.emerald}" />`,
    shieldSvg: `<path d="M 27.6 49.6 L 30.6 52.6 L 36.6 46.6" fill="none" stroke="${PALETTE.emerald}" stroke-width="2.3" stroke-linecap="square" stroke-linejoin="miter" />`,
  },
  needs_review: {
    accent: PALETTE.amber,
    eyesSvg: `<polygon points="18.0,26.8 27.2,27.2 26.6,30.4 18.2,30.2" fill="${PALETTE.amber}" /><polygon points="36.8,27.8 46.0,26.8 45.6,29.2 37.0,29.8" fill="${PALETTE.amber}" />`,
    shieldSvg: `<rect x="28.6" y="46.2" width="2.3" height="6.0" fill="${PALETTE.amber}" /><rect x="33.1" y="46.2" width="2.3" height="6.0" fill="${PALETTE.amber}" />`,
  },
};

export function mapMascotStateToPose(state: MascotState, needsReview = false): PatchCatPose {
  if (state === 'scanning') return 'scanning';
  if (state === 'alert') return 'alert';
  if (needsReview) return 'needs_review';
  if (state === 'success') return 'verified';
  return 'idle';
}

export function renderPatchCatSvg(
  pose: PatchCatPose,
  opts: { size?: number; label?: string } = {}
): string {
  const size = opts.size ?? 56;
  const spec = POSE_SPECS[pose];
  const label = opts.label ?? `PatchCat ${pose}`;
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="${size}" height="${size}" fill="none" role="img" aria-label="${label}">`,
    `<polygon points="15.8,39.4 26.0,42.0 32.0,42.6 38.0,42.0 48.2,39.4 49.6,47.4 32.0,59.0 14.4,47.4" fill="${PALETTE.graphite}" stroke="${spec.accent}" stroke-width="2.1" stroke-linejoin="miter" stroke-miterlimit="2.5" />`,
    `<polygon points="20.4,43.2 32.0,45.0 43.6,43.2 44.6,47.2 32.0,55.8 19.4,47.2" fill="${PALETTE.graphitePlane}" stroke="${spec.accent}" stroke-opacity="0.34" stroke-width="1" />`,
    `<path d="M 12.2 24.4 L 14.4 7.6 L 24.4 15.8 L 32.0 15.0 L 39.6 15.8 L 49.6 7.6 L 50.6 13.0 L 45.6 14.6 L 46.2 17.4 L 51.2 18.6 L 51.8 24.4 L 52.2 30.8 L 47.8 39.0 L 38.0 42.0 L 32.0 42.6 L 26.0 42.0 L 16.2 39.0 L 11.8 30.8 Z" fill="${PALETTE.graphite}" />`,
    `<polygon points="16.0,12.8 21.8,17.4 15.4,22.0" fill="${PALETTE.graphiteFacet}" />`,
    `<polygon points="46.8,12.4 42.0,17.2 48.0,21.8 48.2,19.8 44.0,18.2 44.0,14.2" fill="${PALETTE.graphiteFacet}" />`,
    `<path d="M 12.2 24.4 L 14.4 7.6 L 24.4 15.8 L 32.0 15.0 L 39.6 15.8 L 49.6 7.6 L 50.6 13.0 L 45.6 14.6 L 46.2 17.4 L 51.2 18.6 L 51.8 24.4 L 52.2 30.8 L 47.8 39.0 L 38.0 42.0 L 32.0 42.6 L 26.0 42.0 L 16.2 39.0 L 11.8 30.8 Z" fill="none" stroke="${spec.accent}" stroke-width="2.15" stroke-linejoin="miter" stroke-miterlimit="2.5" />`,
    spec.eyesSvg,
    `<polygon points="29.4,34.6 34.6,34.6 32.0,37.8" fill="${spec.accent}" />`,
    spec.shieldSvg,
    '</svg>',
  ].join('');
}

export class MotionCatMascot3D {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D | null;
  private animId = 0;
  private state: MascotState;
  private destroyed = false;
  private isDocumentVisible = typeof document !== 'undefined' ? !document.hidden : true;
  private isInViewport = true;
  private lastDrawTs = 0;
  private highFpsUntil = 0;
  private mouseHoverActive = false;
  private intersectionObserver: IntersectionObserver | null = null;
  private readonly onVisibilityChange: () => void;
  private readonly onMouseEnter: () => void;

  constructor(containerId: string, initialState: MascotState = 'idle') {
    const container = document.getElementById(containerId);
    if (!container) throw new Error(`Container ${containerId} not found`);
    this.state = initialState;
    this.canvas = document.createElement('canvas');
    this.canvas.width = 160;
    this.canvas.height = 160;
    this.canvas.setAttribute('aria-hidden', 'true');
    container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext('2d');

    this.onMouseEnter = () => {
      this.mouseHoverActive = true;
      this.highFpsUntil = this.nowMs() + 650;
    };

    this.onVisibilityChange = () => {
      this.isDocumentVisible = typeof document !== 'undefined' ? !document.hidden : true;
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

  public setState(next: MascotState): void {
    this.state = next;
    this.highFpsUntil = this.nowMs() + 650;
    this.drawFrame();
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
    if (typeof this.canvas.addEventListener === 'function') {
      this.canvas.addEventListener('mousemove', this.onMouseEnter, { passive: true });
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
      this.mouseHoverActive && ts < this.highFpsUntil
        ? 16
        : ts < this.highFpsUntil || this.state === 'scanning'
          ? 16
          : 38;
    if (ts >= this.highFpsUntil) {
      this.mouseHoverActive = false;
    }
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
    const pose = mapMascotStateToPose(this.state);
    const accent = POSE_SPECS[pose].accent;
    const reduced =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const t = reduced ? 0 : Date.now() * 0.0025;
    const cy = 80 + (reduced ? 0 : Math.cos(t) * 1.5);

    ctx.clearRect(0, 0, 160, 160);
    ctx.strokeStyle = this.state === 'scanning' ? PALETTE.violet : accent;
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    if (this.state === 'scanning') {
      const a = (t * 2) % (Math.PI * 2);
      ctx.arc(80, cy, 58, a, a + Math.PI * 1.15);
    } else {
      ctx.arc(80, cy, 58, 0, Math.PI * 2);
    }
    ctx.stroke();

    ctx.save();
    ctx.translate(80, cy);
    ctx.fillStyle = PALETTE.graphite;
    ctx.strokeStyle = accent;
    ctx.lineWidth = 2.4;
    ctx.beginPath();
    ctx.moveTo(-38, -14);
    ctx.lineTo(-34, -46);
    ctx.lineTo(-14, -30);
    ctx.lineTo(0, -32);
    ctx.lineTo(14, -30);
    ctx.lineTo(34, -46);
    ctx.lineTo(36, -34);
    ctx.lineTo(26, -30);
    ctx.lineTo(28, -24);
    ctx.lineTo(38, -22);
    ctx.lineTo(38, -14);
    ctx.lineTo(30, 18);
    ctx.lineTo(0, 32);
    ctx.lineTo(-30, 18);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = accent;
    ctx.fillRect(-24, -10, 14, 6);
    ctx.fillRect(10, -10, 14, 6);
    ctx.beginPath();
    ctx.moveTo(0, 10);
    ctx.lineTo(-5, 4);
    ctx.lineTo(5, 4);
    ctx.closePath();
    ctx.fill();
    ctx.restore();
  }

  public destroy(): void {
    this.destroyed = true;
    this.pauseAnimation();
    if (typeof this.canvas.removeEventListener === 'function') {
      this.canvas.removeEventListener('mousemove', this.onMouseEnter);
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

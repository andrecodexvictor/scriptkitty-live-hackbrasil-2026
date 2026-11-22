# ScriptKitty Live — Visual Design System (`DESIGN.md`)

## Brand Anchor
- **Mood:** Precision security engineering console — refined dark graphite canvas (`#0C121A`), crisp `1px` structural hairlines, tabular monospace digests, zero visual theater.
- **Default Theme:** `data-theme="dark"` (Dark Graphite). Optional daylight toggle (`data-theme="light"`) switches cleanly via `#btn-toggle-theme` and shares identical semantic ratios.

## OKLCH Color System (100% OKLCH Tokens)
| Token | Dark Graphite Default (`data-theme="dark"`) | Light Mode (`data-theme="light"`) | Role |
|---|---|---|---|
| `--bg` | `oklch(0.180 0.019 255.8)` (`#0C121A`) | `oklch(0.985 0.003 248.0)` | Primary application canvas |
| `--surface` | `oklch(0.222 0.028 251.3)` (`#111C28`) | `oklch(1.000 0.000 0.0)` | Primary card / panel surface |
| `--surface-subtle` | `oklch(0.251 0.031 249.1)` (`#162330`) | `oklch(0.958 0.005 248.0)` | Secondary surface, headers, table rows |
| `--ink` | `oklch(0.971 0.007 247.9)` (`#F2F6FA`) | `oklch(0.180 0.019 255.8)` | Primary text (>= 14:1 contrast) |
| `--ink-secondary` | `oklch(0.865 0.016 247.0)` | `oklch(0.320 0.022 251.0)` | Secondary prose (>= 9:1 contrast) |
| `--ink-muted` | `oklch(0.748 0.032 245.2)` (`#9DB0C1`) | `oklch(0.450 0.020 248.0)` | Labels, captions (>= 6.2:1 contrast) |
| `--border` | `oklch(0.341 0.042 249.1)` (`#273A4D`) | `oklch(0.885 0.012 248.0)` | Structural `1px` hairline borders |
| `--primary` | `oklch(0.761 0.108 248.6)` (`#79B7F3`) | `oklch(0.450 0.140 248.0)` | Ice-blue primary CTA & active focus |
| `--on-primary` | `oklch(0.180 0.019 255.8)` (`#0C121A`) | `oklch(1.000 0.000 0.0)` | Button text on `--primary` (>= 7.2:1) |
| `--status-ok` | `oklch(0.778 0.107 173.6)` (`#64CDB1`) | `oklch(0.430 0.120 173.6)` | Emerald verified / pass states |
| `--accent-violet` | `oklch(0.723 0.144 290.0)` (`#A594F9`) | `oklch(0.450 0.144 290.0)` | Telemetry accent only (never on h1-h3) |
| `--status-warn` | `oklch(0.819 0.113 76.7)` (`#EDBA6C`) | `oklch(0.480 0.135 72.0)` | Amber review / advisory warning |
| `--status-risk` | `oklch(0.734 0.131 18.4)` (`#F08589`) | `oklch(0.480 0.175 20.0)` | Coral blocked path / gate rejection |

## Typography
- **Sans UI & Display:** `'IBM Plex Sans', system-ui, -apple-system, sans-serif` (weights 400, 500, 600, 700; zero `Inter`).
- **Monospace Code & Digests:** `'IBM Plex Mono', ui-monospace, SFMono-Regular, monospace` (`font-variant-numeric: tabular-nums`).
- **Scale:** `0.75rem`, `0.8125rem`, `0.875rem`, `1rem`, `1.25rem`, `1.625rem`, `clamp(1.875rem, 3.2vw, 2.625rem)`. Display letter-spacing floor `-0.025em` (>= `-0.04em`), body line-height `1.55`–`1.65`, prose `max-width: 65ch`.

## Anti-Slop, Accessibility & Motion Invariants
- **Strict Anti-AI-Slop:** Zero `background-clip: text` gradients, zero neon glow `box-shadow` blobs, zero fake macOS window dots, zero `border-left` > `1px` card stripes, zero emojis inside buttons/headings/tabs, card radii strictly `<= 12px` (`8px` panels, `6px` inputs/buttons, `9999px` status pills only).
- **WCAG 2.2 AA:** Contrast `>= 4.5:1` for body text, visible `:focus-visible` ring, `>= 44x44px` touch targets on mobile (`<= 768px`), keyboard `ArrowLeft` / `ArrowRight` support on scenario `role="tablist"`, accessible `<table class="sr-table">` mirror for the ChainBreak SVG graph, and skip-to-content link.
- **Motion.dev (`motion`) & CSS:** `150`–`240ms` exponential ease `cubic-bezier(0.22, 1, 0.36, 1)` (`[0.22, 1, 0.36, 1]`), SVG violation path draw, full `@media (prefers-reduced-motion: reduce)` degradation.

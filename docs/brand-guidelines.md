# PatchCat Brand Guidelines — ScriptKitty Live

**Product:** ScriptKitty Live  
**Autonomous Security Agent:** PatchCat  
**Primary Capability:** ChainBreak (Deterministic Policy-Graph & Attack-Path Reachability)  
**Asset Roots:** `assets/brand/*` · `apps/ui/public/brand/*` · `vercel-app/public/brand/*`  
**UI Modules:** [`apps/ui/src/patchcat-mascot.ts`](../apps/ui/src/patchcat-mascot.ts) · [`apps/ui/src/mascot3d.ts`](../apps/ui/src/mascot3d.ts)

---

## 1. Visual Concept & Silhouette Architecture

PatchCat is an **observant cybersecurity operator** expressed as a sharp, minimalist geometric vector mark. Every asset is constructed on clean integer coordinate grids (`24x24` adaptive icon grid; `64x64` master emblem grid) with zero soft glow filters, zero gradients, and zero decorative clutter.

### Core Structural Signatures
1. **Asymmetric Notched-Ear Silhouette:** Left ear maintains an unbroken angular apex; the right outer ear carries an intentional stepped sentinel notch (`x: 45.6..51.2, y: 13.0..18.6` on the `64x64` artboard) that preserves recognizability across monochrome and multi-tone renders down to `16px`.
2. **Calm Geometric Eyes:** Trapezoidal precision optical lenses communicate vigilant observation rather than cartoon emotion. Lens angle and segmentation shift cleanly across the five functional telemetry states.
3. **Angular Shield-Shaped Collar & Chest Plate:** Beneath the chin, a faceted V-shield anchors the bust (`y: 39.4..59.0` on `64x64`) and carries the deterministic state glyph (`diamond`, `telemetry chevrons`, `exclamation monolith`, `verified checkmark`, or `review bars`) so every state remains distinguishable without relying on color alone.

---

## 2. Color System & Contrast Rules

| Token | Hex | Semantic Role | Surface Pairing & Contrast Notes |
|---|---|---|---|
| **Dark Graphite** | `#0C121A` | Primary emblem fill, dark canvas base, light-mode icon stroke | High-contrast anchor (`> 14:1` against `#F2F6FA` and `#F8FAFC` light surfaces) |
| **Graphite Plane** | `#111C28` | Inner collar plate, card surface, showcase tile fill | Subtle structural separation inside `#0C121A` silhouettes |
| **Graphite Facet** | `#162330` | Inner ear architectural planes | Low-contrast depth without gradients or drop shadows |
| **Slate Border** | `#273A4D` | 1px structural dividers & lockup container frames | Crisp hairline boundary on dark surfaces |
| **Ice-Blue** | `#79B7F3` | Primary brand accent, `idle` & `scanning` outline/eyes | `>= 8.2:1` contrast against `#0C121A` dark graphite |
| **Emerald-Green** | `#64CDB1` | `verified` / healthy posture (`success` / `PASS`) | `>= 9.1:1` contrast against `#0C121A` dark graphite |
| **Refined Violet** | `#A594F9` | Secondary telemetry node (`idle` core, `scanning` sweep) | `>= 6.6:1` contrast against `#0C121A` dark graphite |
| **Amber** | `#EDBA6C` | `needs_review` (`PENDING_REVIEW` / human escalation) | `>= 9.4:1` contrast against `#0C121A` dark graphite |
| **Coral-Risk** | `#F08589` | `alert` (`PATH_VALIDATED` risk path / gate `REJECT`) | `>= 6.8:1` contrast against `#0C121A` dark graphite |

### Light & Dark Surface Rules
- **Adaptive Monochrome Icon (`patchcat-symbol.svg`):** Uses `currentColor` exclusively. On light canvases (`#FFFFFF` / `#F8FAFC`), set icon `color: #0C121A` (or `var(--ink)`). On dark canvases (`#0C121A` / `#111C28`), set `color: #79B7F3` or `#F2F6FA`.
- **Full-Color SVG & PNG Assets (`patchcat-avatar.png`, `renderPatchCatSvg`):** The `#0C121A` dark graphite body combined with `#79B7F3` / `#64CDB1` / `#EDBA6C` / `#F08589` outer silhouette strokes maintains clear edge separation on both dark graphite (`#111C28`) and light daylight (`#FFFFFF`) UI surfaces without needing glow shadows.
- **Horizontal Lockup (`patchcat-lockup-horizontal.svg`):** Self-contained inside an obsidian-graphite `#0C121A` frame with `#273A4D` border so it retains consistent contrast on GitHub README light mode, GitHub dark mode, and application headers.

---

## 3. Safe Area & Scale Legibility (`16px` · `24px` · `64px`)

### Clear Space (Safe Area)
- **Emblem & Avatar (`64x64` / `512x512`):** Maintain at least **10% optical padding** from artwork perimeter (`>= 6px` on `64x64`; `>= 32px` around the outer stroke on `512x512`).
- **Horizontal Lockup (`288x64`):** Preserve internal `16px` vertical divider margin and keep external surrounding padding at least `0.5x` the emblem height (`>= 24px`) when placed in hero headers or documentation banners.

### Verified Scale Checkpoints
| Size | Recommended Asset | Legibility Standard |
|---|---|---|
| **`16px × 16px`** | `patchcat-symbol.svg`, `favicon.svg` | Bold `1.8`–`2.65` relative stroke weight; notched right ear, eyes, and shield tip remain separated without stroke collapse. Never place `patchcat-states.svg` or full lockup text at `16px`. |
| **`24px × 24px`** | `patchcat-symbol.svg`, `renderPatchCatSvg(pose, { size: 24 })` | Inline navigation badges, status indicators, and toolbar buttons. Primary silhouette + pose color and collar silhouette stay clear. |
| **`64px × 64px+`** | `renderPatchCatSvg(pose, { size: 64 })`, `MotionCatMascot3D`, `patchcat-avatar.png` | Full telemetry panels, landing hero emblems, and documentation cards (`512x512` raster avatar scales cleanly down to `64px`–`128px`). |

---

## 4. Five Functional Pose Specifications (`PatchCatPose`)

Implemented in [`apps/ui/src/patchcat-mascot.ts`](../apps/ui/src/patchcat-mascot.ts) and mirrored visually in [`assets/brand/patchcat-states.svg`](../assets/brand/patchcat-states.svg):

| `PatchCatPose` | Mapped `MascotState` (`mapMascotStateToPose`) | Primary / Secondary Hex | Eye Geometry | Shield Collar Glyph |
|---|---|---|---|---|
| `idle` | `'idle'` (`needsReview: false`) | `#79B7F3` / `#A594F9` | Calm outward-balanced trapezoids | Centered violet telemetry diamond |
| `scanning` | `'scanning'` | `#79B7F3` / `#A594F9` | Narrowed scan slits + violet cursor block | Double telemetry chevrons + upper-right ear scan arcs |
| `alert` | `'alert'` | `#F08589` | Sharp inward-angled vigilant wedges | Vertical risk monolith + diamond point |
| `verified` | `'success'` (`needsReview: false`) | `#64CDB1` | Level assured geometric lenses | Crisp geometric checkmark |
| `needs_review` | `'idle'` or `'success'` with `needsReview: true` | `#EDBA6C` | Asymmetric analytic scrutiny (steady left, narrowed right lens) | Dual vertical review-hold bars |

### Reduced Motion Invariant
- `MotionCatMascot3D` in [`apps/ui/src/mascot3d.ts`](../apps/ui/src/mascot3d.ts) checks `window.matchMedia('(prefers-reduced-motion: reduce)').matches`.
- When reduced motion is enabled, `requestAnimationFrame` loops halt immediately after rendering one static frame, pointer tilt is zeroed (`0`), and scanning eye/ring offsets lock to neutral coordinates (`0`).

---

## 5. Typography Discipline

- **Primary UI & Wordmark Sans:** `'IBM Plex Sans', system-ui, -apple-system, sans-serif` (weights `500`, `600`, `700`).
- **Telemetry & State Labels:** `'IBM Plex Mono', ui-monospace, SFMono-Regular, monospace` (`font-variant-numeric: tabular-nums`).
- **Disallowed Font:** Never use `Inter` in any PatchCat SVG, lockup, or UI surface.

---

## 6. Asset Inventory & Mirroring

All brand files live canonically in `assets/brand/` and are mirrored byte-for-byte into `apps/ui/public/brand/` and `vercel-app/public/brand/`:

- `patchcat-symbol.svg` — `24x24` adaptive `currentColor` monochrome mark
- `patchcat-lockup-horizontal.svg` — `288x64` horizontal `"ScriptKitty Live / PatchCat"` wordmark lockup
- `favicon.svg` — `64x64` high-contrast `#0C121A` + `#79B7F3` browser favicon
- `patchcat-states.svg` — `820x196` 5-pose telemetry showcase strip
- `patchcat-avatar.png` — `512x512` transparent RGBA PNG rendered directly from the vector geometry

---

## 7. Forbidden Uses (Strict Brand Guardrails)

1. **Zero Childish Cartoon Tropes:** Do not revert to Sherlock deerstalker hats, magnifying glasses, cartoon whiskers, cute `:3` mouths, or chasing mice.
2. **Zero Threat / Hacker Clichés:** No hoodies, weapons, skulls, masks, or aggressive offensive-security imagery — ScriptKitty Live is a deterministic defensive verification platform.
3. **Zero AI-Slop Visual Effects:** No neon outer-glow blurs (`box-shadow` blobs, SVG `feGaussianBlur` glows), no rainbow/gradient text (`background-clip: text`), no fake macOS window dots, and no decorative text or watermarks inside icon marks.
4. **No Internal Codename Leaks in Brand Surfaces:** Keep internal engine/module codenames out of top-level brand lockups, marketing taglines, and primary mascot labels.
5. **Do Not Distort or Recolor Arbitrarily:** Never stretch the `1:1` artboard aspect ratio, flip the asymmetric notched ear horizontally, or assign `#64CDB1` (`verified`) to an `alert` or `needs_review` posture.

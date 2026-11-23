/**
 * Viewport transform — zoom & pan with a CORRECT pointer→desktop mapping (Milestone V-ZP).
 *
 * The viewer shows the remote desktop in a fixed on-screen surface. Two things must agree, pixel for
 * pixel, or a click lands in the wrong place on the customer's machine:
 *   1. how the desktop image is RENDERED into the surface (CSS), and
 *   2. how a pointer position on the surface is MAPPED back to an absolute desktop coordinate.
 *
 * This module is the SINGLE source of truth for both. `Viewer.tsx` derives the CSS `transform` and the
 * pointer mapping from the very same {@link contentRect}, so the two can never drift — the exact class
 * of bug (two hand-kept mappings disagreeing) that a loop-14 review found in the key path and that the
 * old "input paused in 1:1" workaround existed to dodge. Everything here is pure math on plain numbers,
 * so it is unit-testable with no DOM.
 *
 * ## The model
 *
 * The `<video>` element fills the surface (`width/height: 100%`) with `object-fit: contain`, which
 * letterboxes the desktop to a BASE rect centred in the surface (scale `base = min(Sw/Cw, Sh/Ch)`).
 * On top of that we apply `transform: translate(panX, panY) scale(zoom)` with `transform-origin: 0 0`.
 * Under a top-left origin, a surface point `p` of the untransformed layer maps to `p*zoom + pan`, so
 * the on-screen content rect is `{ ox: ox0*z + panX, oy: oy0*z + panY, cw: cw0*z, ch: ch0*z }` where
 * `(ox0, oy0, cw0, ch0)` is the base letterbox rect. Inverting that rect maps a pointer to a
 * desktop fraction (and then to the agent's 0..=65535 absolute space via {@link toAbs}).
 *
 * `zoom` is expressed RELATIVE TO FIT: `zoom === 1` is scale-to-fit (the whole desktop, letterboxed);
 * `zoom > 1` zooms in. That keeps `zoom === 1 ⇒ panX === panY === 0` (a centred, letterboxed frame) as
 * a clean invariant. The human-facing percentage ({@link displayScalePct}) is native-relative instead,
 * because a technician reads "100%" as "actual pixels", not "the fit".
 */

import { toAbs } from "./dom_input";

/** Smallest zoom: scale-to-fit. Zooming out past the fit only adds black bars, so it is disallowed. */
export const MIN_ZOOM = 1;
/**
 * Largest zoom, relative to fit. 16× the fit scale is far past native for any normal desktop/viewport
 * pair (a 4K desktop in a 1280×720 viewport reaches native — "1:1" — at only ~3× fit). The ceiling
 * exists to keep the transform sane, not to cap useful magnification.
 */
export const MAX_ZOOM = 16;
/** Multiplier for one press of the zoom-in / zoom-out buttons. */
export const ZOOM_STEP = 1.5;
/**
 * Per-`deltaY`-unit exponential rate for Ctrl+wheel zooming. Chosen so one ~100px pixel-mode notch is
 * a ~1.16× step (`e^(0.0015*100)`), close to {@link ZOOM_STEP} but finer for a smooth wheel.
 */
export const WHEEL_ZOOM_RATE = 0.0015;

/** The pan/zoom state. `panX`/`panY` are CSS px applied to the base (contain) layer at origin (0,0). */
export interface ViewTransform {
  /** ≥ {@link MIN_ZOOM}; `1` = scale-to-fit. */
  zoom: number;
  panX: number;
  panY: number;
}

/** Scale-to-fit, no pan — the reset/default view. */
export const IDENTITY_VIEW: ViewTransform = { zoom: 1, panX: 0, panY: 0 };

/**
 * The pixel dimensions the transform needs: the on-screen surface and the intrinsic desktop image.
 * `contentW`/`contentH` come from the `<video>`'s `videoWidth`/`videoHeight`; when they are still
 * unknown (no stream yet) callers pass `0` and the surface size stands in, i.e. the content is treated
 * as exactly filling the surface (correct when the aspect ratios match, which is all a preview needs).
 */
export interface Dims {
  surfaceW: number;
  surfaceH: number;
  contentW: number;
  contentH: number;
}

/** The on-screen rectangle (surface-local px) the desktop image occupies after the transform. */
export interface ContentRect {
  ox: number;
  oy: number;
  cw: number;
  ch: number;
}

/** Clamp any number into `[MIN_ZOOM, MAX_ZOOM]`; a non-finite input floors to {@link MIN_ZOOM}. */
export function clampZoom(z: number): number {
  if (!Number.isFinite(z)) return MIN_ZOOM;
  return Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, z));
}

/** Effective content size: the intrinsic desktop image, or the surface when the image is unknown. */
function effectiveContentDims(d: Dims): { cw: number; ch: number } {
  const cw = d.contentW > 0 && Number.isFinite(d.contentW) ? d.contentW : d.surfaceW;
  const ch = d.contentH > 0 && Number.isFinite(d.contentH) ? d.contentH : d.surfaceH;
  return { cw, ch };
}

/** The base (zoom=1, pan=0) letterbox rect: the `object-fit: contain` fit, centred in the surface. */
function baseFit(
  d: Dims,
): { base: number; cw0: number; ch0: number; ox0: number; oy0: number } | null {
  if (!(d.surfaceW > 0 && d.surfaceH > 0)) return null;
  const { cw, ch } = effectiveContentDims(d);
  if (!(cw > 0 && ch > 0)) return null;
  const base = Math.min(d.surfaceW / cw, d.surfaceH / ch);
  if (!(base > 0) || !Number.isFinite(base)) return null;
  const cw0 = cw * base;
  const ch0 = ch * base;
  return { base, cw0, ch0, ox0: (d.surfaceW - cw0) / 2, oy0: (d.surfaceH - ch0) / 2 };
}

/**
 * The on-screen content rect for a given view, or `null` if the surface/content is degenerate (zero
 * size) — callers treat `null` as "no mapping possible", never as a coordinate.
 */
export function contentRect(d: Dims, view: ViewTransform): ContentRect | null {
  const b = baseFit(d);
  if (!b) return null;
  const z = view.zoom;
  return { ox: b.ox0 * z + view.panX, oy: b.oy0 * z + view.panY, cw: b.cw0 * z, ch: b.ch0 * z };
}

/**
 * Map a surface-local pointer position to the agent's absolute coordinate space (0..=65535), or `null`
 * when the pointer is over the letterbox / off the desktop content (so no bogus edge-clamped click is
 * sent). This is correct at ANY zoom and pan — the whole point of the feature.
 */
export function mapPointerToAbs(
  px: number,
  py: number,
  d: Dims,
  view: ViewTransform,
): { xAbs: number; yAbs: number } | null {
  const r = contentRect(d, view);
  if (!r || !(r.cw > 0 && r.ch > 0)) return null;
  const fx = (px - r.ox) / r.cw;
  const fy = (py - r.oy) / r.ch;
  if (fx < 0 || fx > 1 || fy < 0 || fy > 1) return null;
  return { xAbs: toAbs(fx), yAbs: toAbs(fy) };
}

/**
 * Clamp the pan so the desktop content keeps the surface covered: on an axis where the content is
 * WIDER than the surface it may be dragged only within `[S - c, 0]` (no black gap at either edge); on
 * an axis where it is narrower (or equal) it is CENTRED. At `zoom === 1` this yields `pan === 0`.
 */
export function clampPan(d: Dims, view: ViewTransform): ViewTransform {
  const r = contentRect(d, view);
  if (!r) return view;
  const clampAxis = (o: number, c: number, s: number): number => {
    if (c <= s) return (s - c) / 2; // content fits within the surface on this axis → centre it
    return Math.max(s - c, Math.min(0, o)); // else keep both edges covered: o ∈ [s - c, 0]
  };
  const oxc = clampAxis(r.ox, r.cw, d.surfaceW);
  const oyc = clampAxis(r.oy, r.ch, d.surfaceH);
  return { zoom: view.zoom, panX: view.panX + (oxc - r.ox), panY: view.panY + (oyc - r.oy) };
}

/**
 * Zoom to `nextZoom` while holding the desktop point currently under `(px, py)` fixed under the
 * cursor (the standard "zoom toward the pointer"). Derivation: the surface→base-layer map is
 * `(p - pan) / zoom`; holding it invariant across the zoom change gives
 * `pan' = p - (p - pan) * (zoom'/zoom)`. The result is pan-clamped. A no-op zoom returns the input.
 */
export function zoomAtPoint(
  d: Dims,
  view: ViewTransform,
  px: number,
  py: number,
  nextZoom: number,
): ViewTransform {
  const z1 = clampZoom(nextZoom);
  if (z1 === view.zoom) return clampPan(d, view);
  const ratio = z1 / view.zoom;
  return clampPan(d, {
    zoom: z1,
    panX: px - (px - view.panX) * ratio,
    panY: py - (py - view.panY) * ratio,
  });
}

/** Zoom toward the surface centre — for the toolbar +/− buttons (no cursor anchor). */
export function zoomToCenter(d: Dims, view: ViewTransform, nextZoom: number): ViewTransform {
  return zoomAtPoint(d, view, d.surfaceW / 2, d.surfaceH / 2, nextZoom);
}

/** Apply one Ctrl+wheel notch of zoom toward `(px, py)`; `deltaY < 0` (scroll up) zooms IN. */
export function zoomByWheel(
  d: Dims,
  view: ViewTransform,
  px: number,
  py: number,
  deltaY: number,
): ViewTransform {
  const next = view.zoom * Math.exp(-deltaY * WHEEL_ZOOM_RATE);
  return zoomAtPoint(d, view, px, py, next);
}

/** Translate the view by a pixel delta (a pan drag), then clamp so no black gap opens. */
export function panBy(d: Dims, view: ViewTransform, dx: number, dy: number): ViewTransform {
  return clampPan(d, { zoom: view.zoom, panX: view.panX + dx, panY: view.panY + dy });
}

/**
 * The zoom at which one desktop pixel maps to one surface pixel ("1:1" / actual size). Native scale is
 * `base * zoom`, so native (=1) needs `zoom = 1/base`, clamped into the legal range. When the desktop
 * is smaller than the surface (`base > 1`) this clamps to fit — you already see every pixel.
 */
export function actualZoom(d: Dims): number {
  const b = baseFit(d);
  if (!b) return MIN_ZOOM;
  return clampZoom(1 / b.base);
}

/** Native (1:1)-relative on-screen scale: surface px per desktop px = `base * zoom`. */
export function displayScale(d: Dims, view: ViewTransform): number {
  const b = baseFit(d);
  if (!b) return view.zoom;
  return b.base * view.zoom;
}

/** Human-facing zoom readout, native-relative (1:1 reads "100%"). */
export function displayScalePct(d: Dims, view: ViewTransform): number {
  return Math.round(displayScale(d, view) * 100);
}

/** Whether the content overflows the surface on either axis, i.e. there is something to pan. */
export function isPannable(d: Dims, view: ViewTransform): boolean {
  const r = contentRect(d, view);
  if (!r) return false;
  return r.cw > d.surfaceW + 0.5 || r.ch > d.surfaceH + 0.5;
}

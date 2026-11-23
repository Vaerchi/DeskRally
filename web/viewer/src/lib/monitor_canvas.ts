/**
 * MonitorCanvas — viewer-side independent monitor viewport rendering.
 *
 * When the parent has validated that the encoder is streaming the full virtual-desktop canvas
 * (all monitors stitched into one fixed coordinate space), each viewer can independently crop to
 * a single monitor by clipping the video element inside a positioned wrapper. No control-plane
 * SelectMonitor is needed; the crop is purely local CSS/math.
 *
 * Coordinate model:
 *   - The virtual desktop has a fixed width × height for the entire session.
 *   - Each monitor occupies a sub-rectangle at (x, y) with non-negative pixel offsets.
 *   - The video stream always contains the full virtual desktop, possibly scaled by the encoder;
 *     the coordinate SPACE is preserved (aspect-correct, same proportions).
 *   - "Normalized" means [0, 1] relative to the full virtual desktop.
 */

/** Full virtual desktop with monitor sub-regions. */
export interface MonitorCanvas {
  /** Full virtual-desktop width in pixels. */
  width: number;
  /** Full virtual-desktop height in pixels. */
  height: number;
  /** Individual monitor sub-regions. x/y are non-negative offsets into the virtual desktop. */
  monitors: { id: number; x: number; y: number; width: number; height: number }[];
}

/**
 * Normalized crop for a single monitor: all values in [0, 1] relative to the full virtual desktop.
 * `left`/`top` are the offsets of the monitor's origin; `width`/`height` are the monitor's fraction.
 */
export interface NormalizedCrop {
  left: number;
  top: number;
  width: number;
  height: number;
}

/**
 * Compute the normalized crop rectangle for one monitor id within a canvas.
 * Returns `null` for unknown ids (caller must fail-safe to uncropped path).
 * Returns `null` for the COMPOSITE_MONITOR_ID sentinel (0xffffffff) — "View all" shows the full canvas.
 */
export function monitorCrop(canvas: MonitorCanvas, monitorId: number): NormalizedCrop | null {
  if (monitorId === 0xffffffff) return null; // composite / "View all"
  if (!(canvas.width > 0 && canvas.height > 0)) return null;
  const m = canvas.monitors.find((m) => m.id === monitorId);
  if (!m) return null;
  if (!(m.width > 0 && m.height > 0)) return null;
  // Non-negative offset guard — per spec x/y must be >= 0; reject invalid data fail-safe.
  if (![m.x,m.y,m.width,m.height,canvas.width,canvas.height].every(Number.isFinite) || m.x < 0 || m.y < 0 || m.x+m.width > canvas.width || m.y+m.height > canvas.height) return null;
  return {
    left: m.x / canvas.width,
    top: m.y / canvas.height,
    width: m.width / canvas.width,
    height: m.height / canvas.height,
  };
}

/**
 * Given a pointer position relative to the CROPPED surface and the crop rectangle,
 * remap it to a normalized position relative to the FULL virtual desktop.
 *
 * This is the inverse of the CSS crop: the pointer arrives in crop-local coordinates
 * (0 = crop left/top, 1 = crop right/bottom) and must be expressed in full-canvas
 * coordinates before being sent to the agent, which always uses the full virtual desktop
 * coordinate space.
 *
 * Returns `null` if crop or position is invalid.
 */
export function remapCroppedPointer(
  /** Normalized x within the cropped region, [0, 1]. */
  nx: number,
  /** Normalized y within the cropped region, [0, 1]. */
  ny: number,
  crop: NormalizedCrop,
): { nx: number; ny: number } | null {
  if (!Number.isFinite(nx) || !Number.isFinite(ny) || nx < 0 || nx > 1 || ny < 0 || ny > 1) return null;
  if (!(crop.width > 0 && crop.height > 0)) return null;
  return {
    nx: crop.left + nx * crop.width,
    ny: crop.top + ny * crop.height,
  };
}

/**
 * The CSS properties for the crop wrapper and the full-video element inside it.
 *
 * Strategy: the wrapper is positioned/sized to show only the monitor's sub-rectangle.
 * The full video sits inside at full virtual-desktop dimensions, offset negatively by the
 * monitor's top-left. `overflow: hidden` on the wrapper clips everything else.
 *
 * All values are percentages of the surface dimensions (which the caller controls).
 *
 * `wrapperStyle` — applied to the clip wrapper (positions within the surface, sets size).
 * `videoOffsetStyle` — applied to the <video> inside the wrapper (positions the full canvas
 *   so the monitor's sub-region is flush with the wrapper's top-left).
 */
export interface CropStyles {
  wrapperStyle: {
    position: "absolute";
    overflow: "hidden";
    /** Left offset within the surface as a percentage string. */
    left: string;
    /** Top offset within the surface as a percentage string. */
    top: string;
    /** Width of the wrapper as a percentage of the surface width. */
    width: string;
    /** Height of the wrapper as a percentage of the surface height. */
    height: string;
  };
  videoOffsetStyle: {
    position: "absolute";
    /** Negative left: shifts the full-canvas video so the monitor's left aligns with the wrapper. */
    left: string;
    /** Negative top: shifts the full-canvas video so the monitor's top aligns with the wrapper. */
    top: string;
    /** Full-canvas width expressed as a ratio of the monitor width = 1/crop.width. */
    width: string;
    /** Full-canvas height expressed as a ratio of the monitor height = 1/crop.height. */
    height: string;
  };
}

/**
 * Compute CSS styles for crop wrapper + video positioning.
 *
 * The wrapper fills the logical area the monitor should occupy inside the surface.
 * When the caller wants the crop to fill the ENTIRE surface (the typical per-monitor viewer),
 * pass `fillSurface: true` — wrapper covers 0 0 100% 100%, and the video is shifted/sized so
 * the monitor's region fills exactly that area. This is the "independent monitor crop" mode.
 *
 * When `fillSurface` is false the wrapper is positioned proportionally (for "View all with
 * overlay" composites — not the primary use case but kept for completeness).
 */
export function cropStyles(crop: NormalizedCrop, fillSurface: boolean): CropStyles {
  if (fillSurface) {
    // Wrapper covers the whole surface. The video is shifted so the monitor's sub-region fills it.
    // video left = -(crop.left / crop.width) * 100%  of the wrapper width
    // video top  = -(crop.top  / crop.height) * 100% of the wrapper height
    // video width  = (1 / crop.width)  * 100%
    // video height = (1 / crop.height) * 100%
    const vLeft = -(crop.left / crop.width) * 100;
    const vTop = -(crop.top / crop.height) * 100;
    const vW = (1 / crop.width) * 100;
    const vH = (1 / crop.height) * 100;
    return {
      wrapperStyle: {
        position: "absolute",
        overflow: "hidden",
        left: "0%",
        top: "0%",
        width: "100%",
        height: "100%",
      },
      videoOffsetStyle: {
        position: "absolute",
        left: `${vLeft}%`,
        top: `${vTop}%`,
        width: `${vW}%`,
        height: `${vH}%`,
      },
    };
  }
  // Proportional placement: wrapper is at the monitor's normalized position.
  const vLeft = -(crop.left / crop.width) * 100;
  const vTop = -(crop.top / crop.height) * 100;
  const vW = (1 / crop.width) * 100;
  const vH = (1 / crop.height) * 100;
  return {
    wrapperStyle: {
      position: "absolute",
      overflow: "hidden",
      left: `${crop.left * 100}%`,
      top: `${crop.top * 100}%`,
      width: `${crop.width * 100}%`,
      height: `${crop.height * 100}%`,
    },
    videoOffsetStyle: {
      position: "absolute",
      left: `${vLeft}%`,
      top: `${vTop}%`,
      width: `${vW}%`,
      height: `${vH}%`,
    },
  };
}

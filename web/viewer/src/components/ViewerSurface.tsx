import type { RecoveryNotice } from "../lib/session_recovery";
/**
 * The remote desktop itself — the video, its transform, and every pointer/touch surface — split out
 * of `Viewer` so it can be mounted into a SEPARATE WINDOW without the toolbar coming with it.
 *
 * It is a plain presentational component on purpose: every piece of state it needs arrives as a
 * prop, and every gesture leaves as a callback. That is what lets `Viewer` render it inline in the
 * console, or render the identical element into its own React root inside a pop-out window, without
 * either copy owning state the other cannot see.
 *
 * THE REFS ARE CALLBACKS, NOT `RefObject`s. When this component remounts in another document the
 * browser creates NEW `<video>` and surface elements; a `useRef` handed down would silently start
 * pointing at a detached node, and the effects that attach `srcObject`, the ResizeObserver and the
 * non-passive wheel listener would all still be bound to the old one. A callback lets the parent
 * notice the element CHANGED and re-run them. See `elEpoch` in Viewer.
 */
import { useCallback, useRef, type CSSProperties, type ReactNode } from "react";
import type { CropStyles } from "../lib/monitor_canvas";

export interface ViewerSurfaceProps {
  /**
   * When present, the video is rendered inside a positioned crop wrapper so only the designated
   * monitor's region is visible. The crop is CSS-only and local to this viewer instance; it does
   * not change the underlying stream or send any control messages. The wrapper rectangle already includes zoom/pan from the shared viewport math, so the mapping math in Viewer uses the CROPPED surface dimensions.
   *
   * Absent → uncropped path: the full video fills the surface exactly as before.
   */
  cropStyles?: CropStyles | null;
  /** Receives the surface element on mount, `null` on unmount. */
  onSurfaceEl: (el: HTMLDivElement | null, previous: HTMLDivElement | null) => void;
  /** Receives the video element on mount, `null` on unmount. */
  onVideoEl: (el: HTMLVideoElement | null, previous: HTMLVideoElement | null) => void;
  /** Pan mode: changes the cursor and means drags move the view instead of the remote pointer. */
  panning: boolean;
  /** Zoom/pan transform, from the same view state the pointer mapping uses. */
  transform: string;
  /** Whether guest audio is audible — the operator's click is what permits playback. */
  audioOn: boolean;
  /** Present once media is negotiated; absent shows the placeholder instead. */
  hasStream: boolean;
  /** Live session vs local preview, which changes what the placeholder should say. */
  live: boolean;
  recoveryNotice?: RecoveryNotice | null;
  onReconnect?: () => void;
  onMouseMove: (e: React.MouseEvent) => void;
  onMouseDown: (e: React.MouseEvent) => void;
  onTouchStart: (e: React.TouchEvent) => void;
  onTouchMove: (e: React.TouchEvent) => void;
  onTouchEnd: (e: React.TouchEvent) => void;
  onTouchCancel: (e: React.TouchEvent) => void;
  /** Drawn inside the surface above the video (the trackpad cursor and its controls). It must stop its own touch/mouse events from reaching the surface. */
  overlay?: ReactNode;
}

export function ViewerSurface({
  onSurfaceEl,
  onVideoEl,
  panning,
  transform,
  audioOn,
  hasStream,
  live,
  recoveryNotice,
  onReconnect,
  onMouseMove,
  onMouseDown,
  onTouchStart,
  onTouchMove,
  onTouchEnd,
  onTouchCancel,
  overlay,
  cropStyles: cropStylesProp,
}: ViewerSurfaceProps) {
  // Separate React roots can finish detaching in a different order from mounting.
  // Identify the node being removed so an old pop-out cannot clear the new tab's refs.
  const surfaceNode = useRef<HTMLDivElement | null>(null);
  const videoNode = useRef<HTMLVideoElement | null>(null);
  const setSurface = useCallback((el: HTMLDivElement | null) => {
    const previous = surfaceNode.current;
    surfaceNode.current = el;
    onSurfaceEl(el, previous);
  }, [onSurfaceEl]);
  const setVideo = useCallback((el: HTMLVideoElement | null) => {
    const previous = videoNode.current;
    videoNode.current = el;
    onVideoEl(el, previous);
  }, [onVideoEl]);
  // Canvas wrapper coordinates already include zoom/pan from contentRect. Applying the
  // transform again here would double it. The uncropped path keeps its existing transform.
  const wrapperTransformStyle: CSSProperties = cropStylesProp
    ? { ...cropStylesProp.wrapperStyle }
    : {};
  const videoUncropped: CSSProperties = cropStylesProp
    ? {}
    : { transform, transformOrigin: "0 0" };

  return (
    <div
      ref={setSurface}
      className={`viewer__surface${panning ? " viewer__surface--pan" : ""}`}
      data-testid="viewer-surface"
      tabIndex={0}
      onMouseMove={recoveryNotice ? undefined : onMouseMove}
      onMouseDown={recoveryNotice ? undefined : onMouseDown}
      onTouchStart={recoveryNotice ? undefined : onTouchStart}
      onTouchMove={recoveryNotice ? undefined : onTouchMove}
      onTouchEnd={recoveryNotice ? undefined : onTouchEnd}
      onTouchCancel={recoveryNotice ? undefined : onTouchCancel}
      onContextMenu={(e) => e.preventDefault()}
    >
      {cropStylesProp ? (
        // Canvas/crop mode: a positioned wrapper clips the video to the selected monitor.
        // The zoom+pan transform is on the wrapper so pointer mapping uses cropped dimensions.
        <div style={wrapperTransformStyle} data-testid="viewer-crop-wrapper">
          <video
            ref={setVideo}
            className="viewer__video"
            style={{...cropStylesProp.videoOffsetStyle, objectFit: "fill", maxWidth: "none", maxHeight: "none"} as CSSProperties}
            autoPlay
            playsInline
            muted={!audioOn}
          />
        </div>
      ) : (
        <video
          ref={setVideo}
          className="viewer__video"
          // Base layer is `object-fit: contain` (see index.css); the transform applies zoom/pan on top
          // from the SAME view state the pointer mapping uses (lib/viewport).
          style={videoUncropped}
          autoPlay
          playsInline
          // Not a constant: the operator's click is what makes audible playback permitted.
          muted={!audioOn}
        />
      )}
      {recoveryNotice && (
        <div className="viewer__recovery" role="alert" data-testid="viewer-recovery">
          <strong>{recoveryNotice.message}</strong>
          <p>The displayed image may be out of date. Remote input is paused.</p>
          {onReconnect && <button type="button" data-testid="viewer-reconnect" onClick={onReconnect}>Reconnect</button>}
        </div>
      )}
      {!hasStream && (
        <div className="viewer__placeholder">
          <p>No video stream</p>
          <p className="viewer__hint">
            {live
              ? "Waiting for the agent's video track…"
              : "Preview mode — input events are captured and logged, not sent."}
          </p>
        </div>
      )}
      {overlay}
    </div>
  );
}

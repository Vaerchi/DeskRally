/**
 * Plays one central recording (docs/63 D7): the playlist is a list of per-segment WebM files served by the
 * same-origin, cookie-authenticated stream route; a <video> plays one and, when it ends, the next (segments can
 * differ in resolution, so they are separate files rather than one stream). Loading the playlist is what the server
 * audits as "playback started", so it happens only when the viewer opens the player.
 *
 * Integrity is shown beside the video: the provenance label (with the caveat that neither label is independent
 * capture verification), truncation, dropped frames and the per-segment digests. The evidence download is a plain
 * same-origin link (the server streams a ZIP and audits every download).
 */

import { useEffect, useRef, useState } from "react";
import { ConsoleApiError, type ConsoleApi } from "../lib/console_api";
import {
  PROVENANCE_CAVEAT,
  canDownloadEvidence,
  downloadUrl,
  formatBytes,
  formatDurationMs,
  provenanceView,
  recordingErrorMessage,
  recordingFlags,
  recordingStatus,
  segmentStreamUrl,
  type RecordingDetail,
  type RecordingPlaylist,
} from "../lib/recordings";

export interface RecordingPlayerProps {
  api: ConsoleApi;
  recordingId: string;
  onClose: () => void;
}

function failureText(e: unknown): string {
  if (e instanceof ConsoleApiError) return recordingErrorMessage(e.status, e.code);
  return e instanceof Error ? e.message : String(e);
}

interface LoadOutcome {
  detail: RecordingDetail | null;
  playlist: RecordingPlaylist | null;
  error: string | null;
}

/**
 * The detail (state, integrity) and the playlist are independent: an expired recording has a detail and no
 * playlist (410), and the viewer should see WHY rather than a bare error. The playlist is fetched only for a
 * ready recording.
 */
async function loadRecording(api: ConsoleApi, id: string): Promise<LoadOutcome> {
  let detail: RecordingDetail;
  try {
    detail = await api.getRecording(id);
  } catch (e) {
    return { detail: null, playlist: null, error: failureText(e) };
  }
  if (detail.state !== "playback_ready") {
    const s = recordingStatus(detail.state);
    const error = detail.state === "expired" || detail.state === "deleted" || detail.state === "lost"
      ? recordingErrorMessage(410, detail.state)
      : `${s.label}. ${s.detail}`.trim();
    return { detail, playlist: null, error };
  }
  try {
    return { detail, playlist: await api.getRecordingPlaylist(id), error: null };
  } catch (e) {
    return { detail, playlist: null, error: failureText(e) };
  }
}

export function RecordingPlayer({ api, recordingId, onClose }: RecordingPlayerProps) {
  const [detail, setDetail] = useState<RecordingDetail | null>(null);
  const [playlist, setPlaylist] = useState<RecordingPlaylist | null>(null);
  const [index, setIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [finished, setFinished] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);

  // One load per recording, shared by every effect run for it: loading the playlist is what the server audits as
  // "playback started", so a re-run of the effect (React StrictMode in development) must not fetch it twice.
  const loadRef = useRef<{ id: string; api: ConsoleApi; done: Promise<LoadOutcome> } | null>(null);

  useEffect(() => {
    let cancelled = false;
    setDetail(null); setPlaylist(null); setIndex(0); setError(null); setFinished(false); setLoading(true);
    if (loadRef.current === null || loadRef.current.id !== recordingId || loadRef.current.api !== api) {
      loadRef.current = { id: recordingId, api, done: loadRecording(api, recordingId) };
    }
    void loadRef.current.done.then((o) => {
      if (cancelled) return;
      setDetail(o.detail);
      setPlaylist(o.playlist);
      setError(o.error);
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, [api, recordingId]);

  const item = playlist?.segments[index];
  const src = playlist && item ? segmentStreamUrl(api.base, recordingId, item) : null;

  const onEnded = () => {
    if (playlist && index + 1 < playlist.segments.length) setIndex(index + 1);
    else setFinished(true);
  };

  // A <video> reports only "it failed". Ask the same URL for one byte to learn WHY (403, 410, 503 ...).
  const onVideoError = async () => {
    if (src === null) return;
    try {
      const res = await fetch(src, { headers: { Range: "bytes=0-0" }, credentials: "include", cache: "no-store" });
      if (res.ok) {
        setError(`This browser could not play segment ${index + 1}.`);
        return;
      }
      let code = "";
      try { code = String(((await res.json()) as { error?: unknown }).error ?? ""); } catch { /* not JSON */ }
      setError(recordingErrorMessage(res.status, code));
    } catch {
      setError("The recording could not be reached. Check your connection and try again.");
    }
  };

  const status = detail ? recordingStatus(detail.state) : null;
  const prov = detail ? provenanceView(detail.provenance) : playlist ? provenanceView(playlist.provenance) : null;
  const flags = detail ? recordingFlags(detail) : playlist ? recordingFlags(playlist) : [];

  return (
    <section className="panel__section" data-testid="recording-player" aria-label="Recording player">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Recording</span>
        <span className="panel__mono">{recordingId}</span>
        {status && <span className="panel__badge" data-tone={status.tone} data-testid="recording-player-status">{status.label}</span>}
        {detail && canDownloadEvidence(detail.state) && (
          <a className="panel__action" href={downloadUrl(api.base, recordingId)} download data-testid="recording-download">
            Download evidence (ZIP)
          </a>
        )}
        <button className="panel__action" type="button" onClick={onClose} data-testid="recording-player-close">Close</button>
      </div>

      {loading && <p className="panel__muted" data-testid="recording-player-loading">Loading…</p>}
      {error && <p className="panel__toolbar-error" role="alert" data-testid="recording-player-error">{error}</p>}

      {src !== null && playlist && item && (
        <>
          <video
            ref={videoRef}
            key={recordingId}
            src={src}
            controls
            autoPlay
            playsInline
            preload="metadata"
            onEnded={onEnded}
            onError={() => void onVideoError()}
            style={{ maxWidth: "100%", background: "#000" }}
            data-testid="recording-video"
            data-segment={index}
          />
          <p className="panel__muted" data-testid="recording-segment-position">
            Segment {index + 1} of {playlist.segments.length} · {item.width}×{item.height} · starts at {formatDurationMs(item.start_ms)} of {formatDurationMs(playlist.total_duration_ms)}
            {finished ? " · finished" : ""}
          </p>
          {playlist.segments.length > 1 && (
            <div role="group" aria-label="Segments">
              {playlist.segments.map((s, i) => (
                <button key={s.index} type="button" className="panel__action" aria-pressed={i === index}
                  onClick={() => { setIndex(i); setFinished(false); }} data-testid={`recording-segment-${i}`}>
                  {i + 1}
                </button>
              ))}
            </div>
          )}
        </>
      )}

      {(detail || playlist) && (
        <div data-testid="recording-integrity">
          {prov && (
            <p>
              <span title={prov.tooltip} data-testid="recording-player-provenance">{prov.label}</span>
              <span className="panel__muted"> — {PROVENANCE_CAVEAT}</span>
            </p>
          )}
          {flags.length > 0 && (
            <p className="panel__toolbar-error" data-testid="recording-player-flags">
              {flags.join(" · ")}. {detail?.truncated ? "The recording stopped early; what follows the cut was not captured." : ""}
            </p>
          )}
          {flags.length === 0 && detail && (
            <p className="panel__muted" data-testid="recording-player-complete">No truncation or dropped frames were reported.</p>
          )}
          {detail && (
            <p className="panel__muted">
              {detail.segment_count} segment{detail.segment_count === 1 ? "" : "s"} · {formatBytes(detail.declared_bytes)}
              {detail.frames != null ? ` · ${detail.frames} frames` : ""}
            </p>
          )}
          {detail && detail.segments.length > 0 && (
            <details>
              <summary>Segment digests (SHA-256 of the original files)</summary>
              <ul>
                {detail.segments.map((s) => (
                  <li key={s.index} className="panel__mono" data-testid={`recording-digest-${s.index}`}>{s.index + 1}: {s.sha256}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </section>
  );
}

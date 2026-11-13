/**
 * The Recordings area (docs/63 D6): completed central recordings, newest first. Offered only to a principal the
 * server lets list them (view_recordings; see App's probe) and every request is authorized again by the server.
 *
 * The recordings API names only ids, so the session (technician, start, end) and machine names are joined from
 * the session and machine lists, best effort. Provenance wording comes from lib/recordings (C4), with a tooltip
 * that says neither label is independent capture verification.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { formatIsoUtc } from "../backstage/panels";
import { ConsoleApiError, type ConsoleApi } from "../lib/console_api";
import {
  downloadUrl,
  recordingErrorMessage,
  recordingRows,
  type RecordingListItem,
} from "../lib/recordings";
import { RecordingPlayer } from "./RecordingPlayer";
import { RecordingsNotBackedUpNotice } from "./RecordingsNotBackedUpNotice";

const PAGE = 50;

export function RecordingsPanel({ api, initialRecordingId }: { api: ConsoleApi; initialRecordingId?: string | null }) {
  const [items, setItems] = useState<RecordingListItem[]>([]);
  const [cursor, setCursor] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [playing, setPlaying] = useState<string | null>(initialRecordingId ?? null);
  // Arriving from a session-history row opens that recording even when the panel is already mounted.
  useEffect(() => {
    if (initialRecordingId) setPlaying(initialRecordingId);
  }, [initialRecordingId]);
  const seq = useRef(0);

  const load = useCallback(async (more: boolean, from: string) => {
    const id = ++seq.current;
    setBusy(true);
    setError(null);
    try {
      const page = await api.listRecordings({ limit: PAGE, cursor: more ? from : undefined });
      if (id !== seq.current) return;
      setItems((cur) => (more ? [...cur, ...page.recordings] : page.recordings));
      setCursor(page.next_cursor);
      setLoaded(true);
    } catch (e) {
      if (id !== seq.current) return;
      setError(e instanceof ConsoleApiError ? recordingErrorMessage(e.status, e.code) : e instanceof Error ? e.message : String(e));
    } finally {
      if (id === seq.current) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    void load(false, "");
    return () => { seq.current++; };
  }, [api, load]);

  const rows = recordingRows(items);

  return (
    <section className="panel" data-testid="recordings-panel">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Recordings</span>
        <button className="panel__action" type="button" onClick={() => void load(false, "")} disabled={busy} data-testid="recordings-refresh">
          {busy ? "Loading…" : "Refresh"}
        </button>
        <span className="panel__toolbar-note">
          Stored on the server only when the organization has turned storage on (Security area). Neither provenance label is independent capture verification.
        </span>
        <RecordingsNotBackedUpNotice testId="recordings-not-backed-up" />
        {error && <span className="panel__toolbar-error" role="alert" data-testid="recordings-error">{error}</span>}
      </div>

      {playing !== null && <RecordingPlayer api={api} recordingId={playing} onClose={() => setPlaying(null)} />}

      <table className="panel__table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Machine</th>
            <th>Technician</th>
            <th>Session started (UTC)</th>
            <th>Session ended (UTC)</th>
            <th>Size</th>
            <th>Provenance</th>
            <th>Integrity</th>
            <th className="panel__col--action">Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={9} data-testid="recordings-empty">
                {busy ? "Loading…" : error ? "Could not load recordings." : loaded ? (cursor !== "" ? "Nothing in this stretch is visible to you. Load more." : "No recordings. Nothing is stored centrally unless the organization turns storage on.") : ""}
              </td>
            </tr>
          )}
          {rows.map((r) => (
            <tr key={r.item.id} data-testid={`recording-row-${r.item.id}`}>
              <td>
                <span className="panel__badge" data-tone={r.status.tone} title={r.status.detail} data-testid={`recording-status-${r.item.id}`}>
                  {r.status.label}
                </span>
                {r.status.tone === "bad" && r.status.detail && r.item.state === "lost" && (
                  <div className="panel__note" data-testid={`recording-lost-detail-${r.item.id}`}>{r.status.detail}</div>
                )}
              </td>
              <td className="panel__name">{r.machine}</td>
              <td className="panel__mono">{r.technician}</td>
              <td className="panel__mono">{r.started ? formatIsoUtc(r.started) : "—"}</td>
              <td className="panel__mono">{r.ended ? formatIsoUtc(r.ended) : "—"}</td>
              <td>{r.size}</td>
              <td>
                <span title={r.provenance.tooltip} data-testid={`recording-provenance-${r.item.id}`}>{r.provenance.label}</span>
              </td>
              <td data-testid={`recording-flags-${r.item.id}`}>
                {r.flags.length === 0 ? "—" : r.flags.map((f) => (
                  <span key={f} className="panel__badge" data-tone="bad">{f}</span>
                ))}
              </td>
              <td className="panel__col--action">
                {r.canPlay && (
                  <button className="panel__action" type="button" onClick={() => setPlaying(r.item.id)} data-testid={`recording-play-${r.item.id}`}>
                    Play
                  </button>
                )}
                {r.canDownload && (
                  <a className="panel__action" href={downloadUrl(api.base, r.item.id)} download data-testid={`recording-evidence-${r.item.id}`}>
                    Evidence ZIP
                  </a>
                )}
                {!r.canPlay && !r.canDownload && (
                  <button className="panel__action" type="button" onClick={() => setPlaying(r.item.id)} data-testid={`recording-details-${r.item.id}`}>
                    Details
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {cursor !== "" && (
        <button className="panel__action" type="button" onClick={() => void load(true, cursor)} disabled={busy} data-testid="recordings-more">
          Load more
        </button>
      )}
    </section>
  );
}

import { useToolbarMenuVisible } from "./ToolbarMenu";
import { useCallback, useEffect, useState } from "react";
import { extractDiagnostics, type DiagnosticSnapshot } from "../lib/connection_diagnostics";
import type { ConnectionState } from "../lib";

const POLL_INTERVAL_MS = 2000;

interface Props {
  /** Stable callback wrapping transport.getStats(). Must not change identity across polls. */
  getStats: () => Promise<RTCStatsReport | undefined>;
  connectionState: ConnectionState;
  stream: MediaStream | null;
  /**
   * Changes when the session changes (e.g. DeviceId string). Causes stale results from a
   * prior session to be discarded before the first poll of the new session completes.
   */
  sessionKey: string;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function ConnectionDiagnostics({ getStats, connectionState, stream, sessionKey }: Props) {
  const menuVisible = useToolbarMenuVisible();
  const [expanded, setExpanded] = useState(false);
  const [snap, setSnap] = useState<DiagnosticSnapshot | null>(null);
  const [failed, setFailed] = useState(false);
  // The parent remounts this component for every connection generation. Cleanup
  // also invalidates pending reads when the disclosure closes or stream changes.
  useEffect(() => {
    if (!menuVisible) return;
    setSnap(null);
    setFailed(false);
    if (!expanded) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const report = await getStats();
        if (!cancelled) { setSnap(extractDiagnostics(report, stream)); setFailed(false); }
      } catch {
        if (!cancelled) { setSnap(null); setFailed(true); }
      } finally {
        if (!cancelled) timer = setTimeout(() => { void poll(); }, POLL_INTERVAL_MS);
      }
    };
    void poll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [expanded, getStats, stream, sessionKey, menuVisible]);

  const handleToggle = useCallback((e: React.SyntheticEvent<HTMLDetailsElement>) => {
    setExpanded((e.currentTarget as HTMLDetailsElement).open);
  }, []);

  const stateLabel: Record<ConnectionState, string> = {
    idle: "Idle",
    signaling: "Authorizing connection…",
    connecting: "Connecting…",
    connected: "Connected",
    disconnected: "Disconnected",
    failed: "Failed",
  };

  return (
    <details
      className="conn-diag"
      onToggle={handleToggle}
      style={{ fontSize: "0.8em", userSelect: "text", cursor: "default" }}
    >
      <summary
        style={{ cursor: "pointer", listStyle: "none", display: "inline-flex", alignItems: "center", gap: "0.4em" }}
        aria-label="Connection details"
      >
        <span aria-hidden="true">{expanded ? "▼" : "▶"}</span>
        <span>Connection details</span>
      </summary>
      <div
        role="region"
        aria-label="Connection diagnostic details"
        style={{ paddingTop: "0.4em", paddingLeft: "1em", lineHeight: 1.6 }}
      >
        <div>
          <span>State: </span>
          <span>{stateLabel[connectionState] ?? connectionState}</span>
        </div>
        <div>
          <span>Video track: </span>
          <span>{stream?.getVideoTracks().length ? "present" : "absent"}</span>
        </div>
        {snap?.inbound != null ? (
          <>
            <div>
              <span>Bytes received: </span>
              <span>
                {snap.inbound.bytesReceived != null
                  ? formatBytes(snap.inbound.bytesReceived)
                  : "unavailable"}
              </span>
            </div>
            <div>
              <span>Packets received: </span>
              <span>
                {snap.inbound.packetsReceived != null
                  ? snap.inbound.packetsReceived.toLocaleString()
                  : "unavailable"}
              </span>
            </div>
            <div>
              <span>Frames decoded: </span>
              <span>
                {snap.inbound.framesDecoded != null
                  ? snap.inbound.framesDecoded.toLocaleString()
                  : "unavailable"}
              </span>
            </div>
            {snap.inbound.codec?.mimeShortName != null && (
              <div>
                <span>Codec: </span>
                <span>{snap.inbound.codec.mimeShortName}</span>
              </div>
            )}
          </>
        ) : expanded && snap !== null ? (
          <div>Inbound video stats: unavailable</div>
        ) : null}
        {snap === null && expanded && (
          <div style={{ color: "inherit", opacity: 0.6 }}>{failed ? "Statistics unavailable; retrying…" : "Collecting…"}</div>
        )}
      </div>
    </details>
  );
}

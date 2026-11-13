/**
 * Pure stat extraction for the ConnectionDiagnostics component.
 *
 * Reads a browser RTCStatsReport and extracts ONLY safe, non-identifying fields
 * from the first inbound-rtp video entry. No IPs, no candidates, no SDP, no
 * user identifiers. Missing or non-finite values are returned as `undefined`
 * ("unavailable"), never coerced to zero.
 */

/** Safe subset of codec info — only the codec MIME type short name. */
export interface VideoCodecInfo {
  /** e.g. "VP9", "H264", "AV1". Absent when not reported or not an allowlisted type. */
  mimeShortName?: string;
}

export interface VideoInboundStats {
  bytesReceived?: number;
  packetsReceived?: number;
  framesDecoded?: number;
  codec?: VideoCodecInfo;
}

export interface DiagnosticSnapshot {
  /** True when the MediaStream has at least one video track. */
  videoTrackPresent: boolean;
  /** Inbound-rtp video stats from getStats(). Absent when no video entry found. */
  inbound?: VideoInboundStats;
}

/** Codec MIME types we are willing to show. Anything else is suppressed. */
const ALLOWED_VIDEO_CODECS = new Set(["video/vp8", "video/vp9", "video/av1", "video/h264", "video/h265"]);

function safeUint(v: unknown): number | undefined {
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0) return undefined;
  return Math.floor(v);
}

function extractCodecName(report: RTCStatsReport, codecId: unknown): VideoCodecInfo | undefined {
  if (typeof codecId !== "string") return undefined;
  try {
    const entry = report.get(codecId);
    if (!entry || typeof entry !== "object") return undefined;
    const mime = (entry as Record<string, unknown>)["mimeType"];
    if (typeof mime !== "string") return undefined;
    const lower = mime.toLowerCase();
    if (!ALLOWED_VIDEO_CODECS.has(lower)) return undefined;
    const slash = lower.lastIndexOf("/");
    return { mimeShortName: lower.slice(slash + 1).toUpperCase() };
  } catch {
    return undefined;
  }
}

/**
 * Extract a DiagnosticSnapshot from a live RTCStatsReport and MediaStream.
 *
 * Safe to call with `undefined` report (returns minimal snapshot).
 * Never throws — all stat reads are guarded.
 */
export function extractDiagnostics(
  report: RTCStatsReport | undefined,
  stream: MediaStream | null,
): DiagnosticSnapshot {
  const videoTrackPresent =
    stream != null && stream.getVideoTracks().length > 0;

  if (!report) {
    return { videoTrackPresent };
  }

  // Find the first inbound-rtp entry for video.
  let videoEntry: Record<string, unknown> | null = null;
  try {
    report.forEach((entry: unknown) => {
      if (videoEntry) return;
      if (
        entry != null &&
        typeof entry === "object" &&
        (entry as Record<string, unknown>)["type"] === "inbound-rtp" &&
        (entry as Record<string, unknown>)["kind"] === "video"
      ) {
        videoEntry = entry as Record<string, unknown>;
      }
    });
  } catch {
    return { videoTrackPresent };
  }

  if (!videoEntry) {
    return { videoTrackPresent };
  }

  const inbound: VideoInboundStats = {
    bytesReceived: safeUint(videoEntry["bytesReceived"]),
    packetsReceived: safeUint(videoEntry["packetsReceived"]),
    framesDecoded: safeUint(videoEntry["framesDecoded"]),
    codec: extractCodecName(report, videoEntry["codecId"]),
  };

  return { videoTrackPresent, inbound };
}

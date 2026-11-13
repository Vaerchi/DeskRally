/** Shared scheduler and export shape; outputHead is retained untrusted text. */
export type BulkRowState =
  | "queued"
  | "connecting"
  | "running"
  | "done"
  | "failed"
  | "unknown"
  | "skipped"
  | "cancelled";

/** The retained summary of a run; absent fields export as empty cells. */
export interface BulkRowOutcome {
  exitCode?: number;
  reason?: string;
  outputHead?: string;
  agentTruncated?: boolean;
  consoleTruncated?: boolean;
}

export interface BulkRow {
  deviceId: string;
  machineName: string;
  alias?: string;
  state: BulkRowState;
  outcome?: BulkRowOutcome;
}

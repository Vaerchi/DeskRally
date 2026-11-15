/**
 * The plain "recordings are not backed up" notice (docs/63 C11). Recordings live on the server's own disk, outside
 * the database backup, so the retention period is a deletion policy and not a durability promise. Shown where a
 * tenant turns recording storage on and in the Recordings area.
 */
import { RECORDINGS_NOT_BACKED_UP } from "../lib/recordings";

export function RecordingsNotBackedUpNotice({ testId }: { testId: string }) {
  return (
    <span className="panel__note" role="note" data-testid={testId}>
      {RECORDINGS_NOT_BACKED_UP}
    </span>
  );
}

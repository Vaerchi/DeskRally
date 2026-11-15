/**
 * "Type clipboard" in the viewer's Input menu (Ed, 2026-10-23): types the technician's clipboard into
 * the remote machine as keystrokes, for places the shared clipboard cannot reach (sign-in screen, UAC,
 * VM consoles, fields that block paste). See lib/type_text for what is typed and how.
 *
 * The technician clicks into the remote field FIRST, then opens Input and presses the button. Typing
 * goes through the viewer's one gated key path (`send`), so view-only, pan mode and the capture switch
 * stop it like any other key; closing the Input panel stops it too.
 */
import { useEffect, useRef, useState } from "react";
import { clipboardForWindow } from "../lib/clipboard";
import type { InputEvent } from "../lib/input";
import { TYPE_CONFIRM_ABOVE, typeBatches, typedLength, typingBatches } from "../lib/type_text";

export function TypeClipboard({ enabled, send }: { enabled: boolean; send: (events: InputEvent[]) => boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const cancelled = useRef(false);
  const [progress, setProgress] = useState<{ sent: number; total: number } | null>(null);
  const [status, setStatus] = useState("");
  useEffect(() => () => { cancelled.current = true; }, []);

  const start = async () => {
    const win = host.current?.ownerDocument.defaultView ?? null;
    let raw: string;
    try {
      // Inside this click, so the browser lets the page read the clipboard.
      raw = await clipboardForWindow(win).readText();
    } catch {
      setStatus("Could not read your clipboard.");
      return;
    }
    const chars = typedLength(raw);
    if (chars === 0) {
      setStatus("Your clipboard has no text to type.");
      return;
    }
    if (chars > TYPE_CONFIRM_ABOVE && !(win?.confirm(`Type ${chars} characters into the remote machine?`) ?? false)) return;
    const batches = typingBatches(raw);
    cancelled.current = false;
    setStatus("");
    setProgress({ sent: 0, total: batches.length });
    const sent = await typeBatches(batches, send, {
      cancelled: () => cancelled.current,
      onProgress: (s, total) => setProgress({ sent: s, total }),
    });
    setProgress(null);
    setStatus(sent === batches.length ? `Typed ${chars} characters.`
      : cancelled.current ? "Stopped." : "Stopped: input is not being sent to the remote machine.");
  };

  return (
    <div ref={host} className="viewer__menupanel-field" data-testid="type-clipboard">
      {progress ? (
        <button type="button" className="viewer__zoombtn" data-testid="type-clipboard-stop"
          onClick={() => { cancelled.current = true; }}>
          Stop typing ({Math.round((progress.sent / Math.max(1, progress.total)) * 100)}%)
        </button>
      ) : (
        <button type="button" className="viewer__zoombtn" data-testid="type-clipboard-start" disabled={!enabled}
          onClick={() => void start()}
          title={enabled
            ? "Click into the field on the remote machine first. Types your clipboard there as keystrokes: works on the sign-in screen, UAC prompts and fields that block paste."
            : "Typing is off: the session is view-only, or input is not being sent."}>
          Type clipboard
        </button>
      )}
      {status && <span className="viewer__qualityhint" data-testid="type-clipboard-status">{status}</span>}
    </div>
  );
}

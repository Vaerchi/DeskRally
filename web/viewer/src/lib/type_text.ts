/**
 * Paste by typing (Ed, 2026-10-23): turn the technician's clipboard text into keystrokes for the
 * remote machine, for the places the shared clipboard cannot reach — the sign-in screen, a UAC
 * prompt, a VM or RDP console, a password field that blocks paste.
 *
 * The agent already types a `Text` event as Unicode keystrokes (`KEYEVENTF_UNICODE`, ≤ 4096 UTF-8
 * bytes per event). Two things it cannot do from a Unicode packet, so this module does them here:
 * - **Line breaks and tabs are real key presses.** A Unicode LF or TAB packet does not press Enter or
 *   Tab in most targets, so `\n` becomes VK_RETURN and `\t` becomes VK_TAB, down then up.
 * - **One character at a time, paced.** A burst of Unicode keystrokes garbles some targets (see
 *   TYPE_CHUNK_CHARS), so each character is its own event and the caller paces them.
 *
 * Other control characters are dropped: typed into a field they do nothing useful, and some (ESC,
 * BS) would act on the remote UI.
 */
import { key, text, type InputEvent } from "./input";

export const VK_RETURN = 0x0d;
export const VK_TAB = 0x09;
/**
 * Characters (code points) per Text event: ONE. The agent injects a Text event as back-to-back
 * `VK_PACKET` keystrokes, and a target that falls behind its input queue (Windows 11 Notepad does)
 * then turns a burst into repeats of the last character and drops: the operator's first production test, and
 * the lab VM with 32-character chunks (every line became one repeated digit) and 8-character bursts
 * (23 of 234 characters lost). One character per event, paced, typed all 234 correctly.
 */
export const TYPE_CHUNK_CHARS = 1;
/**
 * Pause between batches, in ms: about 16 characters a second. Spacing alone typed correctly in the VM
 * at 10 ms, but over the internet a connection stall delivers every event sent during it at once, and a
 * clump of keystrokes garbles Windows 11 Notepad on agents up to 1.3.8 (bursts of 3 were fine, 6
 * slipped, 8 lost 23 of 234 characters). The slower the sending, the fewer characters any one stall can
 * clump together (Ed, 2026-10-24: slower but cleaner, until the agent paces typing itself).
 */
export const TYPE_BATCH_DELAY_MS = 60;
/** Above this many characters the technician is asked to confirm before typing starts. */
export const TYPE_CONFIRM_ABOVE = 1000;

/** Line endings to `\n`, and every control character except `\n` and `\t` removed. */
export function normalizeForTyping(raw: string): string {
  return raw
    .replace(/\r\n?/g, "\n")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "");
}

/**
 * The batches to send, in order: each is one Text event (≤ `chunk` code points, never splitting a
 * surrogate pair) or the down+up of Enter or Tab.
 */
export function typingBatches(raw: string, chunk = TYPE_CHUNK_CHARS): InputEvent[][] {
  const batches: InputEvent[][] = [];
  let run: string[] = [];
  const flush = () => {
    if (run.length) batches.push([text(run.join(""))]);
    run = [];
  };
  for (const ch of Array.from(normalizeForTyping(raw))) {
    if (ch === "\n" || ch === "\t") {
      flush();
      const vk = ch === "\n" ? VK_RETURN : VK_TAB;
      batches.push([key(vk, true), key(vk, false)]);
      continue;
    }
    run.push(ch);
    if (run.length >= chunk) flush();
  }
  flush();
  return batches;
}

/** How many characters the technician will see typed (after normalisation), for the confirm/progress text. */
export function typedLength(raw: string): number {
  return Array.from(normalizeForTyping(raw)).length;
}

/**
 * Send `batches` one at a time, `delayMs` apart, through `send`. Stops early when `cancelled()` turns
 * true or `send` returns false (input went inactive). Reports progress after each batch. Resolves to
 * the number of batches sent.
 */
export async function typeBatches(
  batches: InputEvent[][],
  send: (events: InputEvent[]) => boolean,
  opts: { delayMs?: number; cancelled?: () => boolean; onProgress?: (sent: number, total: number) => void;
    sleep?: (ms: number) => Promise<void> } = {},
): Promise<number> {
  const delay = opts.delayMs ?? TYPE_BATCH_DELAY_MS;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let sent = 0;
  for (const b of batches) {
    if (opts.cancelled?.()) break;
    if (!send(b)) break;
    sent += 1;
    opts.onProgress?.(sent, batches.length);
    if (sent < batches.length) await sleep(delay);
  }
  return sent;
}

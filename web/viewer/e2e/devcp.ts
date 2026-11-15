/**
 * Shared e2e teardown helper.
 *
 * Every browser+control-plane spec spawns a throwaway DEV control plane (and the live specs a signaling
 * server + agent) on the SAME ports — CP_PORT / SIG_PORT (ports.ts) — because the Vite `/cp` proxy
 * target (CONTROL_PLANE_ORIGIN) is fixed, and the specs run SERIALLY (workers:1). A bare `proc.kill()`
 * in `afterAll` returns IMMEDIATELY: the process is only *asked* to die, so a dying previous process can
 * still hold its listening port when the NEXT spec's `beforeAll` spawns its own there and its `tcpUp`
 * probe then connects to the DYING one — 500s and, for the live specs, WebRTC session setup that never
 * completes (a timeout). That is the exact race behind the intermittent `tenant_branding` failures
 * (loops 48/51) and the live-WebRTC timeouts (loop 52) that only surface under full-suite load.
 *
 * `stopProc` kills the process AND waits for it to actually EXIT (bounded, so a stuck child cannot hang
 * teardown), releasing the port before the next spec starts. Use it in every `afterAll` in place of
 * `proc?.kill()`.
 */
import { type ChildProcess } from "node:child_process";

/** Kill `proc` and await its exit (up to `timeoutMs`), so its port is free before the next spec spawns. */
export async function stopProc(proc: ChildProcess | null | undefined, timeoutMs = 5000): Promise<void> {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => proc.once("exit", () => resolve()));
  try {
    proc.kill();
  } catch {
    return; // already gone
  }
  // Bound the wait, and ALWAYS clear the timer — on the normal fast-exit path `exited` wins the race,
  // and an uncleared setTimeout would keep Node's event loop alive for the full timeout after teardown.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const bound = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, timeoutMs);
    timer.unref?.();
  });
  try {
    await Promise.race([exited, bound]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

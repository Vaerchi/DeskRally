import {afterEach,describe,it,expect,vi} from "vitest";
import {SessionRecovery,RecoveryRefused,MediaProgress,withDeadline,RECOVERY_WINDOW_MS,RECOVERED_AFTER_MS} from "./session_recovery";
afterEach(()=>vi.useRealTimers());
describe("session recovery",()=> {
 it("retries transient failures with capped backoff and never expires a healthy connection",async()=> {
  vi.useFakeTimers();const retry=vi.fn().mockRejectedValue(new Error("offline"));const notify=vi.fn();
  const recovery=new SessionRecovery(retry,notify); recovery.enabled=true;
  recovery.connected();await vi.advanceTimersByTimeAsync(86400000);expect(retry).not.toHaveBeenCalled();
  recovery.lost();recovery.lost();await vi.advanceTimersByTimeAsync(1999);expect(retry).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);expect(retry).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(4000);expect(retry).toHaveBeenCalledTimes(2);
  recovery.connected();await vi.advanceTimersByTimeAsync(60000);expect(retry).toHaveBeenCalledTimes(2);
 });
 it("a loss reported while a retry is still settling schedules the next attempt",async()=> {
  // An offline machine's rejection can arrive before handleConnect returns; it must not be dropped.
  vi.useFakeTimers();let resolve!:()=>void;const retry=vi.fn(()=>new Promise<void>(r=>resolve=r));const notify=vi.fn();
  const recovery=new SessionRecovery(retry,notify);recovery.enabled=true;recovery.lost("offline");await vi.advanceTimersByTimeAsync(2000);
  expect(retry).toHaveBeenCalledTimes(1);
  recovery.lost("machine is offline");resolve();await vi.advanceTimersByTimeAsync(0);
  expect(notify).toHaveBeenLastCalledWith({message:"machine is offline. Reconnecting in 4s…",retrying:true});
  await vi.advanceTimersByTimeAsync(4000);expect(retry).toHaveBeenCalledTimes(2);
  // A retry that CONNECTS discards a loss reported before it connected: no spurious extra attempt.
  recovery.lost("late");recovery.connected();resolve();await vi.advanceTimersByTimeAsync(60000);
  expect(retry).toHaveBeenCalledTimes(2);
 });
 it("disconnect cancels retry timers and ignores late failed attempts",async()=> {
  vi.useFakeTimers();let reject!:(e:Error)=>void;const retry=vi.fn(()=>new Promise<void>((_,r)=>reject=r));const notify=vi.fn();
  const recovery=new SessionRecovery(retry,notify);recovery.enabled=true;recovery.lost();await vi.advanceTimersByTimeAsync(2000);
  recovery.cancel();reject(new Error("late"));await vi.advanceTimersByTimeAsync(60000);
  expect(retry).toHaveBeenCalledTimes(1);expect(notify).toHaveBeenLastCalledWith(null);
 });
 // Production 2026-11-09 (session 4c1f4541): recovery gave up from a FAILED RETRY (no transport event followed), so the
 // caller never learned it should end the record it was holding. `stopped` is that signal: once per final stop.
 it("tells the caller once when it stops for good (window or refusal), never on a deliberate cancel",async()=> {
  vi.useFakeTimers();const retry=vi.fn().mockRejectedValue(new Error("offline"));const stopped=vi.fn();
  const recovery=new SessionRecovery(retry,vi.fn(),stopped);recovery.enabled=true;recovery.lost();
  await vi.advanceTimersByTimeAsync(RECOVERY_WINDOW_MS-1);expect(stopped).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(60000);expect(stopped).toHaveBeenCalledTimes(1);
  // Further losses and refusals after the stop are not a second stop.
  recovery.lost();recovery.refuse("again");await vi.advanceTimersByTimeAsync(60000);expect(stopped).toHaveBeenCalledTimes(1);
  // A deliberate cancel (Disconnect, sign-out) is the caller's own teardown, not a stop to report...
  recovery.cancel();expect(stopped).toHaveBeenCalledTimes(1);
  // ...and after it a refusal is a new final stop.
  recovery.enabled=true;recovery.refuse("Administrator ended session");expect(stopped).toHaveBeenCalledTimes(2);
  const refusing=vi.fn();const r2=new SessionRecovery(vi.fn().mockRejectedValue(new RecoveryRefused("denied")),vi.fn(),refusing);
  r2.enabled=true;r2.lost();await vi.advanceTimersByTimeAsync(2000);expect(refusing).toHaveBeenCalledTimes(1);
  r2.cancel();await vi.advanceTimersByTimeAsync(60000);expect(refusing).toHaveBeenCalledTimes(1);
 });
 it("refusals stay visible and cannot be erased by close or connected callbacks",async()=> {
  vi.useFakeTimers();const retry=vi.fn().mockRejectedValue(new RecoveryRefused("Administrator ended session"));const notify=vi.fn();
  const recovery=new SessionRecovery(retry,notify);recovery.enabled=true;recovery.lost();await vi.advanceTimersByTimeAsync(2000);
  recovery.lost();recovery.connected();await vi.advanceTimersByTimeAsync(60000);
  expect(retry).toHaveBeenCalledTimes(1);expect(notify).toHaveBeenLastCalledWith({message:"Administrator ended session",retrying:false});
 });
 it("stops retrying RECOVERY_WINDOW_MS after the first loss and says so; a reconnect re-arms it",async()=> {
  vi.useFakeTimers();const retry=vi.fn().mockRejectedValue(new Error("offline"));const notify=vi.fn();
  const recovery=new SessionRecovery(retry,notify);recovery.enabled=true;
  recovery.lost();await vi.advanceTimersByTimeAsync(RECOVERY_WINDOW_MS - 1);
  const before=retry.mock.calls.length;expect(before).toBeGreaterThan(2);
  await vi.advanceTimersByTimeAsync(3600000);
  // At most the one retry already due inside the window; none after it.
  expect(retry.mock.calls.length).toBeLessThanOrEqual(before + 1);
  expect(notify).toHaveBeenLastCalledWith({message:expect.stringContaining("Automatic reconnect stopped"),retrying:false});
  // A later loss stays refused: only a deliberate reconnect (cancel, then a fresh connect) re-arms.
  recovery.lost();await vi.advanceTimersByTimeAsync(60000);expect(retry.mock.calls.length).toBeLessThanOrEqual(before + 1);
  recovery.cancel();recovery.enabled=true;const n=retry.mock.calls.length;
  recovery.lost();await vi.advanceTimersByTimeAsync(2000);expect(retry).toHaveBeenCalledTimes(n + 1);
 });
 it("a connect inside the window that LASTS resets the outage clock and the backoff",async()=> {
  vi.useFakeTimers();const retry=vi.fn().mockRejectedValue(new Error("offline"));const notify=vi.fn();
  const recovery=new SessionRecovery(retry,notify);recovery.enabled=true;
  recovery.lost();await vi.advanceTimersByTimeAsync(RECOVERY_WINDOW_MS - 10000);recovery.connected();
  await vi.advanceTimersByTimeAsync(RECOVERED_AFTER_MS);
  const n=retry.mock.calls.length;recovery.lost();
  expect(notify).toHaveBeenLastCalledWith({message:"Connection lost. Reconnecting in 2s…",retrying:true});
  await vi.advanceTimersByTimeAsync(2000);expect(retry).toHaveBeenCalledTimes(n + 1);
 });
 it("a connection that fails soon after connecting does not end the outage (2026-11-09 no-video loop)",async()=> {
  // Every attempt reached "connected", then failed the 20 s video-stall check: resetting on "connected"
  // made a fresh session every ~33 s forever. Now the backoff grows and the window still ends it.
  vi.useFakeTimers();const notify=vi.fn();let recovery!:SessionRecovery;
  const retry=vi.fn(async()=>{recovery.connected();setTimeout(()=>recovery.lost("Video stopped responding"),23000);});
  recovery=new SessionRecovery(retry,notify);recovery.enabled=true;
  recovery.connected();await vi.advanceTimersByTimeAsync(23000);recovery.lost("Video stopped responding");
  expect(notify).toHaveBeenLastCalledWith({message:"Video stopped responding. Reconnecting in 2s…",retrying:true});
  await vi.advanceTimersByTimeAsync(2000 + 23000);
  expect(notify).toHaveBeenLastCalledWith({message:"Video stopped responding. Reconnecting in 4s…",retrying:true});
  await vi.advanceTimersByTimeAsync(3600000);
  // Inside the 120 s window only: 2+23, 4+23, 8+23, 16+23 s after the first loss leaves room for at most 4.
  expect(retry.mock.calls.length).toBeLessThanOrEqual(4);
  expect(notify).toHaveBeenLastCalledWith({message:expect.stringContaining("Automatic reconnect stopped"),retrying:false});
 });
 it("bounds a hung request and cleans a late acquired session",async()=> {
  vi.useFakeTimers();let resolve!:(s:string)=>void;const cleanup=vi.fn();
  const pending=withDeadline(new Promise<string>(r=>resolve=r),1000,cleanup);
  const rejection=expect(pending).rejects.toThrow("timed out");await vi.advanceTimersByTimeAsync(1000);await rejection;
  resolve("orphan-session");await Promise.resolve();expect(cleanup).toHaveBeenCalledWith("orphan-session");
 });
});
describe("media progress",()=> {
 const report=(frames:number)=>new Map([["video",{type:"inbound-rtp",kind:"video",framesDecoded:frames}]]) as unknown as RTCStatsReport;
 it("detects a frozen decode counter, even if the connection says connected",()=> {
  const p=new MediaProgress(0);expect(p.stalled(report(10),100)).toBe(false);
  expect(p.stalled(report(10),20100)).toBe(true);
 });
 it("keeps a static desktop connected while frames continue; ignores unsupported counters",()=> {
  const p=new MediaProgress(0);for(let i=0;i<100;i++) expect(p.stalled(report(i),i*3000)).toBe(false);
  expect(p.stalled(new Map() as unknown as RTCStatsReport,999999)).toBe(false);
 });
 it("background mode owes no frames: a hidden idle session never stalls, and the clock restarts on return (2026-11-09)",()=> {
  const p=new MediaProgress(0);expect(p.stalled(report(5),0)).toBe(false);
  // Hidden for five minutes over an idle (or powered-off) screen: the agent sends nothing, by design.
  for(let t=3000;t<=300000;t+=3000) expect(p.stalled(report(5),t,false)).toBe(false);
  // Back in front: the full 20 s counts from the return, not from the last frame minutes ago.
  expect(p.stalled(report(5),319000)).toBe(false);
  expect(p.stalled(report(5),320000)).toBe(true);
 });
});

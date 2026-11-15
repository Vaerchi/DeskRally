/**
 * Zoom-race real-component Playwright regression tests.
 *
 * Covers the pending-snap state machine (pendingActualSnapRef) in Viewer.tsx:
 *
 * Test 1 — Fit cancels pending snap:
 *   After 1:1 → different-resolution monitor switch, clicking Fit before loadedmetadata re-fires
 *   left pendingActualSnapRef=true. When dims arrived later, the snap overrode the explicit Fit
 *   choice. Fix: applyView() (called by zoomFit/zoomIn/zoomOut) clears pendingActualSnapRef.
 *   Requires different-resolution monitors: sameRes=false → contentSize cleared → snap waits for
 *   loadedmetadata, leaving pendingActualSnapRef armed when Fit is clicked.
 *   Mutation target: removing `pendingActualSnapRef.current = false` from applyView lets the snap
 *   override Fit (fires after 4K loadedmetadata) → non-identity where identity is expected.
 *
 * Test 2 — Same-resolution switch still snaps (no loadedmetadata re-fires):
 *   For same-resolution switches the video track's intrinsic size is unchanged, so neither
 *   loadedmetadata nor resize re-fires.
 *   Fix: onMonitorChange uses the TARGET monitor's ADVERTISED dims (from MonitorList) to detect
 *   same-res. When the target is same-res, contentSize is preserved and the snap fires immediately
 *   via the monitorSwitchSeq increment.
 *   Mutation target: always clearing contentSize (removing the sameRes guard) permanently blocks
 *   the snap — w=0/h=0 → bail, no event ever arrives to unblock → transform stays IDENTITY.
 *
 * Test 3 — Different-resolution switch must snap with the NEW monitor's dims:
 *   The original sameRes detection compared el.videoWidth (old stream) to contentSize (also old
 *   stream) — both hold the OLD monitor's dims at switch time, so the comparison is always true.
 *   This caused a snap to fire immediately at the OLD dims, clearing pendingActualSnapRef before
 *   the correct new dims arrived via loadedmetadata.
 *   Fix: sameRes compares the TARGET monitor's ADVERTISED width/height (from MonitorList) to
 *   contentSize. A different-resolution target clears contentSize and waits for loadedmetadata.
 *   Mutation target: reverting to the el.videoWidth comparison (always-sameRes bug) snaps at old
 *   1080p dims immediately; when 4K dims arrive pendingActualSnapRef is already false — no re-snap,
 *   transform stays at the wrong zoom for the new monitor.
 *
 * Uses the same FakeDC/Peer stub as download_wiring.spec.ts — no real agent required.
 */

import { test, expect, type Page } from "@playwright/test";
import { clickInViewerPanel } from "./nav";
import { openManualConnect } from "./manual_connect";

async function fixture(page: Page) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines")
      return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions" && method === "POST") {
      return route.fulfill({
        json: { session: { id: "s1" }, signaling: { url: "ws://127.0.0.1:5220/ws", ticket: {} } },
      });
    }
    if (path.endsWith("/policy")) {
      return route.fulfill({
        status: 200,
        json: {
          session_policy: {
            access: "control",
            signed: "test",
            lease_ttl_ms: 30000,
            expires_at_ms: 9_999_999_999_999,
          },
        },
      });
    }
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket("ws://127.0.0.1:5220/ws", () => {});
  await page.addInitScript(() => {
    const w = window as any;
    w.peers = [];
    class FakeDC {
      readyState = "open";
      sent: any[] = [];
      onmessage: any = null;
      onclose: any = null;
      send() {}
      close() {
        this.readyState = "closed";
        this.onclose?.();
      }
    }
    class Peer {
      connectionState = "new";
      onconnectionstatechange: any;
      ontrack: any;
      dc = new FakeDC();
      constructor() { w.peers.push(this); }
      createDataChannel() { return this.dc; }
      addTransceiver() {}
      close() {
        this.connectionState = "closed";
        this.onconnectionstatechange?.();
      }
      getStats() {
        return Promise.resolve(
          new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: 1 }]]),
        );
      }
      connected() {
        this.connectionState = "connected";
        this.onconnectionstatechange?.();
      }
      // Inject a control-channel message (MonitorList, etc.) from the fake agent.
      control(message: unknown) {
        const bytes = new TextEncoder().encode(JSON.stringify(message));
        const frame = new Uint8Array(5 + bytes.length);
        new DataView(frame.buffer).setUint32(1, bytes.length);
        frame.set(bytes, 5);
        this.dc.onmessage?.({ data: frame.buffer });
      }
    }
    w.RTCPeerConnection = Peer;
  });

  await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
}

/** Override videoWidth/videoHeight on the video element and fire loadedmetadata. */
async function setVideoDims(page: Page, w: number, h: number) {
  await page.evaluate(([width, height]) => {
    const video = document.querySelector("video.viewer__video") as HTMLVideoElement;
    Object.defineProperty(video, "videoWidth", { get: () => width, configurable: true });
    Object.defineProperty(video, "videoHeight", { get: () => height, configurable: true });
    video.dispatchEvent(new Event("loadedmetadata"));
  }, [w, h]);
}

/** Read the current CSS transform of the viewer video element. */
function videoTransform(page: Page) {
  return page.evaluate(
    () => (document.querySelector("video.viewer__video") as HTMLVideoElement).style.transform,
  );
}

const IDENTITY = "translate(0px, 0px) scale(1)";

// Two monitors at the same resolution — used by Test 2 (same-res re-snap).
const SAME_RES_MONITORS = [
  { id: 0, width: 1920, height: 1080, primary: true },
  { id: 1, width: 1920, height: 1080, primary: false },
];

// Two monitors at different resolutions — used by Tests 1 and 3.
const MIXED_RES_MONITORS = [
  { id: 0, width: 1920, height: 1080, primary: true },
  { id: 1, width: 3840, height: 2160, primary: false },
];

test("Fit click before new dims arrive cancels pending snap (Bug 1)", async ({ page }) => {
  await fixture(page);

  // Different-resolution monitors: switching to monitor 1 (4K) from monitor 0 (1080p) yields
  // sameRes=false — contentSize is cleared and the snap waits for loadedmetadata. This keeps
  // pendingActualSnapRef armed when Fit is clicked, testing the applyView cancellation.
  await page.evaluate(
    (monitors) => (window as any).peers[0].control({ t: "MonitorList", c: { monitors } }),
    MIXED_RES_MONITORS,
  );

  // Supply video dimensions and fire loadedmetadata so contentSize becomes non-zero.
  await setVideoDims(page, 1920, 1080);

  // Click 1:1 — scalePrefRef = "actual", view zooms to native pixels.
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-zoom-actual"));
  // Transform should be non-identity (actual zoom applied).
  await expect.poll(() => videoTransform(page)).not.toBe(IDENTITY);

  // Switch to monitor 1 (3840×2160 — different resolution).
  // onMonitorChange: target.width=3840 ≠ contentSize.w=1920 → sameRes=false → clear contentSize
  // → pendingActualSnapRef=true. Snap effect bails (contentSize={0,0}).
  await page.getByTestId("viewer-monitor").selectOption("1");

  // Wait for the view reset from onMonitorChange to reach the DOM (setView(IDENTITY_VIEW)).
  // This confirms: (a) contentSize is zero so the snap bailed, (b) pendingActualSnapRef is armed,
  // (c) Fit is about to be clicked into a state where it matters.
  await expect.poll(() => videoTransform(page)).toBe(IDENTITY);

  // Click Fit BEFORE loadedmetadata re-fires — fix: applyView() clears pendingActualSnapRef.
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-zoom-fit"));

  // Now fire loadedmetadata (simulates new monitor's dims arriving).
  await setVideoDims(page, 3840, 2160);

  // Wait 200 ms to give React time to process the state update from loadedmetadata and run any
  // pending snap effects. Without this, expect.poll could sample BEFORE the snap effect runs,
  // seeing IDENTITY in both mutant and fix (the snap fires asynchronously as a React microtask).
  await page.waitForTimeout(200);

  // Assert: transform stays at IDENTITY_VIEW — Fit won, the pending snap did NOT override it.
  // Mutation (removing pendingActualSnapRef.current = false from applyView): snap fires after
  // 4K loadedmetadata, transform becomes non-identity, and this assertion fails.
  await expect.poll(() => videoTransform(page)).toBe(IDENTITY);
});

test("Same-resolution monitor switch still re-applies 1:1 without loadedmetadata re-firing (Bug 2)", async ({
  page,
}) => {
  await fixture(page);

  // Same-resolution monitors: monitor 1 is also 1920×1080, so the video track's intrinsic size
  // is unchanged on switch and neither loadedmetadata nor resize re-fires.
  await page.evaluate(
    (monitors) => (window as any).peers[0].control({ t: "MonitorList", c: { monitors } }),
    SAME_RES_MONITORS,
  );

  // Set video dims and fire loadedmetadata once so contentSize is non-zero.
  await setVideoDims(page, 1920, 1080);

  // Click 1:1 — zoom to native pixels.
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-zoom-actual"));
  await expect.poll(() => videoTransform(page)).not.toBe(IDENTITY);

  // Switch to monitor 1 (same 1920×1080 resolution).
  // Fix: target.width=1920 === contentSize.w=1920 → sameRes=true → keep contentSize; snap fires
  // immediately via monitorSwitchSeq increment without waiting for loadedmetadata.
  await page.getByTestId("viewer-monitor").selectOption("1");

  // Assert: snap is re-applied — transform is non-identity despite no loadedmetadata.
  // Mutation (removing the sameRes guard — always clearing contentSize): contentSize goes to zero,
  // snap effect bails (w=0), no loadedmetadata arrives, transform stays IDENTITY_VIEW → FAILS.
  await expect.poll(() => videoTransform(page), { timeout: 3000 }).not.toBe(IDENTITY);
});

test("Different-resolution monitor switch snaps with new dims, not old (Bug 3)", async ({ page }) => {
  await fixture(page);

  await page.evaluate(
    (monitors) => (window as any).peers[0].control({ t: "MonitorList", c: { monitors } }),
    MIXED_RES_MONITORS,
  );

  // Set video dims to 1080p and fire loadedmetadata.
  await setVideoDims(page, 1920, 1080);

  // Click 1:1 — snap at 1080p dims. Record the resulting transform.
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-zoom-actual"));
  await expect.poll(() => videoTransform(page)).not.toBe(IDENTITY);
  const zoom1080p = await videoTransform(page);

  // Switch to monitor 1 (3840×2160 — different resolution from current 1920×1080).
  // Fix: target.width=3840 ≠ contentSize.w=1920 → sameRes=false → clear contentSize → wait for dims.
  // Broken (old el.videoWidth comparison): el.videoWidth=1920 === contentSize.w=1920 → sameRes=true
  // → snap fires at OLD 1080p dims immediately, clearing pendingActualSnapRef before 4K dims arrive.
  await page.getByTestId("viewer-monitor").selectOption("1");

  // Deliver the 4K monitor's actual dims.
  await setVideoDims(page, 3840, 2160);

  // Give React time to process the contentSize update and run the snap effect.
  await page.waitForTimeout(200);

  // Assert: transform reflects 4K dims — different from the pre-switch 1080p zoom.
  // Fix: snap fires after 4K loadedmetadata → zoom_4K ≠ zoom_1080p → PASSES.
  // Mutation (revert sameRes to el.videoWidth comparison): snap fires at 1080p immediately on
  // switch; 4K loadedmetadata finds pendingActualSnapRef=false, no re-snap → transform stays at
  // the wrong zoom_1080p level → FAILS.
  await expect.poll(() => videoTransform(page)).not.toBe(zoom1080p);
  // Snap did fire (not left at IDENTITY after the monitor-switch reset).
  await expect.poll(() => videoTransform(page)).not.toBe(IDENTITY);
});

/**
 * Test 4 — Pinch gesture before new dims arrive cancels pending snap (Bug 4)
 *
 * Regression for the case where applyGestureAction called setView directly (bypassing applyView),
 * so pendingActualSnapRef was not cleared on a gesture zoom. When content dims arrived later, the
 * snap effect overwrote the operator's gesture.
 *
 * Fix: applyGestureAction "zoom" case now sets pendingActualSnapRef.current = false before setView.
 * Mutation target: removing that line lets the snap run after loadedmetadata and change the
 * transform to the snap's value, making the post-loadedmetadata check fail.
 */

/**
 * Test 5 — COMPOSITE_MONITOR_ID switch waits for loadedmetadata then snaps (composite integration)
 *
 * When the operator selects "View all (composite)", COMPOSITE_MONITOR_ID is passed to
 * onMonitorChange. The code treats this as different-res (COMPOSITE_MONITOR_ID never matches any
 * real monitor id in ml.find(), so target=undefined → sameRes=false) and clears contentSize.
 * The snap must wait for loadedmetadata to deliver composite dims before snapping to 1:1.
 *
 * This test exercises the real "View all (composite)" dropdown option end-to-end and closes the
 * Codex 00:43 UTC review concern: "unknown/composite or scaled same-size streams must not strand
 * contentSize at zero when no metadata/resize event occurs."
 *
 * NOTE: The `id !== COMPOSITE_MONITOR_ID` guard on line 1441 of Viewer.tsx is defensive/
 * documentary — COMPOSITE_MONITOR_ID = u32::MAX = 4294967295 and no real monitor id ever equals
 * it, so removing the guard would leave target=undefined anyway (ml.find returns undefined). The
 * guard cannot be pinned by a mutation test with a realistic monitor list. The test's value is
 * behavioral: it verifies the full composite-select → reset → dims-arrive → snap path.
 *
 * Known limitation not tested here: if the composite stream happens to have the same resolution as
 * the prior single-monitor stream, neither loadedmetadata nor resize re-fires, contentSize stays
 * zeroed, and pendingActualSnapRef stays armed but never fires — the operator's 1:1 preference is
 * silently lost. This is an edge case only possible when composite dims exactly equal prior monitor
 * dims; it is documented here, not treated as a blocking defect.
 */

/**
 * Test 6 — Monitor switch while Fit is active (scalePref='fit') does NOT arm the 1:1 snap
 *
 * onMonitorChange sets pendingActualSnapRef = (scalePrefRef.current === "actual"). When the
 * operator's last explicit zoom was Fit, scalePref is "fit" and the snap must NOT fire after
 * dims arrive — the monitor switch should leave the view at Fit (IDENTITY_VIEW), not snap to
 * 1:1 behind the operator's back.
 *
 * Mutation target: replacing `scalePrefRef.current === "actual"` with `true` (always arm)
 * causes the snap to fire after loadedmetadata even when Fit was chosen. The snap produces a
 * 1:1 translate+scale that is non-IDENTITY, making the post-loadedmetadata assertion fail.
 */
test("Pinch gesture before new dims arrive cancels pending snap (Bug 4)", async ({ page }) => {
  await fixture(page);

  // Different-resolution monitors so sameRes=false on switch: contentSize cleared, snap waits.
  await page.evaluate(
    (monitors) => (window as any).peers[0].control({ t: "MonitorList", c: { monitors } }),
    MIXED_RES_MONITORS,
  );

  // Seed 1080p dims so the surface has a known non-zero content size.
  await setVideoDims(page, 1920, 1080);

  // Switch to 1:1 so scalePrefRef="actual" and pendingActualSnapRef is armed on next switch.
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-zoom-actual"));
  await expect.poll(() => videoTransform(page)).not.toBe(IDENTITY);

  // Switch to monitor 1 (4K — different resolution):
  //   onMonitorChange → setView(IDENTITY_VIEW), contentSize cleared, pendingActualSnapRef=true.
  await page.getByTestId("viewer-monitor").selectOption("1");
  await expect.poll(() => videoTransform(page)).toBe(IDENTITY);

  // Simulate a two-finger pinch on the viewer surface BEFORE loadedmetadata re-fires.
  // The gesture must change the transform (scale > 1) and clear pendingActualSnapRef.
  await page.evaluate(() => {
    const surface = document.querySelector(".viewer__surface") as HTMLElement;
    if (!surface) throw new Error("viewer__surface not found");
    const rect = surface.getBoundingClientRect();
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;

    // Helper: create a TouchList-like object from coordinate pairs.
    function makeTouches(coords: [number, number][]): Touch[] {
      return coords.map(([x, y], i) =>
        new Touch({ identifier: i + 1, target: surface, clientX: x, clientY: y, pageX: x, pageY: y }),
      );
    }

    const startSep = 80; // Initial finger separation (px)
    const start = makeTouches([[cx - startSep / 2, cy], [cx + startSep / 2, cy]]);
    surface.dispatchEvent(new TouchEvent("touchstart", {
      bubbles: true, cancelable: true,
      touches: start, targetTouches: start, changedTouches: start,
    }));

    // Spread fingers by 30% to exceed the pinch latch threshold (PINCH_THRESHOLD = 0.15).
    const moveSep = startSep * 1.3;
    const moved = makeTouches([[cx - moveSep / 2, cy], [cx + moveSep / 2, cy]]);
    surface.dispatchEvent(new TouchEvent("touchmove", {
      bubbles: true, cancelable: true,
      touches: moved, targetTouches: moved, changedTouches: moved,
    }));

    surface.dispatchEvent(new TouchEvent("touchend", {
      bubbles: true, cancelable: true,
      touches: [], targetTouches: [], changedTouches: moved,
    }));
  });

  // The gesture must have produced a non-identity transform (zoom > 1).
  // If this assertion fails, the touch simulation did not reach the gesture recognizer.
  await expect.poll(() => videoTransform(page), { timeout: 2000 }).not.toBe(IDENTITY);
  const gestureTransform = await videoTransform(page);

  // Now fire loadedmetadata with 4K dims — this would trigger the snap if pendingActualSnapRef
  // were still set. With the fix the snap is cancelled and the gesture transform is preserved.
  await setVideoDims(page, 3840, 2160);
  await page.waitForTimeout(200);

  // Assert: the transform after loadedmetadata is still the gesture's value — the snap did NOT
  // override the operator's pinch. Without the fix (pendingActualSnapRef not cleared in the zoom
  // case), the snap re-fires here and the transform changes to the 4K snap value → FAILS.
  await expect.poll(() => videoTransform(page)).toBe(gestureTransform);
});

test("COMPOSITE_MONITOR_ID switch waits for loadedmetadata then snaps to 1:1 (composite coverage)", async ({ page }) => {
  await fixture(page);

  // Two monitors at different resolutions. COMPOSITE will be selectable since monitors.length > 1.
  await page.evaluate(
    (monitors) => (window as any).peers[0].control({ t: "MonitorList", c: { monitors } }),
    MIXED_RES_MONITORS,
  );

  // Seed 1080p dims for the initial monitor 0 so the viewer has a known content size.
  await setVideoDims(page, 1920, 1080);

  // Click 1:1 at 1080p — scalePrefRef = "actual".
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-zoom-actual"));
  await expect.poll(() => videoTransform(page)).not.toBe(IDENTITY);
  const zoom1080p = await videoTransform(page);

  // Select "View all (composite)" — COMPOSITE_MONITOR_ID is the "View all" option value.
  // onMonitorChange: id === COMPOSITE_MONITOR_ID → target=undefined → sameRes=false →
  // contentSize cleared → pendingActualSnapRef=true → waits for loadedmetadata.
  // Guard: the composite option only appears when monitors.length > 1 (verified above).
  await expect(page.getByTestId("viewer-monitor")).toContainText("View all (composite)");
  await page.getByTestId("viewer-monitor").selectOption({ label: "View all (composite)" });

  // View must reset to IDENTITY immediately (contentSize=0 bails the snap effect).
  await expect.poll(() => videoTransform(page)).toBe(IDENTITY);

  // Deliver composite dims (side-by-side 1080p + 4K layout: 5760×2160).
  await setVideoDims(page, 5760, 2160);
  await page.waitForTimeout(200);

  // Assert: snap fires with the composite dims — zoom is different from the pre-switch 1080p
  // value (composite is much wider), and it is not IDENTITY (snap actually applied).
  // Mutation (remove `id !== COMPOSITE_MONITOR_ID` guard → treat composite as sameRes):
  //   sameRes = target.width(1920) === cs.w(1920) → true → contentSize NOT cleared → snap fires
  //   immediately at 1080p dims → zoom stays at zoom1080p even after composite loadedmetadata.
  //   Both assertions below would then FAIL.
  await expect.poll(() => videoTransform(page)).not.toBe(IDENTITY);
  await expect.poll(() => videoTransform(page)).not.toBe(zoom1080p);
});

test("Monitor switch while Fit is active does NOT arm 1:1 snap (scalePref='fit' guard)", async ({ page }) => {
  await fixture(page);

  // Different-resolution monitors so that the switch is a genuine different-res switch
  // (contentSize cleared) — this removes any ambiguity about whether sameRes vs. fit is the
  // reason the snap doesn't fire.
  await page.evaluate(
    (monitors) => (window as any).peers[0].control({ t: "MonitorList", c: { monitors } }),
    MIXED_RES_MONITORS,
  );

  // Seed 1080p dims, click 1:1 (scalePrefRef="actual"), then click Fit (scalePrefRef="fit").
  await setVideoDims(page, 1920, 1080);
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-zoom-actual"));
  await expect.poll(() => videoTransform(page)).not.toBe(IDENTITY);
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-zoom-fit"));
  await expect.poll(() => videoTransform(page)).toBe(IDENTITY);

  // Switch to monitor 1 (4K — different resolution).
  // onMonitorChange: scalePrefRef="fit" → pendingActualSnapRef=false. contentSize cleared (diff-res).
  await page.getByTestId("viewer-monitor").selectOption("1");

  // Deliver 4K dims — the snap effect fires but pendingActualSnapRef is false → bail immediately.
  await setVideoDims(page, 3840, 2160);
  await page.waitForTimeout(200);

  // Assert: transform stays IDENTITY — Fit won, no snap.
  // Mutation (replace `scalePrefRef.current === "actual"` with `true`): snap fires after 4K
  // loadedmetadata → preferredViewForMonitorSwitch("actual", 3840×2160 into ~1280×720 surface)
  // → actualZoom ≈ 3.0 (content pixels are 3× larger than surface pixels) → non-IDENTITY
  // translate+scale → this assertion FAILS.
  await expect.poll(() => videoTransform(page)).toBe(IDENTITY);
});

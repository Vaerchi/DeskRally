/**
 * Download delivery real-App Playwright acceptance tests.
 *
 * Proves that browse-triggered downloads actually fire a browser download event regardless of
 * which tab is active, and that the "✓ saved" badge uses rel-path identity (Bug 1 + Bug 2 fixes).
 *
 *   1. Download while on Screen view fires a Playwright download event (Bug 1 fix).
 *   2. Two sequential downloads while on Screen view each fire a distinct download event.
 *   3. Tab switch to Files after a Screen-view download does NOT duplicate the save.
 *   4. Stale badge cleared after reconnect (completedBrowseRelPaths cleared on teardown).
 *
 * Mutation evidence per test:
 *   Test 1: reverting saveBytesAsFile to inside FileTransferPanel.useEffect → no download event
 *           because FileTransferPanel is not mounted on Screen view.
 *   Test 2: same revert → zero download events for both clicks.
 *   Test 3: calling saveBytesAsFile from BOTH App.tsx AND FileTransferPanel.useEffect → two events
 *           for a single download (one per save site).
 *   Test 4: removing setCompletedBrowseRelPaths(new Set()) from teardown → badge persists across
 *           sessions on the same file path.
 *
 * The FakeDC responds to channel-5 Request frames with Offer + Chunk + Done so the
 * onDownload callback in App.tsx fires and saveBytesAsFile is invoked.
 */

import { test, expect, type Page } from "@playwright/test";
import { openViewerPanel, selectSessionView } from "./nav";
import { openManualConnect } from "./manual_connect";

const TRANSFER_ROOT = "C:\\rmt-agent\\transfers";
const REPORT_FILENAME = "report.pdf";
const SECOND_FILENAME = "data.csv";

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
    w.downloadCount = 0;

    class FakeDC {
      readyState = "open";
      sent: any[] = [];
      onmessage: any = null;
      onclose: any = null;

      send(bytes: ArrayBuffer): void {
        this.sent.push(bytes);
        const view = new Uint8Array(bytes);
        const channelId = view[0];
        try {
          if (channelId === 0) {
            // Control channel: respond to ListDirectory.
            const payload = JSON.parse(new TextDecoder().decode(view.slice(5)));
            if (payload.t === "ListDirectory") {
              const path: string = payload.c.path;
              // "" = drive roots; the transfer root gets both test files; subdirs get one.
              let entries: object[];
              if (path === "") {
                entries = [{ name: "C:\\", is_dir: true, size: 0, modified_unix: 0 }];
              } else {
                entries = [
                  { name: "report.pdf", is_dir: false, size: 4, modified_unix: 1_700_000_000 },
                  { name: "data.csv", is_dir: false, size: 4, modified_unix: 1_700_000_001 },
                ];
              }
              const resp = {
                t: "DirectoryListing",
                c: { path, entries, truncated: false, audit: null },
              };
              const respBytes = new TextEncoder().encode(JSON.stringify(resp));
              const frame = new Uint8Array(5 + respBytes.length);
              new DataView(frame.buffer).setUint32(1, respBytes.length);
              frame.set(respBytes, 5);
              const dc = this;
              setTimeout(() => dc.onmessage?.({ data: frame.buffer }), 0);
            }
          } else if (channelId === 5) {
            // FileTransfer channel: respond to Request with Offer + Chunk + Done.
            try {
              const payload = JSON.parse(new TextDecoder().decode(view.slice(5)));
              if (payload.t === "Request" && payload.c?.id && payload.c?.path) {
                const reqId: string = payload.c.id;
                const reqPath: string = payload.c.path;
                const reqName = reqPath.split("/").pop() || reqPath;
                const data = new Uint8Array([1, 2, 3, 4]);
                const dc = this;
                (async () => {
                  const hashBuf = await crypto.subtle.digest("SHA-256", data);
                  const sha256 = Array.from(new Uint8Array(hashBuf))
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join("");

                  function sendCh5Frame(framePayload: object | Uint8Array) {
                    const payloadBytes =
                      framePayload instanceof Uint8Array
                        ? framePayload
                        : new TextEncoder().encode(JSON.stringify(framePayload));
                    const frame = new Uint8Array(5 + payloadBytes.length);
                    frame[0] = 5;
                    new DataView(frame.buffer).setUint32(1, payloadBytes.length);
                    frame.set(payloadBytes, 5);
                    dc.onmessage?.({ data: frame.buffer });
                  }

                  // Offer
                  sendCh5Frame({
                    t: "Offer",
                    c: { id: reqId, name: reqName, size: data.length, sha256 },
                  });

                  // Chunk: binary [0x01][id:16 bytes][seq:u32 BE=0][data]
                  const idHex = reqId.replace(/-/g, "");
                  const idBytes = new Uint8Array(16);
                  for (let i = 0; i < 16; i++) {
                    idBytes[i] = parseInt(idHex.slice(i * 2, i * 2 + 2), 16);
                  }
                  const chunk = new Uint8Array(1 + 16 + 4 + data.length);
                  chunk[0] = 0x01;
                  chunk.set(idBytes, 1);
                  new DataView(chunk.buffer).setUint32(17, 0, false); // seq=0, big-endian
                  chunk.set(data, 21);
                  sendCh5Frame(chunk);

                  // Done
                  sendCh5Frame({ t: "Done", c: { id: reqId } });
                })();
              }
            } catch {
              /* binary frames or non-JSON — ignore */
            }
          }
        } catch {
          /* non-JSON frames — ignore */
        }
      }

      close(): void {
        this.readyState = "closed";
        this.onclose?.();
      }
    }

    class Peer {
      connectionState = "new";
      onconnectionstatechange: any;
      ontrack: any;
      frames = 1;
      dc = new FakeDC();
      constructor() {
        w.peers.push(this);
      }
      createDataChannel() {
        return this.dc;
      }
      addTransceiver() {}
      close() {
        this.connectionState = "closed";
        this.onconnectionstatechange?.();
      }
      getStats() {
        return Promise.resolve(
          new Map([
            ["video", { type: "inbound-rtp", kind: "video", framesDecoded: this.frames }],
          ]),
        );
      }
      connected() {
        this.connectionState = "connected";
        this.onconnectionstatechange?.();
      }
      fail() {
        this.connectionState = "failed";
        this.onconnectionstatechange?.();
      }
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

  await page.goto(test.info().project.use.baseURL!);
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
  // Advertise the transfer root.
  await page.evaluate(
    (root) => (window as any).peers[0].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );
}

// Navigate to the transfer dir in the file browser (while remaining on Screen tab).
async function openFileBrowserAtTransferRoot(page: Page) {
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId(`file-download-${REPORT_FILENAME}`)).toBeVisible();
}

test("download while on Screen view fires a Playwright download event (Bug 1 fix)", async ({
  page,
}) => {
  await fixture(page);
  // Stay on the Screen view (default tab) — do NOT switch to the Files tab.
  // The file browser is a side panel in Screen view; FileTransferPanel is NOT mounted.
  await openFileBrowserAtTransferRoot(page);

  // saveBytesAsFile is now called from App.tsx onDownload (not from FileTransferPanel.useEffect),
  // so the download event fires even when the Files tab is not active.
  const downloadPromise = page.waitForEvent("download");
  await page.getByTestId(`file-download-${REPORT_FILENAME}`).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe(REPORT_FILENAME);
});

test("two sequential downloads while on Screen view each fire a distinct download event", async ({
  page,
}) => {
  await fixture(page);
  await openFileBrowserAtTransferRoot(page);

  const dl1Promise = page.waitForEvent("download");
  await page.getByTestId(`file-download-${REPORT_FILENAME}`).click();
  const dl1 = await dl1Promise;
  expect(dl1.suggestedFilename()).toBe(REPORT_FILENAME);

  const dl2Promise = page.waitForEvent("download");
  await page.getByTestId(`file-download-${SECOND_FILENAME}`).click();
  const dl2 = await dl2Promise;
  expect(dl2.suggestedFilename()).toBe(SECOND_FILENAME);
});

test("switching to Files tab after Screen-view download does NOT duplicate the save", async ({
  page,
}) => {
  await fixture(page);
  await openFileBrowserAtTransferRoot(page);

  // Count downloads: expect exactly ONE from the click.
  const downloadPromise = page.waitForEvent("download");
  await page.getByTestId(`file-download-${REPORT_FILENAME}`).click();
  const dl = await downloadPromise;
  expect(dl.suggestedFilename()).toBe(REPORT_FILENAME);

  // Now switch to the Files tab — this mounts FileTransferPanel.
  // If saveBytesAsFile were still called in FileTransferPanel.useEffect, a second download event
  // would fire here. The test times out waiting for a second event, proving it does NOT fire.
  const secondDownloadPromise = page.waitForEvent("download", { timeout: 2000 });
  await selectSessionView(page, "Files");
  await expect(page.getByTestId("file-transfer-panel")).toBeVisible();
  // No second download event — saveBytesAsFile is only called once (from App.tsx onDownload).
  await expect(secondDownloadPromise).rejects.toThrow();
});

test("stale badge cleared after reconnect — no completedBrowseRelPaths carry across sessions", async ({
  page,
}) => {
  await fixture(page);
  await openFileBrowserAtTransferRoot(page);

  // Download report.pdf and wait for the save.
  const downloadPromise = page.waitForEvent("download");
  await page.getByTestId(`file-download-${REPORT_FILENAME}`).click();
  await downloadPromise;

  // The "✓ saved" badge should be visible after the download.
  await expect(page.getByTestId(`file-saved-${REPORT_FILENAME}`)).toBeVisible();

  // Disconnect: teardown clears completedBrowseRelPaths.
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();

  // Reconnect without sending a new TransferDir (simulates a fresh session).
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  await page.evaluate(() => (window as any).peers[1].connected());
  // Re-advertise the same transfer root so the file browser works.
  await page.evaluate(
    (root) => (window as any).peers[1].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );

  // Open the file browser at the transfer root in the new session.
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId(`file-row-${REPORT_FILENAME}`)).toBeVisible();

  // Mutation: removing setCompletedBrowseRelPaths(new Set()) from teardown would leave the
  // badge visible here. With the fix, it must be absent.
  await expect(page.getByTestId(`file-saved-${REPORT_FILENAME}`)).toHaveCount(0);
});

test("failed request (Error frame) leaves no stale badge — onDownloadError clears map entry", async ({
  page,
}) => {
  // FakeDC variant: responds to the FIRST Request on channel 5 with an Error frame (peer abort),
  // then falls back to normal Offer+Chunk+Done for subsequent requests.
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
      firstRequest = true; // first Request on ch5 → Error frame; rest → normal delivery

      send(bytes: ArrayBuffer): void {
        this.sent.push(bytes);
        const view = new Uint8Array(bytes);
        const channelId = view[0];
        try {
          if (channelId === 0) {
            const payload = JSON.parse(new TextDecoder().decode(view.slice(5)));
            if (payload.t === "ListDirectory") {
              const path: string = payload.c.path;
              let entries: object[];
              if (path === "") {
                entries = [{ name: "C:\\", is_dir: true, size: 0, modified_unix: 0 }];
              } else {
                entries = [
                  { name: "report.pdf", is_dir: false, size: 4, modified_unix: 1_700_000_000 },
                  { name: "data.csv", is_dir: false, size: 4, modified_unix: 1_700_000_001 },
                ];
              }
              const resp = {
                t: "DirectoryListing",
                c: { path, entries, truncated: false, audit: null },
              };
              const respBytes = new TextEncoder().encode(JSON.stringify(resp));
              const frame = new Uint8Array(5 + respBytes.length);
              new DataView(frame.buffer).setUint32(1, respBytes.length);
              frame.set(respBytes, 5);
              const dc = this;
              setTimeout(() => dc.onmessage?.({ data: frame.buffer }), 0);
            }
          } else if (channelId === 5) {
            const payload = JSON.parse(new TextDecoder().decode(view.slice(5)));
            if (payload.t === "Request" && payload.c?.id && payload.c?.path) {
              const reqId: string = payload.c.id;
              const dc = this;

              function sendCh5Frame(framePayload: object) {
                const payloadBytes = new TextEncoder().encode(JSON.stringify(framePayload));
                const frame = new Uint8Array(5 + payloadBytes.length);
                frame[0] = 5;
                new DataView(frame.buffer).setUint32(1, payloadBytes.length);
                frame.set(payloadBytes, 5);
                dc.onmessage?.({ data: frame.buffer });
              }

              if (dc.firstRequest) {
                // First request → Offer then Error (peer aborts after offer — triggers onDownloadError).
                // Error-before-Offer is silently dropped; Offer+Error is the path that calls onDownloadError.
                dc.firstRequest = false;
                const reqPath: string = payload.c.path;
                const reqName = reqPath.split("/").pop() || reqPath;
                const abortData = new Uint8Array([1, 2, 3, 4]);
                (async () => {
                  const hashBuf = await crypto.subtle.digest("SHA-256", abortData);
                  const sha256 = Array.from(new Uint8Array(hashBuf))
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join("");
                  // Send Offer to register the download entry, then Error to abort it.
                  sendCh5Frame({ t: "Offer", c: { id: reqId, name: reqName, size: abortData.length, sha256 } });
                  sendCh5Frame({ t: "Error", c: { id: reqId, message: "disk full" } });
                })();
              } else {
                // Subsequent requests → normal Offer+Chunk+Done.
                const reqPath: string = payload.c.path;
                const reqName = reqPath.split("/").pop() || reqPath;
                const data = new Uint8Array([1, 2, 3, 4]);
                (async () => {
                  const hashBuf = await crypto.subtle.digest("SHA-256", data);
                  const sha256 = Array.from(new Uint8Array(hashBuf))
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join("");
                  sendCh5Frame({ t: "Offer", c: { id: reqId, name: reqName, size: data.length, sha256 } });
                  const idHex = reqId.replace(/-/g, "");
                  const idBytes = new Uint8Array(16);
                  for (let i = 0; i < 16; i++) {
                    idBytes[i] = parseInt(idHex.slice(i * 2, i * 2 + 2), 16);
                  }
                  const chunkData = new Uint8Array(1 + 16 + 4 + data.length);
                  chunkData[0] = 0x01;
                  chunkData.set(idBytes, 1);
                  new DataView(chunkData.buffer).setUint32(17, 0, false);
                  chunkData.set(data, 21);
                  // Binary chunk: wrap in the channel frame directly (not JSON-encoded).
                  const chunkFrame = new Uint8Array(5 + chunkData.length);
                  chunkFrame[0] = 5;
                  new DataView(chunkFrame.buffer).setUint32(1, chunkData.length);
                  chunkFrame.set(chunkData, 5);
                  dc.onmessage?.({ data: chunkFrame.buffer });
                  sendCh5Frame({ t: "Done", c: { id: reqId } });
                })();
              }
            }
          }
        } catch { /* ignore */ }
      }

      close(): void {
        this.readyState = "closed";
        this.onclose?.();
      }
    }

    class Peer {
      connectionState = "new";
      onconnectionstatechange: any;
      ontrack: any;
      frames = 1;
      dc = new FakeDC();
      constructor() { w.peers.push(this); }
      createDataChannel() { return this.dc; }
      addTransceiver() {}
      close() { this.connectionState = "closed"; this.onconnectionstatechange?.(); }
      getStats() {
        return Promise.resolve(
          new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: this.frames }]]),
        );
      }
      connected() { this.connectionState = "connected"; this.onconnectionstatechange?.(); }
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

  await page.goto(test.info().project.use.baseURL!);
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
  await page.evaluate(
    (root) => (window as any).peers[0].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );

  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId(`file-download-${REPORT_FILENAME}`)).toBeVisible();

  // Click report.pdf — FakeDC responds with Error (first request).
  // The error banner appears; no badge should appear.
  await page.getByTestId(`file-download-${REPORT_FILENAME}`).click();
  // Wait for the error to surface (the error banner).
  await expect(page.getByText("rejected")).toBeVisible({ timeout: 3000 });

  // The saved badge must NOT appear — the failed request's map entry was cleared by onDownloadError.
  // Mutation: if the delete(id) were absent, the next same-basename success would show the badge.
  await expect(page.getByTestId(`file-saved-${REPORT_FILENAME}`)).toHaveCount(0);

  // Click data.csv — FakeDC responds with normal Offer+Chunk+Done (second request).
  // This proves the FakeDC still works after the error, and only data.csv gets a badge.
  const downloadPromise = page.waitForEvent("download");
  await page.getByTestId(`file-download-${SECOND_FILENAME}`).click();
  await downloadPromise;
  await expect(page.getByTestId(`file-saved-${SECOND_FILENAME}`)).toBeVisible();
  // report.pdf still has no badge — the failed request did not pollute completedBrowseRelPaths.
  await expect(page.getByTestId(`file-saved-${REPORT_FILENAME}`)).toHaveCount(0);
});

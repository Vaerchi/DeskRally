/**
 * Download-wiring real-App Playwright acceptance tests.
 *
 * Proves that App.tsx correctly wires:
 *   1. TransferDir control message → agentTransferDir state → Go-to-Transfers enabled.
 *   2. Browse-click → downloadFromBrowse → FileTransferClient.request() → channel-5 frame.
 *   3. onInstallGrant → setGrantCapabilities → gateDownloadOnCapability suppresses buttons.
 *   4. teardown() clears agentTransferDir → Go-to-Transfers disabled on the next session.
 *   5. teardown() clears grantCapabilities → downloads visible again on the next session.
 *
 * Mutation evidence per test:
 *   Test 1: removing setAgentTransferDir(path) from onTransferDir → button stays disabled.
 *   Test 2: removing gateDownloadOnCapability / downloadFromBrowse call → no ch-5 frame.
 *   Test 3: removing setGrantCapabilities(parseGrantCapabilities(…)) → download not suppressed.
 *   Test 4: removing setAgentTransferDir(undefined) from teardown → button enabled on new session.
 *   Test 5: removing setGrantCapabilities(null) from teardown → downloads suppressed on new session.
 *
 * Follows supervisor_session_recovery.spec.ts: addInitScript stubs RTCPeerConnection with a
 * FakeDC that auto-responds to ListDirectory (channel 0) and Backstage (channel 6) frames so
 * no real agent or signaling server is required.
 */

import { test, expect, type Page } from "@playwright/test";
import { openViewerPanel, selectSessionView } from "./nav";
import { openManualConnect } from "./manual_connect";

const TRANSFER_ROOT = "C:\\rmt-agent\\transfers";
const REPORT_FILENAME = "report.pdf";

// SignedGrant with no file_download capability — parseGrantCapabilities returns Set{["process_list"]}.
const RESTRICTED_GRANT = JSON.stringify({
  claims: {
    grant: { capabilities: ["process_list"], machine_id: "m1", machine_group_id: null },
    issued_at_ms: 1,
    expires_at_ms: 9_999_999_999_999,
  },
  sig: "deadbeef".repeat(16),
});

async function fixture(page: Page) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines")
      return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions" && method === "POST") {
      return route.fulfill({
        json: { session: { id: "s1" }, signaling: { url: "ws://127.0.0.1:5188/ws", ticket: {} } },
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
  await page.routeWebSocket("ws://127.0.0.1:5188/ws", () => {});
  await page.addInitScript(() => {
    const w = window as any;
    w.peers = [];
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
            // Control channel: auto-respond to ListDirectory requests.
            const payload = JSON.parse(new TextDecoder().decode(view.slice(5)));
            if (payload.t === "ListDirectory") {
              const path: string = payload.c.path;
              // "" = drive roots; anything else = the transfer dir contents.
              const entries =
                path === ""
                  ? [{ name: "C:\\", is_dir: true, size: 0, modified_unix: 0 }]
                  : [{ name: "report.pdf", is_dir: false, size: 1024, modified_unix: 1_700_000_000 }];
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
          } else if (channelId === 6) {
            // Backstage channel: always deny — triggers the grant affordance in BackstagePanels.
            const denial = {
              ok: false,
              error: { kind: "denied", message: "access denied: no grant installed" },
            };
            const denialBytes = new TextEncoder().encode(JSON.stringify(denial));
            const frame = new Uint8Array(5 + denialBytes.length);
            frame[0] = 6; // Backstage channel ID
            new DataView(frame.buffer).setUint32(1, denialBytes.length);
            frame.set(denialBytes, 5);
            const dc = this;
            setTimeout(() => dc.onmessage?.({ data: frame.buffer }), 0);
          }
        } catch {
          /* binary FileTransfer frames and other non-JSON payloads — ignore */
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
          new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: this.frames }]]),
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
      // Inject a control-channel message FROM the fake agent into the app.
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
}

test("TransferDir message enables Go-to-Transfers; absent TransferDir keeps it disabled", async ({
  page,
}) => {
  await fixture(page);
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  // No TransferDir yet — tdir is undefined → button is disabled.
  // Mutation: removing setAgentTransferDir(path) from onTransferDir would leave this disabled forever.
  await expect(page.getByTestId("file-goto-transfers")).toBeDisabled();
  // Inject the TransferDir control message from the fake agent.
  await page.evaluate(
    (root) => (window as any).peers[0].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );
  // agentTransferDir is now set → tdir is known → button becomes enabled.
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
});

test("browse-click-to-download sends a FileTransfer Request frame on channel 5", async ({ page }) => {
  await fixture(page);
  await page.evaluate(
    (root) => (window as any).peers[0].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  // Wait for loading to finish and button to be enabled before clicking.
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
  await page.getByTestId("file-goto-transfers").click();
  // Fake DC responds to ListDirectory TRANSFER_ROOT with report.pdf.
  await expect(page.getByTestId(`file-download-${REPORT_FILENAME}`)).toBeVisible();
  await page.getByTestId(`file-download-${REPORT_FILENAME}`).click();
  // A channel-5 FileTransfer Request must appear in dc.sent.
  // Mutation: removing downloadFromBrowse/gateDownloadOnCapability → no ch-5 frame → false.
  await expect
    .poll(() =>
      page.evaluate(() =>
        (window as any).peers[0].dc.sent.some((bytes: ArrayBuffer) => {
          const view = new Uint8Array(bytes);
          if (view[0] !== 5) return false;
          try {
            const msg = JSON.parse(new TextDecoder().decode(view.slice(5)));
            return msg.t === "Request" && typeof msg.c?.path === "string";
          } catch {
            return false;
          }
        }),
      ),
    )
    .toBe(true);
});

test("installing a restricted grant suppresses download buttons while the session is live", async ({
  page,
}) => {
  await fixture(page);
  await page.evaluate(
    (root) => (window as any).peers[0].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );
  // Navigate to Backstage: auto-request fires, fake DC denies it, grant affordance appears.
  await selectSessionView(page, "Under the Hood");
  // Mutation: removing setGrantCapabilities(parseGrantCapabilities(…)) from onInstallGrant would
  // leave grantCapabilities = null (visible by default) so the button would remain visible.
  await expect(page.getByTestId("backstage-grant")).toBeVisible();
  await page.getByTestId("backstage-grant-input").fill(RESTRICTED_GRANT);
  await page.getByTestId("backstage-grant-install").click();
  // Return to Screen, open files, navigate to the transfer dir.
  await selectSessionView(page, "Screen");
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId(`file-row-${REPORT_FILENAME}`)).toBeVisible();
  // grantCapabilities excludes file_download → gateDownloadOnCapability returns undefined → no button.
  await expect(page.getByTestId(`file-download-${REPORT_FILENAME}`)).toHaveCount(0);
});

test("session teardown clears agentTransferDir; Go-to-Transfers disabled on the next session", async ({
  page,
}) => {
  await fixture(page);
  await page.evaluate(
    (root) => (window as any).peers[0].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
  // Disconnect: teardown() clears agentTransferDir.
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  // Reconnect without sending a new TransferDir message.
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  await page.evaluate(() => (window as any).peers[1].connected());
  // Open the files panel on the fresh session.
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  // Mutation: removing setAgentTransferDir(undefined) from teardown → old path persists → enabled.
  await expect(page.getByTestId("file-goto-transfers")).toBeDisabled();
});

test("session teardown clears grantCapabilities; downloads visible again on the next session", async ({
  page,
}) => {
  await fixture(page);
  await page.evaluate(
    (root) => (window as any).peers[0].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );
  // Session 1: install the restricted grant to suppress download buttons.
  await selectSessionView(page, "Under the Hood");
  await expect(page.getByTestId("backstage-grant")).toBeVisible();
  await page.getByTestId("backstage-grant-input").fill(RESTRICTED_GRANT);
  await page.getByTestId("backstage-grant-install").click();
  // Confirm downloads are suppressed on session 1.
  await selectSessionView(page, "Screen");
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId(`file-row-${REPORT_FILENAME}`)).toBeVisible();
  await expect(page.getByTestId(`file-download-${REPORT_FILENAME}`)).toHaveCount(0);
  // Disconnect: teardown() resets grantCapabilities to null.
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  // Session 2: reconnect with TransferDir but no new grant.
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  await page.evaluate(() => (window as any).peers[1].connected());
  await page.evaluate(
    (root) => (window as any).peers[1].control({ t: "TransferDir", c: { path: root } }),
    TRANSFER_ROOT,
  );
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId(`file-row-${REPORT_FILENAME}`)).toBeVisible();
  // grantCapabilities is null (reset by teardown) → gateDownloadOnCapability passes through → visible.
  // Mutation: removing setGrantCapabilities(null) from teardown → restricted caps persist → hidden.
  await expect(page.getByTestId(`file-download-${REPORT_FILENAME}`)).toBeVisible();
});

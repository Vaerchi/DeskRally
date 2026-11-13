/**
 * File-browser upload, real-App mocked acceptance.
 *
 * Proves App.tsx wires the file browser's "Upload here" to the session's FileTransferClient:
 *   1. The action is offered only AT the advertised transfer root (absent at the drive roots).
 *   2. Picking a file sends a channel-5 Offer (name, size, SHA-256 of the bytes), its Chunk(s) and a
 *      Done; the agent's Ack settles the row; the root is then re-listed and shows the new file.
 *   3. A refused upload shows the agent's own reason on its row.
 *
 * Same fake transport as download_wiring.spec.ts (addInitScript stubs RTCPeerConnection), extended so
 * the fake agent answers a FileTransfer Done with an Ack and lists committed uploads in the root. No
 * real agent or signaling server. Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import { openViewerPanel } from "./nav";
import { openManualConnect } from "./manual_connect";

const TRANSFER_ROOT = "C:\\rmt-agent\\transfers";

async function fixture(page: Page, mode: "ack-ok" | "ack-refused" | "error") {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions" && method === "POST") {
      return route.fulfill({
        json: { session: { id: "s1" }, signaling: { url: "ws://127.0.0.1:5188/ws", ticket: {} } },
      });
    }
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket("ws://127.0.0.1:5188/ws", () => {});
  await page.addInitScript((mode: string) => {
    const w = window as any;
    w.peers = [];
    w.listRequests = [] as string[];
    w.committed = [] as string[];
    const frameOf = (channel: number, payload: unknown) => {
      const bytes = new TextEncoder().encode(JSON.stringify(payload));
      const frame = new Uint8Array(5 + bytes.length);
      frame[0] = channel;
      new DataView(frame.buffer).setUint32(1, bytes.length);
      frame.set(bytes, 5);
      return frame.buffer;
    };
    class FakeDC {
      readyState = "open";
      sent: ArrayBuffer[] = [];
      onmessage: any = null;
      onclose: any = null;
      offers = new Map<string, string>(); // transfer id -> name
      send(bytes: ArrayBuffer): void {
        this.sent.push(bytes);
        const view = new Uint8Array(bytes);
        const channel = view[0];
        const reply = (buf: ArrayBuffer) => setTimeout(() => this.onmessage?.({ data: buf }), 0);
        if (view[5] !== 0x7b) return; // only JSON payloads ('{') are answered; chunks are binary
        const msg = JSON.parse(new TextDecoder().decode(view.slice(5)));
        if (channel === 0 && msg.t === "ListDirectory") {
          const path: string = msg.c.path;
          w.listRequests.push(path);
          const entries =
            path === ""
              ? [{ name: "C:\\", is_dir: true, size: 0, modified_unix: 0 }]
              : (w.committed as string[]).map((name) => ({ name, is_dir: false, size: 1, modified_unix: 0 }));
          reply(frameOf(0, { t: "DirectoryListing", c: { path, entries, truncated: false, audit: null } }));
        } else if (channel === 5 && msg.t === "Offer") {
          this.offers.set(msg.c.id, msg.c.name);
        } else if (channel === 5 && msg.t === "Done") {
          const name = this.offers.get(msg.c.id);
          const ok = mode === "ack-ok";
          if (ok && name) w.committed.push(name);
          if (mode === "error") {
            // The agent refuses some uploads with an Error and never an Ack (limit, disk, gap).
            reply(frameOf(5, { t: "Error", c: { id: msg.c.id, message: "refused at offer" } }));
          } else {
            reply(frameOf(5, { t: "Ack", c: { id: msg.c.id, ok, message: ok ? "" : "upload refused by test agent" } }));
          }
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
        return Promise.resolve(new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: 1 }]]));
      }
      connected() {
        this.connectionState = "connected";
        this.onconnectionstatechange?.();
      }
      control(message: unknown) {
        this.dc.onmessage?.({ data: frameOf(0, message) });
      }
    }
    w.RTCPeerConnection = Peer;
  }, mode);

  await page.goto(test.info().project.use.baseURL!);
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
  await page.evaluate((root) => (window as any).peers[0].control({ t: "TransferDir", c: { path: root } }), TRANSFER_ROOT);
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-files-toggle").click();
  await expect(page.getByTestId("file-manager")).toBeVisible();
}

/** The channel-5 JSON messages the app sent, in order. */
async function ftMessages(page: Page): Promise<{ t: string; c: any }[]> {
  return page.evaluate(() =>
    ((window as any).peers[0].dc.sent as ArrayBuffer[])
      .map((b) => new Uint8Array(b))
      .filter((v) => v[0] === 5 && v[5] === 0x7b)
      .map((v) => JSON.parse(new TextDecoder().decode(v.slice(5)))),
  );
}

test("Upload here sends Offer/Chunk/Done, settles on the Ack, and re-lists the root", async ({ page }) => {
  await fixture(page, "ack-ok");
  // At the drive roots there is nothing to upload into.
  await expect(page.getByTestId("file-goto-transfers")).toBeEnabled();
  await expect(page.getByTestId("file-upload")).toHaveCount(0);

  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId("file-upload")).toBeVisible();
  const listsBefore = await page.evaluate(() => (window as any).listRequests.length);

  const body = Buffer.from("hello from the technician\n");
  await page.getByTestId("file-upload-input").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: body });

  await expect(page.locator('[data-testid^="file-upload-row-"]')).toHaveAttribute("data-phase", "ok");
  const msgs = await ftMessages(page);
  const offer = msgs.find((m) => m.t === "Offer");
  expect(offer?.c).toMatchObject({
    name: "notes.txt",
    size: body.length,
    sha256: createHash("sha256").update(body).digest("hex"),
  });
  expect(msgs.filter((m) => m.t === "Done").map((m) => m.c.id)).toEqual([offer!.c.id]);
  const chunks = await page.evaluate(
    () => ((window as any).peers[0].dc.sent as ArrayBuffer[]).filter((b) => new Uint8Array(b)[0] === 5 && new Uint8Array(b)[5] === 0x01).length,
  );
  expect(chunks).toBeGreaterThan(0);

  // The root is re-listed after the batch and shows the committed file.
  await expect.poll(() => page.evaluate(() => (window as any).listRequests.slice(-1)[0])).toBe(TRANSFER_ROOT);
  expect(await page.evaluate(() => (window as any).listRequests.length)).toBeGreaterThan(listsBefore);
  await expect(page.getByTestId("file-row-notes.txt")).toBeVisible();
});

test("a refused upload shows the agent's reason on its row", async ({ page }) => {
  await fixture(page, "ack-refused");
  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId("file-upload")).toBeVisible();
  await page.getByTestId("file-upload-input").setInputFiles({ name: "x.bin", mimeType: "application/octet-stream", buffer: Buffer.from([1, 2, 3]) });
  const row = page.locator('[data-testid^="file-upload-row-"]');
  await expect(row).toHaveAttribute("data-phase", "error");
  await expect(row).toContainText("upload refused by test agent");
  await expect(page.getByTestId("file-row-x.bin")).toHaveCount(0);
});

test("an upload the agent answers with an Error settles its row as failed and the batch continues", async ({ page }) => {
  await fixture(page, "error");
  await page.getByTestId("file-goto-transfers").click();
  await expect(page.getByTestId("file-upload")).toBeVisible();
  await page.getByTestId("file-upload-input").setInputFiles([
    { name: "one.bin", mimeType: "application/octet-stream", buffer: Buffer.from([1]) },
    { name: "two.bin", mimeType: "application/octet-stream", buffer: Buffer.from([2]) },
  ]);
  const rows = page.locator('[data-testid^="file-upload-row-"]');
  await expect(rows).toHaveCount(2); // the second file started, so the first did not stall the batch
  await expect(rows.nth(0)).toHaveAttribute("data-phase", "error");
  await expect(rows.nth(1)).toHaveAttribute("data-phase", "error");
  await expect(rows.nth(0)).not.toContainText("refused at offer"); // the peer's text is not echoed
});

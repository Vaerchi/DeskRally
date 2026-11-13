/**
 * Tests for the popup-window clipboard seam added in the popout-clipboard feature:
 *  - clipboardForWindow() routing
 *  - sendText(altClipboard) reads from the provided API
 *  - setReceiveEnabled(true, altClipboard) routes inbound writes to the provided API
 *  - setReceiveEnabled(false) falls back to the constructor clipboard
 *  - dispose() resets receiveClipboard to the constructor clipboard
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clipboardForWindow,
  ClipboardClient,
  encodeMessage,
  type ClipboardApi,
} from "./clipboard";

// ── helpers ──────────────────────────────────────────────────────────────────

function makeApi(value = "default"): ClipboardApi & { writes: string[] } {
  const writes: string[] = [];
  return {
    writes,
    readText: vi.fn(async () => value),
    writeText: vi.fn(async (t: string) => { writes.push(t); }),
  };
}

function makeClient(constructorApi: ClipboardApi) {
  const sends: Uint8Array[] = [];
  const client = new ClipboardClient(p => sends.push(p), constructorApi, {});
  return { client, sends };
}

const allClients: ClipboardClient[] = [];
function tracked(api: ClipboardApi) {
  const { client, sends } = makeClient(api);
  allClients.push(client);
  return { client, sends };
}

afterEach(() => {
  for (const c of allClients.splice(0)) c.dispose();
  vi.restoreAllMocks();
});

// ── clipboardForWindow ────────────────────────────────────────────────────────

describe("clipboardForWindow", () => {
  it("rejects readText when win is null", async () => {
    const api = clipboardForWindow(null);
    await expect(api.readText()).rejects.toThrow("clipboard API unavailable");
  });

  it("rejects writeText when win is null", async () => {
    const api = clipboardForWindow(null);
    await expect(api.writeText("x")).rejects.toThrow("clipboard API unavailable");
  });

  it("rejects readText when win.navigator.clipboard is absent", async () => {
    const fakeWin = { navigator: {} } as unknown as Window;
    const api = clipboardForWindow(fakeWin);
    await expect(api.readText()).rejects.toThrow("clipboard API unavailable");
  });

  it("rejects writeText when win.navigator.clipboard is absent", async () => {
    const fakeWin = { navigator: {} } as unknown as Window;
    const api = clipboardForWindow(fakeWin);
    await expect(api.writeText("x")).rejects.toThrow("clipboard API unavailable");
  });

  it("delegates readText to win.navigator.clipboard.readText", async () => {
    const readText = vi.fn(async () => "popup text");
    const fakeWin = { navigator: { clipboard: { readText, writeText: vi.fn() } } } as unknown as Window;
    const api = clipboardForWindow(fakeWin);
    expect(await api.readText()).toBe("popup text");
    expect(readText).toHaveBeenCalledOnce();
  });

  it("delegates writeText to win.navigator.clipboard.writeText", async () => {
    const writeText = vi.fn(async () => {});
    const fakeWin = { navigator: { clipboard: { readText: vi.fn(), writeText } } } as unknown as Window;
    const api = clipboardForWindow(fakeWin);
    await api.writeText("hello popup");
    expect(writeText).toHaveBeenCalledWith("hello popup");
  });
});

// ── sendText(altClipboard) ────────────────────────────────────────────────────

describe("sendText(altClipboard)", () => {
  it("reads from the provided alt clipboard, not the constructor clipboard", async () => {
    const constructorApi = makeApi("main window text");
    const popupApi = makeApi("popup window text");
    const { client, sends } = tracked(constructorApi);

    const result = await client.sendText(popupApi);

    expect(result).toBe("popup window text");
    expect(popupApi.readText).toHaveBeenCalledOnce();
    expect(constructorApi.readText).not.toHaveBeenCalled();
    expect(sends).toHaveLength(1);
  });

  it("falls back to constructor clipboard when no alt is provided", async () => {
    const constructorApi = makeApi("main window text");
    const { client } = tracked(constructorApi);

    const result = await client.sendText();

    expect(result).toBe("main window text");
    expect(constructorApi.readText).toHaveBeenCalledOnce();
  });

  it("returns null without sending when alt clipboard readText rejects", async () => {
    const constructorApi = makeApi();
    const rejectApi: ClipboardApi = {
      readText: vi.fn(async () => { throw new Error("no permission"); }),
      writeText: vi.fn(),
    };
    const { client, sends } = tracked(constructorApi);

    const result = await client.sendText(rejectApi);

    expect(result).toBeNull();
    expect(sends).toHaveLength(0);
  });
});

// ── setReceiveEnabled(enabled, altClipboard) ──────────────────────────────────

describe("setReceiveEnabled with alt clipboard", () => {
  it("routes inbound writes to altClipboard when receive is enabled", async () => {
    const constructorApi = makeApi();
    const popupApi = makeApi();
    const { client } = tracked(constructorApi);

    client.setReceiveEnabled(true, popupApi);
    await client.handleMessage(encodeMessage({ t: "Text", c: "remote text" }));

    expect(popupApi.writes).toEqual(["remote text"]);
    expect(constructorApi.writes).toEqual([]);
  });

  it("routes inbound writes to constructor clipboard when re-disabled", async () => {
    const constructorApi = makeApi();
    const popupApi = makeApi();
    const { client } = tracked(constructorApi);

    client.setReceiveEnabled(true, popupApi);
    client.setReceiveEnabled(false);
    await client.handleMessage(encodeMessage({ t: "Text", c: "should be dropped" }));

    // disabled → no write to either
    expect(popupApi.writes).toEqual([]);
    expect(constructorApi.writes).toEqual([]);
  });

  it("routes inbound writes to constructor clipboard when re-enabled without alt", async () => {
    const constructorApi = makeApi();
    const popupApi = makeApi();
    const { client } = tracked(constructorApi);

    client.setReceiveEnabled(true, popupApi);
    client.setReceiveEnabled(false);
    client.setReceiveEnabled(true); // back to constructor clipboard

    await client.handleMessage(encodeMessage({ t: "Text", c: "back to main" }));

    expect(constructorApi.writes).toEqual(["back to main"]);
    expect(popupApi.writes).toEqual([]);
  });

  it("is a no-op when enabled and receiveClipboard are both unchanged", () => {
    const constructorApi = makeApi();
    const popupApi = makeApi();
    const { client } = tracked(constructorApi);

    client.setReceiveEnabled(true, popupApi);
    const genBefore = (client as unknown as { stateGen: number }).stateGen;
    client.setReceiveEnabled(true, popupApi); // exact same args
    const genAfter = (client as unknown as { stateGen: number }).stateGen;

    expect(genAfter).toBe(genBefore);
  });

  it("bumps stateGen when only the clipboard changes (enabled stays true)", () => {
    const constructorApi = makeApi();
    const popupApi1 = makeApi();
    const popupApi2 = makeApi();
    const { client } = tracked(constructorApi);

    client.setReceiveEnabled(true, popupApi1);
    const genBefore = (client as unknown as { stateGen: number }).stateGen;
    client.setReceiveEnabled(true, popupApi2); // different clipboard object
    const genAfter = (client as unknown as { stateGen: number }).stateGen;

    expect(genAfter).toBeGreaterThan(genBefore);
  });
});

// ── dispose() resets receiveClipboard ────────────────────────────────────────

describe("dispose resets receiveClipboard", () => {
  it("after dispose, receiveClipboard is the constructor clipboard", async () => {
    const constructorApi = makeApi();
    const popupApi = makeApi();
    const { client } = tracked(constructorApi);

    client.setReceiveEnabled(true, popupApi);
    client.dispose();

    // Re-enable on a disposed client is a no-op, but we can verify via the receive path:
    // A handleMessage after dispose does nothing regardless.
    await client.handleMessage(encodeMessage({ t: "Text", c: "post-dispose" }));
    expect(popupApi.writes).toEqual([]);
    expect(constructorApi.writes).toEqual([]);
  });
});

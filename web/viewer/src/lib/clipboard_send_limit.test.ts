import { describe, it, expect } from "vitest";
import { ClipboardClient, MAX_CLIPBOARD_SEND_BYTES, type ClipboardApi } from "./clipboard";

// 10-28: the agent caps inbound clipboard text at 1 MiB, and until 1.3.15 it ENDED the session when a
// push went over. The console had no cap and pushes on focus, so a big copied log could end a session
// by clicking into the viewer. The console now refuses to send over the agent's limit and says why.
class FakeClipboard implements ClipboardApi {
  value = "";
  async readText(): Promise<string> {
    return this.value;
  }
  async writeText(t: string): Promise<void> {
    this.value = t;
  }
}

describe("ClipboardClient outbound size limit", () => {
  it("does not send text over the agent's 1 MiB limit, and says why", async () => {
    const fake = new FakeClipboard();
    const sent: Uint8Array[] = [];
    const client = new ClipboardClient((p) => sent.push(p), fake);

    fake.value = "x".repeat(MAX_CLIPBOARD_SEND_BYTES + 1);
    expect(await client.sendText()).toBeNull();
    expect(client.lastSendOutcome).toBe("too-large");
    expect(sent).toHaveLength(0);

    fake.value = "x".repeat(MAX_CLIPBOARD_SEND_BYTES);
    expect(await client.sendText()).toBe(fake.value);
    expect(client.lastSendOutcome).toBe("sent");
    expect(sent).toHaveLength(1);
  });

  it("measures UTF-8 bytes, not characters", async () => {
    const fake = new FakeClipboard();
    const sent: Uint8Array[] = [];
    const client = new ClipboardClient((p) => sent.push(p), fake);
    // 3 bytes per character in UTF-8: under the limit in characters, over it in bytes.
    fake.value = "€".repeat(Math.floor(MAX_CLIPBOARD_SEND_BYTES / 3) + 1);
    expect(await client.sendText()).toBeNull();
    expect(client.lastSendOutcome).toBe("too-large");
    expect(sent).toHaveLength(0);
  });

  it("a refused push does not mark the text as already sent", async () => {
    const fake = new FakeClipboard();
    const sent: Uint8Array[] = [];
    const client = new ClipboardClient((p) => sent.push(p), fake);
    fake.value = "x".repeat(MAX_CLIPBOARD_SEND_BYTES + 1);
    await client.sendText();
    await client.sendText();
    expect(client.lastSendOutcome).toBe("too-large");
  });

  it("matches the agent's limit", () => {
    expect(MAX_CLIPBOARD_SEND_BYTES).toBe(1024 * 1024);
  });
});

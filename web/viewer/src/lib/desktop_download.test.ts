import { describe, it, expect } from "vitest";
import { desktopDownload } from "./desktop_download";
const manifest = { version: "0.5.0", url: "https://main.deskrally.com/download/client/releases/0.5.0/DeskRallyClient.exe", sha256: "a".repeat(64), size: 431016 };
describe("desktop download", () => {
  it("keeps the shared release download on the visitor's origin", () => {
    expect(desktopDownload(manifest, "https://loam.deskrally.com")).toEqual({ version: "0.5.0", url: "/download/client/releases/0.5.0/DeskRallyClient.exe" });
  });
  for (const patch of [{ url: "https://evil.example/client.exe" }, { version: "../../agent" }, { sha256: "bad" }, { size: 0 }, { version: "01.2.3" }, { size: 1.2 }, { url: manifest.url + "?token=secret" }]) {
    it(`rejects malformed release metadata ${JSON.stringify(patch)}`, () => expect(desktopDownload({ ...manifest, ...patch }, "https://main.deskrally.com")).toBeNull());
  }
});

import { afterEach, expect, it, vi } from "vitest";
import { openPopout } from "./popout";

afterEach(() => vi.unstubAllGlobals());

// Successful child-document mounting, styles, input, and return-to-tab behavior are covered
// with real windows in e2e/viewer_chrome.spec.ts and e2e/popout_controls.spec.ts.
it("returns null when the browser blocks the popup, without requiring a child document", async () => {
  const open = vi.fn(() => null);
  vi.stubGlobal("window", { open });

  await expect(openPopout("Remote Desktop")).resolves.toBeNull();
  expect(open).toHaveBeenCalledOnce();
});

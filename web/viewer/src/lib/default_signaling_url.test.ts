import { describe, expect, it } from "vitest";

import { DEV_SIGNALING_URL, defaultSignalingUrl } from "./default_signaling_url";

const loc = (protocol: string, hostname: string, host = hostname) => ({ protocol, hostname, host });

describe("defaultSignalingUrl", () => {
  it("uses the page's own origin on a deployed console", () => {
    expect(
      defaultSignalingUrl(loc("https:", "main.deskrally.com")),
    ).toBe("wss://main.deskrally.com/ws");
  });

  it("keeps a non-default port, which is where a second deployment on one host lives", () => {
    expect(defaultSignalingUrl(loc("https:", "remote.example.com", "remote.example.com:8443"))).toBe(
      "wss://remote.example.com:8443/ws",
    );
  });

  // A console on http:// cannot open wss:// without a certificate for that host, and one on https://
  // cannot open ws:// at all — the browser blocks it as mixed content. The scheme has to follow.
  it("follows the page's scheme", () => {
    expect(defaultSignalingUrl(loc("http:", "internal.lan"))).toBe("ws://internal.lan/ws");
  });

  // THE REGRESSION GUARD. The e2e browses 127.0.0.1:5173 while signaling listens separately on
  // :8080, so deriving from the origin there would point every manual connect at the Vite dev
  // server. The one-origin assumption is a property of the Caddy deployment, not of the product.
  it("keeps the loopback default when served locally", () => {
    for (const h of ["localhost", "127.0.0.1", "::1"]) {
      expect(defaultSignalingUrl(loc("http:", h, `${h}:5173`)), `hostname ${h}`).toBe(DEV_SIGNALING_URL);
    }
  });
});

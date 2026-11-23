/**
 * Multi-machine (Tech-Many) unit tests.
 *
 * Exercises the URL-param parsing and new-tab URL construction used by the
 * "Open in new tab" feature and the App-level auto-connect on page load.
 *
 * The logic is in `lib/machine_url_params.ts` (pure functions, no React),
 * so these run in the vitest `node` environment without a DOM renderer.
 */

import { describe, it, expect } from "vitest";
import { parseMachineUrlParams, machineNewTabUrl, machineInviteUrl } from "./lib/machine_url_params";

const PROD_LOCATION = { protocol: "https:", hostname: "main.deskrally.com", host: "main.deskrally.com" };
const DEV_LOCATION = { protocol: "http:", hostname: "localhost", host: "localhost" };

const DEVICE_ID = "2b948dba-0000-4000-8000-000000000001";
const MACHINE_NAME = "the operator's Desktop";
const PROD_SIGNALING = "wss://main.deskrally.com/ws";
const DEV_SIGNALING = "ws://127.0.0.1:8080/ws";

describe("parseMachineUrlParams", () => {
  it("returns null when no device param", () => {
    expect(parseMachineUrlParams("", PROD_LOCATION)).toBeNull();
    expect(parseMachineUrlParams("?name=foo", PROD_LOCATION)).toBeNull();
    expect(parseMachineUrlParams("?signaling=wss://x/ws", PROD_LOCATION)).toBeNull();
  });

  it("parses full params on production location", () => {
    const search = `?device=${DEVICE_ID}&name=${encodeURIComponent(MACHINE_NAME)}&signaling=${encodeURIComponent(PROD_SIGNALING)}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result).not.toBeNull();
    expect(result!.device).toBe(DEVICE_ID);
    expect(result!.name).toBe(MACHINE_NAME);
    expect(result!.signalingUrl).toBe(PROD_SIGNALING);
  });

  it("derives signaling from location when param is absent (production)", () => {
    const search = `?device=${DEVICE_ID}&name=${encodeURIComponent(MACHINE_NAME)}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result!.signalingUrl).toBe(PROD_SIGNALING);
  });

  it("derives signaling from location when param is absent (dev)", () => {
    const search = `?device=${DEVICE_ID}&name=${encodeURIComponent(MACHINE_NAME)}`;
    const result = parseMachineUrlParams(search, DEV_LOCATION);
    expect(result!.signalingUrl).toBe(DEV_SIGNALING);
  });

  it("falls back to shortened device id when name is absent", () => {
    const search = `?device=${DEVICE_ID}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result!.name).toBe(`agent ${DEVICE_ID.slice(0, 8)}`);
  });

  it("accepts a signaling param that matches the expected host", () => {
    // Same host as the page — valid override (e.g. a custom path on the same server).
    const sameHost = "wss://main.deskrally.com/ws-alt";
    const search = `?device=${DEVICE_ID}&signaling=${encodeURIComponent(sameHost)}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result!.signalingUrl).toBe(sameHost);
  });
});

describe("parseMachineUrlParams — signaling URL security validation", () => {
  it("rejects an external signaling URL and falls back to the safe default", () => {
    // Attacker-controlled: ?signaling=wss://evil.example.com/ws must be silently ignored.
    const external = "wss://evil.example.com/ws";
    const search = `?device=${DEVICE_ID}&signaling=${encodeURIComponent(external)}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result!.signalingUrl).not.toBe(external);
    expect(result!.signalingUrl).toBe(PROD_SIGNALING);
  });

  it("rejects an http/https scheme (not a WebSocket protocol)", () => {
    const httpUrl = "https://main.deskrally.com/ws";
    const search = `?device=${DEVICE_ID}&signaling=${encodeURIComponent(httpUrl)}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result!.signalingUrl).toBe(PROD_SIGNALING);
  });

  it("rejects a malformed signaling URL and falls back to the safe default", () => {
    const search = `?device=${DEVICE_ID}&signaling=${encodeURIComponent("not-a-url")}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result!.signalingUrl).toBe(PROD_SIGNALING);
  });

  it("rejects an external URL even when device and name are present", () => {
    const search = `?device=${DEVICE_ID}&name=${encodeURIComponent(MACHINE_NAME)}&signaling=${encodeURIComponent("wss://attacker.com/ws")}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result!.device).toBe(DEVICE_ID);      // device still parsed
    expect(result!.name).toBe(MACHINE_NAME);      // name still parsed
    expect(result!.signalingUrl).toBe(PROD_SIGNALING); // signaling falls back to safe default
  });

  it("accepts the dev signaling URL on dev location (same host)", () => {
    // Dev: signaling is at 127.0.0.1:8080, same host as the derived default.
    const search = `?device=${DEVICE_ID}&signaling=${encodeURIComponent(DEV_SIGNALING)}`;
    const result = parseMachineUrlParams(search, DEV_LOCATION);
    expect(result!.signalingUrl).toBe(DEV_SIGNALING);
  });

  it("rejects a cross-port URL (different host identity than the default)", () => {
    // Ports are part of the host in URL terms; a different port means a different origin.
    const differentPort = "wss://main.deskrally.com:8765/ws";
    const search = `?device=${DEVICE_ID}&signaling=${encodeURIComponent(differentPort)}`;
    const result = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result!.signalingUrl).toBe(PROD_SIGNALING);
  });

  it("round-trip from machineNewTabUrl always passes validation (same host)", () => {
    // The URLs produced by machineNewTabUrl use the same signaling URL as the source page,
    // which by construction is the same host as the derived default. They must always pass.
    const url = machineNewTabUrl(DEVICE_ID, MACHINE_NAME, PROD_SIGNALING, "https://main.deskrally.com");
    const parsed = new URL(url);
    const result = parseMachineUrlParams(parsed.search, PROD_LOCATION);
    expect(result!.signalingUrl).toBe(PROD_SIGNALING);
  });
});

describe("machineNewTabUrl", () => {
  it("encodes device, name and signaling into a /console URL", () => {
    const url = machineNewTabUrl(DEVICE_ID, MACHINE_NAME, PROD_SIGNALING, "https://main.deskrally.com");
    const parsed = new URL(url);
    expect(parsed.searchParams.get("device")).toBe(DEVICE_ID);
    expect(parsed.searchParams.get("name")).toBe(MACHINE_NAME);
    expect(parsed.searchParams.get("signaling")).toBe(PROD_SIGNALING);
    expect(parsed.origin).toBe("https://main.deskrally.com");
    // Must target /console so that auth-required renders the technician login form,
    // not the customer-facing JoinPage (which App.tsx renders at the root path).
    expect(parsed.pathname).toBe("/console");
  });

  it("targets /console so that login-required shows technician form, not JoinPage", () => {
    const url = machineNewTabUrl(DEVICE_ID, MACHINE_NAME, PROD_SIGNALING, "https://main.deskrally.com");
    const parsed = new URL(url);
    expect(parsed.pathname).toBe("/console");
  });

  it("keeps the same origin as the page", () => {
    const url = machineNewTabUrl(DEVICE_ID, MACHINE_NAME, DEV_SIGNALING, "http://localhost:5173");
    expect(url.startsWith("http://localhost:5173/")).toBe(true);
    expect(new URL(url).pathname).toBe("/console");
  });

  it("round-trips through parseMachineUrlParams", () => {
    const url = machineNewTabUrl(DEVICE_ID, MACHINE_NAME, PROD_SIGNALING, "https://main.deskrally.com");
    const parsed = new URL(url);
    const result = parseMachineUrlParams(parsed.search, PROD_LOCATION);
    expect(result!.device).toBe(DEVICE_ID);
    expect(result!.name).toBe(MACHINE_NAME);
    expect(result!.signalingUrl).toBe(PROD_SIGNALING);
  });

  it("handles machine names with special characters", () => {
    const name = "the operator's Desktop & dual-homed laptop #1";
    const url = machineNewTabUrl(DEVICE_ID, name, PROD_SIGNALING, "https://main.deskrally.com");
    const parsed = new URL(url);
    const result = parseMachineUrlParams(parsed.search, PROD_LOCATION);
    expect(result!.name).toBe(name);
  });
});

describe("multi-machine lifecycle isolation", () => {
  it("two tabs parsing the same URL params produce independent sessions (no shared state)", () => {
    // Each browser tab is its own JS context. This test verifies the parsing is stateless
    // (pure functions produce the same result twice) — the isolation property comes from the
    // browser, but we confirm the function is idempotent.
    const search = `?device=${DEVICE_ID}&name=${encodeURIComponent(MACHINE_NAME)}&signaling=${encodeURIComponent(PROD_SIGNALING)}`;
    const result1 = parseMachineUrlParams(search, PROD_LOCATION);
    const result2 = parseMachineUrlParams(search, PROD_LOCATION);
    expect(result1).toEqual(result2);
    // Mutating one result does not affect the other (plain objects)
    result1!.name = "mutated";
    expect(result2!.name).toBe(MACHINE_NAME);
  });
});

describe("invite links (docs/01 §7: invite a participant)", () => {
  const loc = { protocol: "https:", hostname: "main.deskrally.com", host: "main.deskrally.com" };
  const dev = "2b948dba-0000-4000-8000-000000000001";

  it("a watch invite round-trips to a view-only connect", () => {
    const url = new URL(machineInviteUrl(dev, "https://main.deskrally.com", true));
    expect(url.pathname).toBe("/console");
    const parsed = parseMachineUrlParams(url.search, loc);
    expect(parsed?.device).toBe(dev);
    expect(parsed?.observe).toBe(true);
  });

  it("a control invite does not observe", () => {
    const url = new URL(machineInviteUrl(dev, "https://main.deskrally.com", false));
    expect(url.searchParams.has("observe")).toBe(false);
    expect(parseMachineUrlParams(url.search, loc)?.observe).toBe(false);
  });

  it("carries only the device: no name, no signaling URL", () => {
    const url = new URL(machineInviteUrl(dev, "https://main.deskrally.com", true));
    expect([...url.searchParams.keys()].sort()).toEqual(["device", "observe"]);
  });

  it("only observe=1 means observe", () => {
    expect(parseMachineUrlParams(`?device=${dev}&observe=true`, loc)?.observe).toBe(false);
    expect(parseMachineUrlParams(`?device=${dev}`, loc)?.observe).toBe(false);
  });
});

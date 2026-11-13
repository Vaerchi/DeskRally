import { describe, it, expect } from "vitest";
import { desktopLink, desktopMinVersion, tenantFromOrigin, defaultDesktopPreference, isDesktopClient, attendedLaunchId, desktopClientLacksSso, desktopClientPromptsEveryClipboardRead } from "./desktop_launch";
const id = "00112233-4455-6677-8899-aabbccddeeff";
describe("desktop launch", () => {
  it("passes only a validated ID, never credentials or an arbitrary URL", () => {
    expect(desktopLink({kind:"connect",id},"https://main.deskrally.com")).toBe(`deskrally-client://connect/${id}`);
    expect(desktopLink({kind:"attended",id},"https://main.deskrally.com")).toBe(`deskrally-client://attended/${id}`);
    for (const invalid of ["", id+"?token=secret", id+"#secret", id+"/", "%22", "https://evil.example", id+"\n"]) {
      expect(desktopLink({kind:"connect",id:invalid},"https://loam.deskrally.com")).toBeNull();
    }
  });
  it("routes any tenant origin to its own slug and rejects every other origin instead of falling back to Main", () => {
    for (const kind of ["connect","attended"] as const) {
      expect(desktopLink({kind,id:id.toUpperCase()},"https://loam.deskrally.com")).toBe(`deskrally-client://tenant/loam/${kind}/${id}`);
      expect(desktopLink({kind,id},"https://vc.deskrally.com")).toBe(`deskrally-client://tenant/vc/${kind}/${id}`);
      expect(desktopLink({kind,id},"https://acme-2.deskrally.com")).toBe(`deskrally-client://tenant/acme-2/${kind}/${id}`);
      for (const origin of ["https://evil.example", "http://loam.deskrally.com", "https://loam.deskrally.com.evil.test", "https://evil.loam.deskrally.com", "https://loam.deskrally.com:8443", "https://user@loam.deskrally.com", "https://loam.deskrally.com/path", "https://loam.deskrally.com?secret=token", "http://127.0.0.1:5173", "",
        "https://deskrally.com", "https://www.deskrally.com", "https://turn.deskrally.com", "https://api.deskrally.com", "https://updater.deskrally.com", "https://-x.deskrally.com", "https://x-.deskrally.com", "https://a_b.deskrally.com", "https://LOAM.deskrally.com", `https://${"a".repeat(64)}.deskrally.com`]) {
        expect(desktopLink({kind,id},origin)).toBeNull();
      }
    }
    expect(desktopLink({kind:"connect",id},`https://${"a".repeat(63)}.deskrally.com`)).toBe(`deskrally-client://tenant/${"a".repeat(63)}/connect/${id}`);
  });
  it("names the any-tenant app version only away from the main tenant", () => {
    expect(desktopMinVersion("https://main.deskrally.com")).toBeNull();
    expect(desktopMinVersion("https://loam.deskrally.com")).toBe("0.6.0");
    expect(desktopMinVersion("https://vc.deskrally.com")).toBe("0.6.0");
    expect(desktopMinVersion("https://evil.example")).toBeNull();
    expect(tenantFromOrigin("https://vc.deskrally.com")).toBe("vc");
    expect(tenantFromOrigin("https://www.deskrally.com")).toBeNull();
  });
  it("defaults Windows browsers to the app but respects browser fallback", () => {
    const hosted = "https://main.deskrally.com";
    expect(defaultDesktopPreference(null,"Windows NT 10.0 Chrome",hosted)).toBe(true);
    expect(defaultDesktopPreference(null,"Windows NT 10.0 Chrome","https://loam.deskrally.com")).toBe(true);
    expect(defaultDesktopPreference("browser","Windows NT 10.0",hosted)).toBe(false);
    expect(defaultDesktopPreference(null,"Android",hosted)).toBe(false);
    expect(defaultDesktopPreference(null,"Windows DeskRallyDesktop/0.2.0",hosted)).toBe(false);
  });
  it("defaults a self-hosted console to the browser, where no desktop link can exist (2026-11-10)", () => {
    // A first Connect on a self-hosted server must not try the app and fail with "cannot open in the desktop app".
    for (const origin of ["https://main.deskrally.internal","https://remote.example.com","https://deskrally.com.evil.example","http://127.0.0.1:5173"]) {
      expect(defaultDesktopPreference(null,"Windows NT 10.0 Chrome",origin)).toBe(false);
    }
    // An explicit choice is still the operator's own (the click then explains why the app cannot open here).
    expect(defaultDesktopPreference("desktop","Windows NT 10.0 Chrome","https://remote.example.com")).toBe(true);
    expect(isDesktopClient("Windows DeskRallyDesktop/0.2.0")).toBe(true);
  });
  it("only accepts an attended UUID", () => {
    expect(attendedLaunchId(`?attended=${id}`)).toBe(id);
    expect(attendedLaunchId("?attended=unknown")).toBeNull();
    expect(attendedLaunchId("")).toBeNull();
  });
});

describe("desktopClientLacksSso (Microsoft sign-in in the app)", () => {
  const base = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130 Edg/130";
  it("is false in a browser", () => {
    expect(desktopClientLacksSso(base)).toBe(false);
  });
  it("is true in a desktop app without the SSO token (before 0.8.0)", () => {
    expect(desktopClientLacksSso(`${base} DeskRallyDesktop/0.7.0`)).toBe(true);
    expect(desktopClientLacksSso(`${base} DeskRallyDesktop/0.7.0 DeskRallyHello/1`)).toBe(true);
  });
  it("is false once the app advertises DeskRallySSO/1", () => {
    expect(desktopClientLacksSso(`${base} DeskRallyDesktop/0.8.0 DeskRallySSO/1`)).toBe(false);
    expect(desktopClientLacksSso(`${base} DeskRallyDesktop/0.8.0 DeskRallyHello/1 DeskRallySSO/1`)).toBe(false);
  });
  it("needs the exact token, not a look-alike", () => {
    expect(desktopClientLacksSso(`${base} DeskRallyDesktop/0.8.0 DeskRallySSO/10`)).toBe(true);
    expect(desktopClientLacksSso(`${base} DeskRallyDesktop/0.8.0 XDeskRallySSO/1`)).toBe(true);
  });
});

describe("desktopClientPromptsEveryClipboardRead (automatic clipboard send)", () => {
  const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36 Edg/141.0";
  it("a browser never prompts per read", () => expect(desktopClientPromptsEveryClipboardRead(chrome)).toBe(false));
  it("an app without the capability prompts per read", () =>
    expect(desktopClientPromptsEveryClipboardRead(`${chrome} DeskRallyDesktop/0.8.2 DeskRallySSO/1`)).toBe(true));
  it("an app advertising DeskRallyClipAuto/1 does not", () =>
    expect(desktopClientPromptsEveryClipboardRead(`${chrome} DeskRallyDesktop/0.8.3 DeskRallySSO/1 DeskRallyClipAuto/1`)).toBe(false));
  it("only the exact token counts", () =>
    expect(desktopClientPromptsEveryClipboardRead(`${chrome} DeskRallyDesktop/0.8.3 DeskRallyClipAuto/10`)).toBe(true));
});

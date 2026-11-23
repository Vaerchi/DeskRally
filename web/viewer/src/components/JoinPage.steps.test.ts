// The Join page's steps (menu-review 2026-11-07, then the 2026-11-13 first-time-customer fix): code first, then the
// download, then approval. Every config combination (bundle on/off x plain download on/off) is covered here; the
// browser behaviour (Continue moves focus, the launch link) is in e2e/join_flow.spec.ts.
import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { JoinPage } from "./JoinPage";

const CODE = "0123456789ABC";
const SHORT = "ABCD2345";
const download = { url: "/download/DeskRallySupport.exe", sha256: "ab".repeat(32) };
const render = (props: Record<string, unknown>) =>
  renderToStaticMarkup(createElement(JoinPage, { origin: "https://support.example", platform: "windows", code: CODE, ...props } as never));
const count = (html: string, needle: string) => html.split(needle).length - 1;
const headings = (html: string) => [...html.matchAll(/<h2[^>]*join__stephead[^>]*>(.*?)<\/h2>/g)].map((m) => m[1].replace(/<[^>]+>/g, "").trim());

describe("steps run: code, client, approval", () => {
  it("lists the three steps in order", () => {
    expect(headings(render({ download }))).toEqual([
      "1 Enter your session code", "2 Get the DeskRally support client", "3 Approve screen sharing",
    ]);
  });
  it("the code button is honest (Continue) and the code form comes before the download", () => {
    const html = render({ download });
    expect(html).toMatch(/<button class="join__action" type="submit"[^>]*>Continue<\/button>/);
    expect(html).not.toContain("Join a support session");
    expect(html.indexOf('id="support-session-code"')).toBeLessThan(html.indexOf('data-testid="join-download-link"'));
  });
  it("step 2 is a focus target and, with a code, the highlighted next action", () => {
    const html = render({ download });
    expect(html).toMatch(/<h2 id="join-step2"[^>]*tabindex="-1"/);
    expect(html).toContain("join__step--active");
  });
});

describe("production shape: plain download ON, bundle OFF", () => {
  const html = render({ download });
  it("the primary button is the plain download, labelled Download support client", () => {
    expect(html).toMatch(/class="join__downloadbtn"[^>]*data-testid="join-download-link"[^>]*href="\/download\/DeskRallySupport.exe"[^>]*>Download support client</);
    expect(html).not.toContain('data-testid="join-bundle');
  });
  it("shows the code large and copyable with the one-line instruction", () => {
    expect(html).toContain("enter this code");
    expect(html).toMatch(/When <bdi[^>]*>DeskRally<\/bdi> Support opens, enter this code/);
    expect(html).toMatch(/join__code join__code--big" data-testid="join-code" data-code="0123456789ABC">0123-4567-89AB-C</);
    expect(html).toContain('data-testid="join-copy-code"');
  });
  it("keeps the sha256 read-back and the warnings", () => {
    expect(html).toContain('data-testid="join-sha256"');
    expect(html).toContain("ab".repeat(32));
    expect(html).toContain("If Windows or your browser gets in the way");
    expect(html).toContain("stop and read the exact message to your technician");
  });
  it("does not depend on the bundle: nothing about a bundle is said", () => {
    expect(html).not.toContain("No code to type");
    expect(html).not.toContain("bundle");
  });
});

describe("bundle ON (a legacy-mode answer from the server)", () => {
  // Server-side renders show the state before the support-mode answer: pending withholds the plain exe.
  it("pending: the bundle button leads and the plain exe is withheld", () => {
    const html = render({ download, bundleEnabled: true });
    expect(html).toMatch(/data-testid="join-bundle-btn"[^>]*>Download support client</);
    expect(html).toContain('data-testid="join-bundle-step"');
    expect(html).toContain("No code to type");
    expect(html).not.toContain('data-testid="join-download-link"');
    expect(html).not.toContain('data-testid="join-sha256"');
    expect(html).toMatch(/If the <bdi[^>]*>DeskRally<\/bdi> client asks for a code, enter this one/);
  });
  it("works with the plain download OFF (no build-time URL): the bundle still appears", () => {
    const html = render({ bundleEnabled: true });
    expect(html).toContain('data-testid="join-bundle-btn"');
    expect(html).not.toContain('data-testid="join-download-link"');
    expect(html).not.toContain('data-testid="join-download-unavailable"');
  });
  it("without a code there is no bundle button, only the ask", () => {
    const html = render({ download, bundleEnabled: true, code: "" });
    expect(html).not.toContain('data-testid="join-bundle-btn"');
    expect(html).toContain('data-testid="join-needs-code"');
  });
});

describe("bundle OFF and plain download OFF", () => {
  const html = render({});
  it("says no download is offered, still shows the code, and points at the command line", () => {
    expect(html).toContain('data-testid="join-download-unavailable"');
    expect(html).not.toContain('data-testid="join-download-link"');
    expect(html).toContain('data-testid="join-code"');
    expect(html).toContain("agent_host attend --code 0123456789ABC");
  });
  it("offers no warnings list for a download that is not there", () => {
    expect(html).not.toContain("If Windows or your browser gets in the way");
  });
});

describe("no code yet", () => {
  for (const [label, props] of [["plain", { download }], ["bundle", { download, bundleEnabled: true }], ["none", {}]] as const) {
    it(`${label}: step 2 waits for the code and shows no download, code or launch link`, () => {
      const html = render({ ...props, code: "" });
      expect(html).toContain('data-testid="join-no-code"');
      expect(html).toContain('data-testid="join-needs-code"');
      expect(html).toContain("join__step--waiting");
      for (const id of ["join-download-link", "join-bundle-btn", "join-code", "join-launch", "join-copy-code"]) {
        expect(html).not.toContain(`data-testid="${id}"`);
      }
    });
  }
});

describe("platform", () => {
  it("a non-Windows visitor is told, with or without the bundle, and gets no download", () => {
    for (const bundleEnabled of [false, true]) {
      const html = render({ download, platform: "other", bundleEnabled });
      expect(html).toContain('data-testid="join-unsupported"');
      expect(html).not.toContain('data-testid="join-download-link"');
      expect(html).not.toContain('data-testid="join-bundle-btn"');
    }
  });
});

describe("the launch link is demoted", () => {
  for (const [label, props] of [["plain", { download }], ["bundle", { download, bundleEnabled: true }], ["none", {}]] as const) {
    it(`${label}: one quiet link in step 2, after the primary action, never a button, relabelled`, () => {
      const html = render({ ...props, code: SHORT });
      expect(count(html, 'data-testid="join-launch"')).toBe(1);
      expect(html).toMatch(/<a class="join__downloadlink" data-testid="join-launch" href="rmt-[0-9a-f]{16}:\/\/attend\?code=ABCD2345/);
      expect(html).toContain("Open it with this code");
      expect(html).toMatch(/Already have <bdi[^>]*>DeskRally<\/bdi> Support open or installed\?/);
      expect(html).not.toMatch(/class="join__action"[^>]*data-testid="join-launch"/);
      expect(html).not.toContain("Open the <bdi");
      const launch = html.indexOf('data-testid="join-launch"');
      const primary = Math.max(html.indexOf('data-testid="join-download-link"'), html.indexOf('data-testid="join-bundle-btn"'));
      expect(launch).toBeGreaterThan(primary);
      expect(launch).toBeLessThan(html.indexOf('id="join-step3"'));
      expect(html.slice(html.indexOf('data-testid="join-advanced"'))).not.toContain('data-testid="join-launch"');
    });
  }
  it("says the browser cannot tell whether it opened", () => {
    expect(render({ download })).toContain("If nothing happens, use the download above.");
  });
});

describe("platform note is independent of the download configuration (review r1)", () => {
  for (const [label, props] of [["bundle on, plain off", { bundleEnabled: true }], ["bundle off, plain off", {}], ["bundle on, plain on", { download, bundleEnabled: true }]] as const) {
    it(`${label}: a non-Windows visitor gets the Windows-only note, no bundle and no 'not offered' note`, () => {
      const html = render({ ...props, platform: "other" });
      expect(html).toContain('data-testid="join-unsupported"');
      expect(html).not.toContain('data-testid="join-bundle-btn"');
      expect(html).not.toContain('data-testid="join-download-unavailable"');
    });
  }
});

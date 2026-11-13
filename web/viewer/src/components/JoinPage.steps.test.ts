// Menu wave 11 (menu-review 2026-11-07, "Repair guest entry points"): the Join page says one thing per action and its
// steps match the download the guest actually gets.
import { expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { JoinPage } from "./JoinPage";

const base = { origin: "https://support.example", platform: "windows" as const, download: { url: "/download/DeskRallySupport.exe" } };
const count = (html: string, needle: string) => html.split(needle).length - 1;

it("with the session bundle, step 2 says the code is already inside and both downloads share one name", () => {
  const html = renderToStaticMarkup(createElement(JoinPage, { ...base, code: "0123456789ABC", bundleEnabled: true }));
  expect(html).toContain('data-testid="join-bundle-btn"');
  expect(html).toMatch(/data-testid="join-bundle-btn"[^>]*>Download support client</);
  expect(html).toContain('data-testid="join-bundle-step"');
  expect(html).toMatch(/<\/span> Open the client<\/h2>/);
  expect(html).not.toContain("Download session bundle");
});

it("without the bundle, step 2 asks for the code and there is no bundle sentence", () => {
  const html = renderToStaticMarkup(createElement(JoinPage, { ...base, code: "0123456789ABC" }));
  expect(html).toMatch(/data-testid="join-download-link"[^>]*>Download support client</);
  expect(html).not.toContain('data-testid="join-bundle-step"');
  expect(html).toContain("Open the client and enter your code");
});

it("the code button is honest (Continue) and there is exactly one launch link, in step 2, not under Advanced", () => {
  const html = renderToStaticMarkup(createElement(JoinPage, { ...base, code: "0123456789ABC" }));
  expect(html).toMatch(/<button class="join__action" type="submit">Continue<\/button>/);
  expect(html).not.toContain("Join a support session");
  expect(html).not.toContain("Open installed support agent");
  expect(count(html, 'data-testid="join-launch"')).toBe(1);
  const advanced = html.slice(html.indexOf('data-testid="join-advanced"'));
  expect(advanced).not.toContain('data-testid="join-launch"');
  expect(html.indexOf('data-testid="join-launch"')).toBeLessThan(html.indexOf('id="join-step3"'));
});

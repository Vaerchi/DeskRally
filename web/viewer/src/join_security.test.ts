import { expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { JoinPage } from "./components/JoinPage";

it("does not offer an executable command or launch link for an invalid public fragment", () => {
  for (const code of ["ABC;whoami", "ABC&whoami", "0123456789ABC\n", "$(whoami)"]) {
    const html = renderToStaticMarkup(createElement(JoinPage, { code, origin: "https://support.example", platform: "windows" }));
    expect(html).not.toContain("whoami");
    expect(html).toContain("&lt;CODE&gt;");
    expect(html).not.toContain('data-testid="join-launch"');
    expect(html).toMatch(/data-testid="join-copy"[^>]*disabled/);
  }
});
it("still offers the command for a valid issued code", () => {
  const html = renderToStaticMarkup(createElement(JoinPage, { code: "0123456789ABC", origin: "https://support.example", platform: "windows" }));
  expect(html).toContain("agent_host attend --code 0123456789ABC");
  expect(html).toContain('data-testid="join-launch"');
});

import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { LocalFolderPane } from "./LocalFolderPane";

describe("LocalFolderPane (docs/77)", () => {
  it("with folder access, starts by offering to choose a folder", () => {
    const html = renderToStaticMarkup(<LocalFolderPane folderAccess onSend={vi.fn()} />);
    expect(html).toContain('data-testid="local-choose"');
    expect(html).toContain("Choose a folder");
    expect(html).not.toContain('data-testid="local-pick-files"');
  });

  it("without folder access, explains why and offers a file picker for Send", () => {
    const html = renderToStaticMarkup(<LocalFolderPane folderAccess={false} onSend={vi.fn()} />);
    expect(html).toContain("cannot open a folder");
    expect(html).toContain('data-testid="local-pick-files"');
    expect(html).not.toContain('data-testid="local-choose"');
  });

  it("offers no Send without permission to send", () => {
    const html = renderToStaticMarkup(<LocalFolderPane folderAccess={false} />);
    expect(html).not.toContain('data-testid="local-pick-files"');
  });
});

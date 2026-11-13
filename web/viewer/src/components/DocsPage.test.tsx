import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { GuideBody } from "./DocsPage";
import nativeGuide from "../../../../docs/guides/native-server.md?raw";

describe("public deployment guide rendering", () => {
  it("renders commands literally and never interprets HTML or unsafe links", () => {
    const html = renderToStaticMarkup(<GuideBody source={'# Install\n\n<script>alert(1)</script>\n\n[bad](javascript:alert)\n\n```sh\necho "$VALUE" <file>\n```\n\n[Services](https://caddyserver.com/docs/running)'} />);
    expect(html).not.toContain("<script>");
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain('&lt;file&gt;');
    expect(html).toContain('<pre><code>');
    expect(html).toContain('href="https://caddyserver.com/docs/running"');
  });
  it("renders the canonical native guide with commands and navigable headings", () => {
    const html = renderToStaticMarkup(<GuideBody source={nativeGuide} />);
    expect(html).toContain('id="recording-storage-and-key-rotation"');
    expect(html).toContain("DIRECTIVE_SIGNING_SEED");
    expect(html).toContain("MIGRATE_DATABASE_URL");
    expect(html).toContain("RECORDING_MASTER_KEY_PREVIOUS");
    expect(html).toContain('<pre><code>');
  });
});

import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { DocsPage, GuideBody } from "../components/DocsPage";
import { PUBLIC_DOCS, docHeadings, findPublicDoc, resolveDocLink } from "./public_docs";
import deployment from "../../../../docs/10-deployment.md?raw";
import backups from "../../../../docs/22-backup-and-restore.md?raw";
import template from "../../../../deploy/.env.example?raw";

describe("public technical documentation", () => {
  it("publishes full reference sources and the real environment template", () => {
    expect(findPublicDoc("deployment")?.text).toBe(deployment);
    expect(findPublicDoc("backups")?.text).toBe(backups);
    expect(findPublicDoc("configuration")?.text).toContain(template);
    expect(new Set(PUBLIC_DOCS.map(doc => doc.id)).size).toBe(PUBLIC_DOCS.length);
  });

  it("resolves repository-relative Markdown links and preserves section anchors", () => {
    expect(resolveDocLink("server-deployment.md", "docs/guides/client-deployment.md")).toBe("/docs/docker");
    expect(resolveDocLink("../22-backup-and-restore.md#7-encryption-and-key-management", "docs/guides/server-deployment.md"))
      .toBe("/docs/backups#7-encryption-and-key-management");
    const html = renderToStaticMarkup(<GuideBody source="[Backup runbook](../22-backup-and-restore.md)" sourcePath="docs/guides/server-deployment.md" />);
    expect(html).toContain('href="/docs/backups"');
    const prose = renderToStaticMarkup(<GuideBody source="Use https://remote.example.com, then continue." />);
    expect(prose).toContain('href="https://remote.example.com"');
    expect(prose).not.toContain('href="https://remote.example.com,"');
  });

  it("never exposes unlisted internal documents or unsafe link schemes", () => {
    for (const href of ["../07-session-handoff.md", "../23-security-audit-loop96.md", "javascript:alert(1)", "data:text/html,hello", "//other.example/docs"])
      expect(resolveDocLink(href, "docs/guides/server-deployment.md")).toBeNull();
  });

  it("provides a working destination and heading for every published local Markdown link", () => {
    for (const doc of PUBLIC_DOCS) {
      let fenced = false;
      const prose = doc.text.split(/\r?\n/).filter(line => {
        if (/^\s*```/.test(line)) { fenced = !fenced; return false; }
        return !fenced;
      }).join("\n");
      for (const match of prose.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
        const href = match[1];
        if (/^https:\/\//.test(href)) continue;
        const resolved = resolveDocLink(href, doc.source);
        expect(resolved, `${doc.source}: ${href}`).not.toBeNull();
        if (!resolved) continue;
        const url = new URL(resolved, `https://docs.invalid/docs/${doc.id}`);
        if (!url.pathname.startsWith("/docs/")) continue;
        const destination = findPublicDoc(url.pathname.split("/")[2]);
        expect(destination, `${doc.source}: ${href}`).toBeDefined();
        if (url.hash && destination)
          expect(docHeadings(destination.text).map(h => h.id), `${doc.source}: ${href}`).toContain(decodeURIComponent(url.hash.slice(1)));
      }
    }
  });

  it("keeps shell comments out of the contents and assigns unique duplicate anchors", () => {
    const source = "# Title\n\n## Repeat\n\n```sh\n## not a heading\n```\n\n## Repeat\n";
    expect(docHeadings(source).map(h => h.id)).toEqual(["title", "repeat", "repeat-1"]);
    const html = renderToStaticMarkup(<GuideBody source={source} />);
    expect(html).toContain('id="repeat-1"');
    expect(html).not.toContain('id="not-a-heading"');
  });

  it("makes the detailed references discoverable from the index and installation articles", () => {
    const index = renderToStaticMarkup(<DocsPage pathname="/docs" />);
    for (const id of ["deployment", "configuration", "backups", "troubleshooting"])
      expect(index).toContain(`href="/docs/${id}"`);
    const installation = renderToStaticMarkup(<DocsPage pathname="/docs/clients" />);
    expect(installation).toContain('href="/docs/deployment#4a-enrollment-and-agent-identity-m3"');
    expect(installation).toContain('href="/docs/backups"');
    const missing = renderToStaticMarkup(<DocsPage pathname="/docs/unknown" />);
    expect(missing).toContain("Document not found");
    expect(missing).not.toContain("Run DeskRally without Docker");
  });
});

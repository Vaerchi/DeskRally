import { useMemo } from "react";
import type { ReactNode } from "react";
import { RallyMark } from "./RallyIdentity";
import { PUBLIC_DOCS, docHeadings, findPublicDoc, resolveDocLink } from "../lib/public_docs";
import "./DocsPage.css";

// Deliberately a small, text-only Markdown renderer. Source docs remain the single source of
// truth; raw HTML is never interpreted and links only allow HTTPS, relative paths or anchors.
function inline(text: string, source: string): ReactNode[] {
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\)|https:\/\/[^\s<>]+)/g).map((part, i) => {
    if (part.startsWith("`")) return <code key={i}>{part.slice(1, -1)}</code>;
    if (part.startsWith("**")) return <strong key={i}>{part.slice(2, -2)}</strong>;
    const link = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(part);
    const href = link?.[2] ?? (part.startsWith("https://") ? part.replace(/[.,;:!?]+$/, "") : null);
    const resolved = href ? resolveDocLink(href, source) : null;
    if (resolved) return <span key={i}><a href={resolved}>{link?.[1] ?? href}</a>{!link && href ? part.slice(href.length) : ""}</span>;
    if (link) return <span key={i}>{link[1]}</span>;
    return part;
  });
}
export function GuideBody({ source, sourcePath = "docs/guides/native-server.md" }: { source: string; sourcePath?: string }) {
  const lines = source.replace(/\r/g, "").split("\n");
  const blocks: ReactNode[] = [];
  const headings = new Map(docHeadings(source).map(heading => [heading.line, heading]));
  const renderInline = (text: string) => inline(text, sourcePath);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (/^-{3,}$/.test(line.trim())) { blocks.push(<hr key={i} />); i++; continue; }
    if (/^\s*```/.test(line)) {
      const code: string[] = []; i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) code.push(lines[i++]);
      i++;
      blocks.push(<pre key={i}><code>{code.join("\n")}</code></pre>);
      continue;
    }
    const heading = headings.get(i);
    if (heading) {
      const Tag = `h${heading.level}` as "h1" | "h2" | "h3" | "h4" | "h5" | "h6";
      blocks.push(<Tag id={heading.id} key={i}>{renderInline(heading.title)}</Tag>); i++; continue;
    }
    if (/^\|/.test(line)) {
      const rows: string[][] = [];
      while (i < lines.length && /^\|/.test(lines[i])) {
        const cells = lines[i++].replace(/^\||\|$/g, "").split("|").map(s => s.trim());
        if (!cells.every(s => /^:?-+:?$/.test(s))) rows.push(cells);
      }
      blocks.push(<div className="docs__table" key={i}><table><thead><tr>{rows[0]?.map((cell, j) => <th key={j}>{renderInline(cell)}</th>)}</tr></thead>
        <tbody>{rows.slice(1).map((row, j) => <tr key={j}>{row.map((cell, k) => <td key={k}>{renderInline(cell)}</td>)}</tr>)}</tbody></table></div>);
      continue;
    }
    if (/^\s*[-*] /.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*] /.test(lines[i])) items.push(lines[i++].replace(/^\s*[-*] /, ""));
      blocks.push(<ul key={i}>{items.map((item, j) => <li key={j}>{renderInline(item)}</li>)}</ul>); continue;
    }
    if (/^\d+\. /.test(line)) {
      blocks.push(<p key={i}>{renderInline(line)}</p>); i++; continue;
    }
    const paragraph = [line.replace(/^>\s?/, "")]; i++;
    while (i < lines.length && lines[i].trim() && !/^\s*(```|#{1,6} |[-*] |\d+\. |\|)/.test(lines[i])) paragraph.push(lines[i++].replace(/^>\s?/, ""));
    blocks.push(<p key={i}>{renderInline(paragraph.join(" "))}</p>);
  }
  return <>{blocks}</>;
}

export function DocsPage({ pathname = window.location.pathname }: { pathname?: string }) {
  const key = pathname.split("/")[2] ?? "";
  const guide = findPublicDoc(key);
  const headings = useMemo(() => guide ? docHeadings(guide.text).filter(h => h.level === 2 || h.level === 3) : [], [guide]);
  return <div className="docs">
    <header className="join__topbar">
      <a className="join__brand" href="/"><RallyMark />DeskRally</a>
      <span className="join__brandby">Documentation</span>
      <a href="/downloads">Downloads</a>
      <a className="join__signin" href="/console">Technician sign in</a>
    </header>
    <div className="docs__layout">
      <aside className="docs__sidebar">
        <p className="docs__eyebrow">SELF-HOST DESKRALLY</p>
        <h2>Deployment<br />documentation</h2>
        <p>Installation steps, full technical references and operating runbooks.</p>
        <a href="/docs" aria-current={!key ? "page" : undefined}>Documentation index</a>
        <nav aria-label="Documentation guides">
          {(["Installation guides", "Technical reference"] as const).map(group => <section key={group}>
            <h3>{group}</h3>
            {PUBLIC_DOCS.filter(doc => doc.group === group).map(doc => <a key={doc.id} href={`/docs/${doc.id}`} aria-current={doc.id === key ? "page" : undefined}>{doc.title}</a>)}
          </section>)}
        </nav>
        <p className="docs__status">Native deployment is in preview. Docker remains the established release path.</p>
        <nav aria-label="On this page">
          <h3>On this page</h3>
          {headings.map(h => <a className={h.level === 3 ? "docs__subheading" : undefined} key={h.id} href={`#${h.id}`}>{h.title}</a>)}
        </nav>
      </aside>
      <main className="docs__article" key={key}>
        {guide ? <>
          <p className="docs__eyebrow">{guide.group} / {guide.id === "native" ? "NATIVE PREVIEW" : guide.title}</p>
          <p className="docs__source">Repository source: <code>{guide.source}</code>. This page includes the full reference text.</p>
          <GuideBody source={guide.text} sourcePath={guide.source} />
          <footer className="docs__related"><h2>Continue in the technical documentation</h2>
            {PUBLIC_DOCS.filter(doc => doc.group === "Technical reference" && doc.id !== key).map(doc => <p key={doc.id}><a href={`/docs/${doc.id}`}>{doc.title}</a> — {doc.summary}</p>)}
          </footer>
        </> : key ? <><h1>Document not found</h1><p>This address does not identify a published guide. <a href="/docs">Browse the documentation index.</a></p></> : <>
          <p className="docs__eyebrow">INSTALL & OPERATE DESKRALLY</p><h1>Deployment guides and technical references</h1>
          <p>Start with an installation guide. Use the full references for build prerequisites, environment settings, database migrations, TURN, encrypted backups and connection failures.</p>
          {(["Installation guides", "Technical reference"] as const).map(group => <section key={group}><h2>{group}</h2>
            <div className="docs__cards">{PUBLIC_DOCS.filter(doc => doc.group === group).map(doc => <a className="docs__card" href={`/docs/${doc.id}`} key={doc.id}><h3>{doc.title}</h3><p>{doc.summary}</p><span>Read {doc.group === "Technical reference" ? "technical reference" : "installation guide"} →</span></a>)}</div>
          </section>)}
        </>}
      </main>
    </div>
  </div>;
}

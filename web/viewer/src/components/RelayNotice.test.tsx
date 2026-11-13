/**
 * `RelayNotice` tests. This repo's vitest runs in Node without a DOM, so the component is invoked as a pure
 * function and its element tree inspected (the IncomingDownloadPrompt convention), and rendered with
 * `renderToStaticMarkup` where what matters is the exact text and escaping the technician's browser gets.
 */
import { describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { RelayNotice } from "./RelayNotice";
import { RELAY_NOTICE_COPY } from "../lib/relay_notice";

type Node = ReactElement<Record<string, unknown>>;

function walk(node: unknown, out: Node[] = []): Node[] {
  if (Array.isArray(node)) {
    for (const child of node) walk(child, out);
    return out;
  }
  if (node && typeof node === "object" && "props" in node) {
    const n = node as Node;
    out.push(n);
    walk((n.props as { children?: unknown }).children, out);
  }
  return out;
}
const findAll = (root: unknown, testid: string) => walk(root).filter((n) => n.props?.["data-testid"] === testid);

const SERVER_TEXT = "relay capacity exhausted for your account; direct connection only";
const render = (notice: string) => renderToStaticMarkup(<RelayNotice notice={notice} onDismiss={() => {}} />);

describe("RelayNotice", () => {
  it("says what happened, what it means and what to do, in plain words", () => {
    const markup = render(SERVER_TEXT);
    expect(markup).toContain("No relay connection is available.");
    expect(markup).toContain("This account has reached its limit of relay credentials");
    expect(markup).toContain("only a direct connection can be tried");
    expect(markup).toContain("That may fail on restrictive networks.");
    // Not "close sessions you no longer need": a credential outlives its session, so that frees nothing.
    expect(markup).toContain("Closing sessions will not free a relay credential");
    expect(markup).not.toContain("Close sessions you no longer need");
    expect(markup).toContain("older relay credentials expire on their own, normally within 2 hours");
    expect(markup).toContain("Ask an administrator if this keeps happening.");
    // The constants are what is shown (so a copy edit is one edit).
    for (const line of Object.values(RELAY_NOTICE_COPY)) expect(markup).toContain(line);
  });

  it("is a polite status that takes no focus, with Dismiss as its only control", () => {
    const tree = RelayNotice({ notice: SERVER_TEXT, onDismiss: () => {} });
    expect(tree.props.role).toBe("status");
    expect(tree.props["data-testid"]).toBe("relay-notice");
    const nodes = walk(tree);
    expect(nodes.some((n) => "autoFocus" in n.props || "tabIndex" in n.props)).toBe(false);
    const buttons = nodes.filter((n) => n.type === "button");
    expect(buttons).toHaveLength(1);
    expect(buttons[0].props["data-testid"]).toBe("relay-notice-dismiss");
    expect(buttons[0].props.type).toBe("button");
    expect(buttons[0].props["aria-label"]).toBe("Dismiss relay notice");
  });

  it("Dismiss calls onDismiss once and does nothing else", () => {
    const onDismiss = vi.fn();
    const tree = RelayNotice({ notice: SERVER_TEXT, onDismiss });
    const [dismiss] = findAll(tree, "relay-notice-dismiss");
    (dismiss.props.onClick as () => void)();
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(onDismiss).toHaveBeenCalledWith();
  });

  it("shows the server's own text as a labelled aside, isolated from the text around it", () => {
    const markup = render(SERVER_TEXT);
    expect(markup).toContain(`Server message: <bdi>${SERVER_TEXT}</bdi>`);
    // The explanation is the component's own wording: the server's text appears once, only in the aside.
    expect(markup.split(SERVER_TEXT)).toHaveLength(2);
  });

  it("renders a hostile server string as TEXT only: escaped, never markup, never in the notice's own wording", () => {
    const hostile = '<img src=x onerror="alert(1)"><script>steal()</script> & "quotes"';
    const tree = RelayNotice({ notice: hostile, onDismiss: () => {} });
    // No raw-HTML escape hatch anywhere in the tree.
    expect(walk(tree).some((n) => "dangerouslySetInnerHTML" in n.props)).toBe(false);

    const markup = render(hostile);
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain("<script");
    expect(markup).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&lt;script&gt;steal()&lt;/script&gt; &amp; &quot;quotes&quot;");
    // Outside the aside the markup is exactly the fixed copy: nothing of the hostile text leaked into it.
    const withoutAside = markup.replace(/<p class="relay-notice__server"[^>]*>.*?<\/p>/, "");
    expect(withoutAside).not.toContain("onerror");
    expect(withoutAside).not.toContain("steal");
  });

  it("cleans the server's text (one line, no control or bidi characters, clipped)", () => {
    const markup = render("line one\n\nline two \u202Eevil\u200B");
    expect(markup).toContain("<bdi>line one line two evil</bdi>");
    const long = render("x".repeat(5000));
    expect(long.length).toBeLessThan(5000);
  });

  it("omits the aside, and keeps its own wording, when nothing displayable is left of the server's text", () => {
    const tree = RelayNotice({ notice: "\u200B \u202E", onDismiss: () => {} });
    expect(findAll(tree, "relay-notice-server")).toHaveLength(0);
    expect(findAll(tree, "relay-notice-lead")).toHaveLength(1);
    expect(render("\u200B \u202E")).toContain("No relay connection is available.");
  });
});

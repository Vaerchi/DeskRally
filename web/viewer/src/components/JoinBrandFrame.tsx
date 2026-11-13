/**
 * A viewport of a given width for the REAL join page frame (docs/66 2a.7, 2k): an iframe the console's own styles
 * are copied into, with the children rendered inside it through a portal. A fixed-width `div` would not do: the
 * join page's responsive rules are viewport media queries, so only a document of that width shows what a guest on
 * that screen gets (the top bar wrapping on a phone, the single column, the long name's ellipsis).
 *
 * The preview is inert by construction: a click on any link inside it is cancelled, so an operator reviewing a
 * tenant's contact link or website cannot be sent anywhere by it (the destination is shown beside it, literally).
 */

import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

export interface JoinBrandFrameProps {
  /** The viewport width in CSS pixels. */
  width: number;
  /** The frame's height; the page scrolls inside it. */
  height?: number;
  /** Accessible name of the frame (also what a test addresses it by). */
  title: string;
  testId?: string;
  children: ReactNode;
}

const BLANK = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body></body></html>";

/** Copy the console's stylesheets (`<link rel=stylesheet>` and `<style>`, in order) into the frame's head. */
function copyStyles(from: Document, to: Document) {
  for (const n of Array.from(from.head.querySelectorAll("link[rel~='stylesheet'], style"))) to.head.appendChild(n.cloneNode(true));
}

export function JoinBrandFrame({ width, height = 520, title, testId, children }: JoinBrandFrameProps) {
  const [frame, setFrame] = useState<HTMLIFrameElement | null>(null);
  const [body, setBody] = useState<HTMLElement | null>(null);

  useEffect(() => {
    if (!frame) return;
    let cancelled = false;
    let seen: Document | null = null;
    const swallowLinks = (e: Event) => {
      // The target belongs to the frame's realm, so `instanceof Element` of THIS realm is always false: duck-type it.
      const t = e.target as Node | null;
      const el = t && "closest" in t ? (t as Element) : null;
      if (el?.closest("a")) e.preventDefault();
    };
    // The srcdoc document loads asynchronously and a (re)load replaces it, so (re)build whenever a new one appears.
    const attach = () => {
      const doc = frame.contentDocument;
      if (cancelled || !doc || !doc.body || doc === seen || doc.readyState === "loading") return;
      seen = doc;
      copyStyles(document, doc);
      doc.body.style.margin = "0";
      doc.addEventListener("click", swallowLinks, true);
      doc.addEventListener("auxclick", swallowLinks, true);
      setBody(doc.body);
    };
    frame.addEventListener("load", attach);
    attach();
    return () => {
      cancelled = true;
      frame.removeEventListener("load", attach);
      seen?.removeEventListener("click", swallowLinks, true);
      seen?.removeEventListener("auxclick", swallowLinks, true);
    };
  }, [frame]);

  return (
    <div className="join-frame" data-testid={testId}>
      <iframe ref={setFrame} className="join-frame__iframe" title={title} srcDoc={BLANK} sandbox="allow-same-origin" style={{ width, height }} />
      {body && createPortal(children, body)}
    </div>
  );
}

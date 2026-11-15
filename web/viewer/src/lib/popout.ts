/**
 * Opening and preparing the separate browser window the remote desktop can be moved into.
 *
 * WHY A SEPARATE WINDOW AT ALL. A technician on two monitors wants the guest's desktop filling one
 * screen and the console — machine list, files, chat, audit — on the other. Inside one browser window
 * those compete for the same pixels no matter how far the chrome is trimmed.
 *
 * WHY THIS IS NOT `<video>` PICTURE-IN-PICTURE. `HTMLVideoElement.requestPictureInPicture()` gives a
 * chromeless video with no way to forward pointer or keyboard events, so the operator could watch the
 * desktop and not touch it — which is not remote control. A regular `window.open` hosts the interactive DOM and supplies native window controls.
 *
 * WHY THE CALLER MUST MOUNT A SEPARATE REACT ROOT INTO THE RETURNED WINDOW, and not `createPortal`
 * into it: React attaches its event listeners to the ROOT CONTAINER of a tree. A portal's DOM lives
 * in the child document, so native events there bubble to the child document and never reach the
 * opener's root container — every `onMouseDown`/`onTouchStart` on the surface would silently stop
 * firing, which for this component means a remote desktop you can see and cannot click. A root
 * created against a container IN the child document listens where the events actually are.
 */

/** A prepared pop-out window plus how to take it down. */
export interface PopoutWindow {
  /** The child window. */
  win: Window;
  /** The element a React root should be created against. */
  container: HTMLElement;
  /** True when the window came from Document Picture-in-Picture rather than `window.open`. */
  documentPip: boolean;
}

/**
 * Copy the opener's styles into `dst`.
 *
 * A child window starts with an empty document and inherits NOTHING — not the app's stylesheet, not
 * the CSS custom properties the whole theme is built from. Both shapes have to be handled because
 * they are what the two builds produce: Vite's dev server injects `<style>` elements, while the
 * production bundle links a hashed `.css` file.
 *
 * `<link>` is preferred over inlining `cssRules` where possible: reading `cssRules` throws on any
 * cross-origin sheet, and a font stylesheet is exactly that.
 */
function cloneStyles(src: Document, dst: Document): void {
  for (const node of Array.from(src.querySelectorAll('style, link[rel="stylesheet"]'))) {
    if (node.tagName === "LINK") {
      const link = node as HTMLLinkElement;
      const copy = dst.createElement("link");
      copy.rel = "stylesheet";
      // `.href` is already absolute, which matters: the child document's base URL is not the
      // opener's, so a relative href would resolve somewhere else (or nowhere).
      copy.href = link.href;
      dst.head.appendChild(copy);
    } else {
      const copy = dst.createElement("style");
      copy.textContent = node.textContent;
      dst.head.appendChild(copy);
    }
  }
}

/** Base layout for the child document: the surface should fill it edge to edge, on the app's ground. */
const CHILD_BASE_CSS = `
  html, body { height: 100%; margin: 0; background: #0b0d10; overflow: hidden; }
  #rmt-popout-root { height: 100%; display: flex; flex-direction: column; min-height: 0; }
  /* The surface is the whole window here — there is no toolbar in this document to share with. */
  #rmt-popout-root .viewer__surface { flex: 1; min-height: 0; }
`;

/**
 * Open a regular resizable pop-out window with operating-system window controls.
 *
 * Returns `null` when the window could not be opened — overwhelmingly a popup blocker, which is why
 * this must be called directly from a user gesture. The caller is expected to SAY so rather than
 * failing silently: a button that does nothing reads as a broken feature.
 */
export async function openPopout(title: string, windowName = "rmt-remote-desktop"): Promise<PopoutWindow | null> {
  // A regular window retains OS maximize/minimize controls. Document PiP does not.
  const win = window.open("", windowName, "popup=yes,width=1280,height=800,resizable=yes");
  if (!win) return null;
  const documentPip = false;

  const doc = win.document;
  // A reused window (same name, still open) keeps its old contents; clear before re-mounting.
  doc.head.replaceChildren();
  doc.body.replaceChildren();
  doc.title = title;

  cloneStyles(document, doc);
  const base = doc.createElement("style");
  base.textContent = CHILD_BASE_CSS;
  doc.head.appendChild(base);

  const container = doc.createElement("div");
  container.id = "rmt-popout-root";
  doc.body.appendChild(container);

  return { win, container, documentPip };
}

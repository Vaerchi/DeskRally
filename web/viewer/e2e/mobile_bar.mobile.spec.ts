/**
 * Phone, outside full screen (Ed, 2026-11-13): "the top bar is very crowded on mobile and i have to slide
 * over to change screens", and "can you tell if we are entering in a password - and if we are obfuscate the
 * keyboard on mobile?"
 *
 * Drives the REAL App against a fake live session (e2e/fake_session.ts: no agent, stubbed peer) under the
 * mobile-phone (412x915) and mobile-foldable (700x900) projects, both touch with a coarse pointer. The pure
 * rules are unit-tested in src/lib/mobile_bar.test.ts and src/lib/phone_typing_password.test.ts; this proves
 * the wiring: the row fits, the screen picker is on screen without sliding, More holds the rest and behaves
 * like the other menus, and password mode masks the field yet still sends every key.
 *
 * SESSION CHROME MODES (lib/session_chrome.ts). The config seeds the bar PINNED for every spec; the compact
 * bar lives in the same toolbar host, so it follows the modes for free, and the last describe block opts OUT
 * of the seed to prove it for collapsed and overlay. The top-row rule (operator, 10-29) is asserted in the
 * first test: the row's controls all fit and nothing was ADDED (the old View/Input/Tools buttons are gone).
 *
 * Set MOBILE_SHOTS=<dir> to write screenshots for a human to look at (not assertions).
 */
import { test, expect, type Page } from "@playwright/test";
import { connect, advertise, selectsSent, inputSent, TWO_MONITORS } from "./fake_session";

const SHOTS = process.env.MOBILE_SHOTS;
async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}-${test.info().project.name}.png` });
}

/** The compact bar draws its picker only when there is something to pick between. */
async function ready(page: Page) {
  await connect(page);
  await advertise(page, TWO_MONITORS);
  await expect(page.getByTestId("viewer-screen-picker")).toBeVisible();
}

const more = (page: Page) => page.getByTestId("viewer-more-menu");
const morePanel = (page: Page) => page.getByTestId("viewer-more-panel");

async function noSidewaysScroll(page: Page) {
  const r = await page.evaluate(() => {
    const host = document.querySelector(".app__toolbar-host") as HTMLElement;
    const top = document.querySelector(".app__topbar") as HTMLElement;
    return {
      host: [host.scrollWidth, host.clientWidth],
      hostLeft: host.scrollLeft,
      top: [top.scrollWidth, top.clientWidth],
      doc: [document.documentElement.scrollWidth, window.innerWidth],
    };
  });
  expect(r.host[0], "toolbar host scrolls sideways").toBeLessThanOrEqual(r.host[1]);
  expect(r.hostLeft).toBe(0);
  expect(r.top[0], "top row overflows").toBeLessThanOrEqual(r.top[1]);
  expect(r.doc[0], "page scrolls sideways").toBeLessThanOrEqual(r.doc[1]);
}

test("the row fits with no sideways scroll, and the screen picker is on screen without sliding", async ({ page }) => {
  await ready(page);
  await noSidewaysScroll(page);
  const vw = page.viewportSize()!.width;

  // The picker comes first and every button is wholly on screen, at touch size.
  for (const id of ["viewer-screen-1", "viewer-screen-2", "viewer-screen-All", "viewer-more-menu"]) {
    const b = (await page.getByTestId(id).boundingBox())!;
    expect(b.x, id).toBeGreaterThanOrEqual(0);
    expect(b.x + b.width, id).toBeLessThanOrEqual(vw);
    expect(b.height, id).toBeGreaterThanOrEqual(43.5);
    expect(b.width, id).toBeGreaterThanOrEqual(43.5);
  }
  const picker = (await page.getByTestId("viewer-screen-picker").boundingBox())!;
  const moreBox = (await more(page).boundingBox())!;
  expect(picker.x + picker.width).toBeLessThanOrEqual(moreBox.x + 0.5); // picker first, More after it

  // Nothing was ADDED to the row (it is full at phone widths): the bar is the full-screen bar's twin, floating
  // under the row, and the old buttons are gone from the row altogether.
  for (const id of ["viewer-view-menu", "viewer-input-menu", "viewer-tools-menu", "viewer-monitor"]) {
    await expect(page.getByTestId(id)).toHaveCount(0);
  }
  await expect(page.locator(".app__topbar").getByTestId("viewer-more-menu")).toHaveCount(0);
  await expect(page.locator(".app__topbar").getByTestId("viewer-screen-picker")).toHaveCount(0);
  const rowBottom = (await page.locator(".app__topbar").boundingBox())!;
  const bar = (await page.getByTestId("viewer-cbar").boundingBox())!;
  expect(bar.y).toBeGreaterThanOrEqual(rowBottom.y + rowBottom.height - 0.5);
  expect(bar.x).toBeGreaterThanOrEqual(0);
  expect(bar.x + bar.width).toBeLessThanOrEqual(vw);
  // Every control in the row is wholly on screen, and the row did not grow.
  const row = await page.evaluate(() => {
    const top = document.querySelector(".app__topbar")!;
    return {
      height: top.getBoundingClientRect().height,
      overs: [...top.querySelectorAll("button, select")]
        .map((e) => ({ r: e.getBoundingClientRect(), t: (e.getAttribute("data-testid") || e.getAttribute("aria-label") || e.textContent || "").trim() }))
        .filter((x) => x.r.width > 0 && x.r.right > window.innerWidth + 0.5)
        .map((x) => x.t),
    };
  });
  expect(row.overs).toEqual([]);
  expect(row.height).toBeLessThanOrEqual(46.5);
  await shot(page, "bar-closed");
});

test("the picker switches the screen in one tap", async ({ page }) => {
  await ready(page);
  await expect(page.getByTestId("viewer-screen-1")).toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("viewer-screen-2").tap();
  await expect.poll(() => selectsSent(page)).toContain(20);
  await expect(page.getByTestId("viewer-screen-2")).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("viewer-screen-1")).toHaveAttribute("aria-pressed", "false");
  await noSidewaysScroll(page);
});

test("More opens and closes like the other menus: tap, Escape (focus returns), outside tap", async ({ page }) => {
  await ready(page);
  await expect(more(page)).toHaveAttribute("aria-expanded", "false");
  await expect(more(page)).toHaveAttribute("aria-haspopup", "dialog");
  await expect(morePanel(page)).toHaveCount(0);

  await more(page).tap();
  await expect(morePanel(page)).toBeVisible();
  await expect(morePanel(page)).toHaveAttribute("role", "dialog");
  await expect(more(page)).toHaveAttribute("aria-expanded", "true");
  // Every item is there, at touch size, wholly on screen.
  const vw = page.viewportSize()!.width;
  for (const id of ["trackpad", "keyboard", "fullscreen", "view", "input", "tools"]) {
    const b = (await page.getByTestId(`viewer-more-${id}`).boundingBox())!;
    expect(b.height, id).toBeGreaterThanOrEqual(43.5);
    expect(b.x + b.width, id).toBeLessThanOrEqual(vw);
  }
  await shot(page, "more-open");

  // A second tap on More closes it.
  await more(page).tap();
  await expect(morePanel(page)).toHaveCount(0);

  // Escape closes it and gives focus back to More (keyboard users, and the existing panels' contract).
  await more(page).tap();
  await expect(morePanel(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(morePanel(page)).toHaveCount(0);
  await expect(more(page)).toBeFocused();
  await expect(more(page)).toHaveAttribute("aria-expanded", "false");

  // A tap outside closes it.
  await more(page).tap();
  await expect(morePanel(page)).toBeVisible();
  await page.locator(".app__topbar").tap({ position: { x: 3, y: 3 } });
  await expect(morePanel(page)).toHaveCount(0);

  // It is reachable by keyboard: Enter on the focused trigger opens it.
  await more(page).focus();
  await page.keyboard.press("Enter");
  await expect(morePanel(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(morePanel(page)).toHaveCount(0);
});

test("More items work: Trackpad, Keyboard, and the View / Input / Tools panels", async ({ page }) => {
  await ready(page);

  await more(page).tap();
  await expect(page.getByTestId("viewer-more-trackpad")).toHaveAttribute("aria-pressed", "false");
  await page.getByTestId("viewer-more-trackpad").tap();
  await expect(morePanel(page)).toHaveCount(0); // an item that acts closes the menu
  await expect(page.getByTestId("trackpad-cursor")).toBeVisible();
  await more(page).tap();
  await expect(page.getByTestId("viewer-more-trackpad")).toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("viewer-more-trackpad").tap();
  await expect(page.getByTestId("trackpad-cursor")).toHaveCount(0);

  // The three panels open from More, anchored and on screen; Escape returns focus to More.
  for (const [item, probe] of [
    ["view", "viewer-audio"],
    ["input", "viewer-trackpad-toggle"],
    ["tools", "viewer-screenshot"],
  ] as const) {
    await more(page).tap();
    await page.getByTestId(`viewer-more-${item}`).tap();
    await expect(morePanel(page)).toHaveCount(0);
    await expect(page.getByTestId(probe), item).toBeVisible();
    const b = (await page.getByTestId(probe).boundingBox())!;
    expect(b.x).toBeGreaterThanOrEqual(0);
    expect(b.x + b.width).toBeLessThanOrEqual(page.viewportSize()!.width);
    await page.keyboard.press("Escape");
    await expect(page.getByTestId(probe)).toHaveCount(0);
    await expect(more(page)).toBeFocused();
  }

  // Keyboard opens the typing field, focused, inside the tap (Android only raises its keyboard for that).
  await more(page).tap();
  await page.getByTestId("viewer-more-keyboard").tap();
  await expect(page.getByTestId("viewer-typing-field")).toBeFocused();
  await more(page).tap();
  await expect(page.getByTestId("viewer-more-keyboard")).toHaveAttribute("aria-expanded", "true");
});

test("More > Full screen enters the full-screen bar and leaves it again", async ({ page }) => {
  await ready(page);
  await more(page).tap();
  await page.getByTestId("viewer-more-fullscreen").tap();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement?.className ?? "")).toContain("viewer");
  await expect(page.getByTestId("viewer-mfs-bar")).toBeVisible();
  await page.getByTestId("viewer-mfs-exit").tap();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement == null)).toBe(true);
  await expect(more(page)).toBeVisible();
});

test("wide layouts keep the full toolbar, and a live resize swaps contents without dropping the video", async ({ page }) => {
  await ready(page);
  await page.evaluate(() => document.querySelector("video")?.setAttribute("data-marker", "same"));
  await page.setViewportSize({ width: 1100, height: 800 });
  await expect(page.getByTestId("viewer-view-menu")).toBeVisible();
  await expect(more(page)).toHaveCount(0);
  await expect(page.getByTestId("viewer-monitor")).toBeVisible();
  await page.setViewportSize({ width: 412, height: 915 });
  await expect(more(page)).toBeVisible();
  await expect(page.getByTestId("viewer-view-menu")).toHaveCount(0);
  // The same <video> element: nothing around it was unmounted.
  await expect(page.locator("video[data-marker='same']")).toHaveCount(1);
});

test.describe("password mode on the typing bar", () => {
  const SECRET = "Pa55 w0rd!";

  async function openTyping(page: Page) {
    await ready(page);
    await more(page).tap();
    await page.getByTestId("viewer-more-keyboard").tap();
    await expect(page.getByTestId("viewer-typing-field")).toBeFocused();
  }
  const field = (page: Page) => page.getByTestId("viewer-typing-field");
  const toggle = (page: Page) => page.getByTestId("viewer-password-toggle");
  /** Everything the page shows or exposes, minus form values: it must never contain the secret. */
  const pageText = (page: Page) =>
    page.evaluate(() => {
      const out: string[] = [document.body.innerText];
      for (const el of document.querySelectorAll("*")) {
        for (const a of el.getAttributeNames()) out.push(el.getAttribute(a) ?? "");
        out.push(el.textContent ?? "");
      }
      return out.join("\n");
    });

  test("defaults off, in text mode, and the toggle sits on the key line", async ({ page }) => {
    await openTyping(page);
    await expect(field(page)).toHaveJSProperty("tagName", "TEXTAREA");
    await expect(toggle(page)).toHaveAttribute("aria-pressed", "false");
    await expect(toggle(page)).toHaveAttribute("aria-label", "Password mode");
    await expect(page.getByTestId("viewer-password-state")).toHaveCount(0);
    // It is on the existing special-key line (first item), and on screen without sliding it.
    const nav = (await page.locator(".viewer__typing-nav").boundingBox())!;
    const t = (await toggle(page).boundingBox())!;
    expect(t.x).toBeGreaterThanOrEqual(nav.x);
    expect(t.x + t.width).toBeLessThanOrEqual(page.viewportSize()!.width);
    await shot(page, "typing-text-mode");
  });

  test("turning it on masks the field, keeps focus, and says so; turning it off restores it", async ({ page }) => {
    await openTyping(page);
    await toggle(page).tap();
    await expect(field(page)).toHaveJSProperty("tagName", "INPUT");
    await expect(field(page)).toHaveAttribute("type", "password");
    await expect(field(page)).toBeFocused(); // the phone keyboard does not drop
    await expect(toggle(page)).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("viewer-password-state")).toContainText("Password mode");
    for (const [a, v] of [
      ["autocomplete", "off"],
      ["autocorrect", "off"],
      ["autocapitalize", "off"],
      ["spellcheck", "false"],
    ] as const) {
      await expect(field(page), a).toHaveAttribute(a, v);
    }
    await expect(field(page)).not.toHaveAttribute("inputmode", /.*/);
    await shot(page, "typing-password-mode");

    await toggle(page).tap();
    await expect(field(page)).toHaveJSProperty("tagName", "TEXTAREA");
    await expect(field(page)).toBeFocused();
    await expect(page.getByTestId("viewer-password-state")).toHaveCount(0);
    await expect(toggle(page)).toHaveAttribute("aria-pressed", "false");
  });

  test("masked, yet every key still reaches the remote exactly as in text mode; the secret is never in the page", async ({ page }) => {
    await openTyping(page);
    await toggle(page).tap();
    await expect(field(page)).toBeFocused();
    const before = (await inputSent(page)).length;

    // What Android's keyboard does for a password field: insertText edits with no composition.
    for (const ch of SECRET) await page.keyboard.insertText(ch);
    await page.keyboard.press("Backspace"); // deleteContentBackward on a non-empty field
    await page.keyboard.insertText("!");
    await page.keyboard.press("Enter"); // a single-line input makes no edit for Enter
    await expect.poll(async () => (await inputSent(page)).length).toBeGreaterThan(before);

    const sent = (await inputSent(page)).slice(before);
    const texts = sent.filter((e) => e.t === "Text").map((e) => e.c as string);
    // Text events are append-only: the Backspace is a key event between them, so the Text stream is SECRET then "!".
    expect(texts.join("")).toBe(SECRET + "!");
    const keys = sent.filter((e) => e.t === "Key").map((e) => `${e.c.code}:${e.c.down}`);
    expect(keys).toEqual(["8:true", "8:false", "13:true", "13:false"]); // Backspace tap, then Enter tap

    // Nothing in the UI echoes it, and nothing was stored.
    expect(await pageText(page)).not.toContain("Pa55");
    expect(await field(page).inputValue()).not.toContain("Pa55");
    const store = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
    expect(store).not.toMatch(/Pa55|assword/);
    await shot(page, "typing-password-sent");
  });

  test("the same keystrokes reach the remote in text mode (the control)", async ({ page }) => {
    await openTyping(page);
    const before = (await inputSent(page)).length;
    for (const ch of SECRET) await page.keyboard.insertText(ch);
    await expect.poll(async () => (await inputSent(page)).length).toBeGreaterThan(before);
    const texts = (await inputSent(page)).slice(before).filter((e) => e.t === "Text").map((e) => e.c as string);
    expect(texts.join("")).toBe(SECRET);
  });

  test("a paste into the masked field goes as one Text event, and the mode leaves no trace in storage", async ({ page }) => {
    await openTyping(page);
    const storageBefore = await page.evaluate(() => JSON.stringify({ ...localStorage }));
    await toggle(page).tap();
    const before = (await inputSent(page)).length;
    await page.evaluate((s) => {
      const el = document.querySelector("[data-testid='viewer-typing-field']") as HTMLInputElement;
      el.focus();
      document.execCommand("insertText", false, s);
    }, "hunter2-hunter2");
    await expect.poll(async () => (await inputSent(page)).length).toBeGreaterThan(before);
    const texts = (await inputSent(page)).slice(before).filter((e) => e.t === "Text").map((e) => e.c as string);
    expect(texts.join("")).toBe("hunter2-hunter2");
    expect(await page.evaluate(() => JSON.stringify({ ...localStorage }))).toBe(storageBefore);
  });
});

// The compact bar lives in the toolbar host, so it follows the session chrome modes. The config pins the bar for
// every spec; these two opt out (like session_chrome.spec.ts) to prove collapsed and overlay.
test.describe("session chrome modes", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("collapsed: only the tab shows (it already holds one-tap screens); the dropped bar is compact and fits", async ({ page }) => {
    await connect(page);
    await advertise(page, TWO_MONITORS);
    await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
    await expect(page.locator(".app__topbar")).toBeHidden();
    await expect(more(page)).toBeHidden();
    await expect(page.getByTestId("session-tab-monitor-2")).toBeVisible();
    await shot(page, "chrome-collapsed");

    // Overlay: the same compact row drops over the screen.
    await page.getByTestId("session-tab-toggle").tap();
    await expect(page.locator(".app")).toHaveAttribute("data-chrome", "overlay");
    await expect(page.getByTestId("viewer-screen-picker")).toBeVisible();
    await expect(more(page)).toBeVisible();
    await noSidewaysScroll(page);
    // More still opens from the dropped bar, and its panel is on screen.
    await more(page).tap();
    await expect(morePanel(page)).toBeVisible();
    const b = (await morePanel(page).boundingBox())!;
    expect(b.x).toBeGreaterThanOrEqual(0);
    expect(b.x + b.width).toBeLessThanOrEqual(page.viewportSize()!.width);
    await shot(page, "chrome-overlay-more");
  });
});

// ---- Codex review r1 of 491e94ab ---------------------------------------------------------------------------

/** True when any hook state of the Viewer's component chain holds `secret` as a string (React refs included). */
const holdsText = (page: Page, secret: string) =>
  page.evaluate((needle) => {
    const el = document.querySelector('[data-testid="viewer-surface"]') as unknown as Record<string, unknown>;
    const key = Object.keys(el).find((k) => k.startsWith("__reactFiber$"))!;
    const seen = new Set<unknown>();
    let found = false;
    const visit = (v: unknown, depth: number) => {
      if (found || depth > 6 || v == null) return;
      if (typeof v === "string") {
        if (v.includes(needle)) found = true;
        return;
      }
      if (typeof v !== "object" || seen.has(v) || v instanceof Node || v instanceof Window) return;
      seen.add(v);
      for (const k of Object.keys(v as object)) {
        try {
          visit((v as Record<string, unknown>)[k], depth + 1);
        } catch {
          /* a getter that throws is not state */
        }
      }
    };
    for (let f = el[key] as { return: unknown; memoizedState: unknown } | null; f; f = f.return as typeof f) {
      for (let h = f.memoizedState as { memoizedState: unknown; next: unknown } | null; h && typeof h === "object"; h = h.next as typeof h) {
        visit(h.memoizedState, 0);
      }
    }
    return found;
  }, secret);

test.describe("review fixes", () => {
  const field = (page: Page) => page.getByTestId("viewer-typing-field");
  const toggle = (page: Page) => page.getByTestId("viewer-password-toggle");
  async function typingOpen(page: Page) {
    await ready(page);
    await more(page).tap();
    await page.getByTestId("viewer-more-keyboard").tap();
    await expect(field(page)).toBeFocused();
  }

  test("a typed password leaves no trace in the Viewer's state or the DOM: typing, Enter, toggling, closing", async ({ page }) => {
    const S = "Zq9x7";
    await typingOpen(page);
    // Positive control: in text mode the history legitimately holds a short word, so the scan can see it.
    await page.keyboard.insertText(S);
    expect(await holdsText(page, S)).toBe(true);

    await toggle(page).tap(); // text -> password (history forgotten)
    expect(await holdsText(page, S)).toBe(false);
    await page.keyboard.insertText(S);
    expect(await holdsText(page, S)).toBe(false); // nothing retained once the event was sent
    expect(await field(page).inputValue()).not.toContain("Zq9");

    await page.keyboard.press("Enter");
    expect(await holdsText(page, S)).toBe(false);

    await page.keyboard.insertText(S);
    await toggle(page).tap(); // password -> text
    expect(await holdsText(page, S)).toBe(false);

    await toggle(page).tap(); // back to password, type, then CLOSE the bar
    await page.keyboard.insertText(S);
    await more(page).tap();
    await page.getByTestId("viewer-more-keyboard").tap();
    await expect(field(page)).toHaveCount(0);
    expect(await holdsText(page, S)).toBe(false);
    expect(await page.evaluate(() => document.documentElement.outerHTML.includes("Zq9x7"))).toBe(false);
  });

  test("toggling mid-composition sends nothing, even when the removed node fires compositionend and input", async ({ page }) => {
    await typingOpen(page);
    await page.evaluate(() => {
      const el = document.querySelector("[data-testid='viewer-typing-field']") as HTMLTextAreaElement;
      el.dispatchEvent(new CompositionEvent("compositionstart", { bubbles: true }));
      el.value = " he";
      el.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertCompositionText" }));
      // The composition-safe order: a live composition is force-committed by a blur BEFORE the node is swapped.
      (window as unknown as { __blurred: boolean }).__blurred = false;
      el.addEventListener("blur", () => {
        (window as unknown as { __blurred: boolean }).__blurred = true;
      });
      // A browser commits a composition when its field goes away: model that on removal of THIS node.
      const orig = Node.prototype.removeChild;
      Node.prototype.removeChild = function <T extends Node>(this: Node, child: T): T {
        if (child instanceof HTMLElement && child.dataset.testid === "viewer-typing-field") {
          child.dispatchEvent(new CompositionEvent("compositionend", { bubbles: true }));
          child.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "deleteContentBackward" }));
        }
        return orig.call(this, child) as T;
      };
    });
    await expect.poll(async () => (await inputSent(page)).filter((e) => e.t === "Text").length).toBeGreaterThan(0);
    const before = (await inputSent(page)).length;
    await toggle(page).tap();
    await expect(field(page)).toHaveAttribute("type", "password");
    await expect(field(page)).toBeFocused();
    expect((await inputSent(page)).length).toBe(before); // no Backspaces for characters the remote already has
    expect(await page.evaluate(() => (window as unknown as { __blurred: boolean }).__blurred)).toBe(true);
  });

  test("More: keyboard open moves focus in, Tab wraps inside, Escape returns to More; an action returns to More", async ({ page }) => {
    await ready(page);
    await more(page).focus();
    await page.keyboard.press("Enter");
    await expect(morePanel(page)).toBeVisible();
    const ids = ["trackpad", "keyboard", "fullscreen", "view", "input", "tools"];
    await expect(page.getByTestId("viewer-more-trackpad")).toBeFocused();
    for (const id of ids.slice(1)) {
      await page.keyboard.press("Tab");
      await expect(page.getByTestId("viewer-more-" + id)).toBeFocused();
    }
    await page.keyboard.press("Tab"); // wraps, never leaves the panel
    await expect(page.getByTestId("viewer-more-trackpad")).toBeFocused();
    await page.keyboard.press("Shift+Tab");
    await expect(page.getByTestId("viewer-more-tools")).toBeFocused();

    await page.keyboard.press("Escape");
    await expect(morePanel(page)).toHaveCount(0);
    await expect(more(page)).toBeFocused();

    // An action that unmounts the focused item: focus goes back to More, not to the page.
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("viewer-more-trackpad")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(morePanel(page)).toHaveCount(0);
    await expect(more(page)).toBeFocused();
    await expect(page.getByTestId("trackpad-cursor")).toBeVisible();
  });

  // Codex review r2: with the typing bar open, a keyboard user who closes it from More must not be left with focus
  // on the page (the field and the menu item both unmount).
  test("More > Keyboard by keyboard while typing is open: the bar closes and focus returns to More", async ({ page }) => {
    await typingOpen(page);
    await more(page).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("viewer-more-trackpad")).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(page.getByTestId("viewer-more-keyboard")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(field(page)).toHaveCount(0);
    await expect(more(page)).toBeFocused();
  });

  test("More opened by touch does not take focus from the typing field (the phone keyboard stays up)", async ({ page }) => {
    await typingOpen(page);
    await more(page).tap();
    await expect(morePanel(page)).toBeVisible();
    await expect(field(page)).toBeFocused();
  });
});

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { handoffAdvertised, inputControlChanged, NO_INPUT_HANDOFF } from "../lib/input_handoff";
import { InputRequestController, type InputRequestSender } from "../lib/input_request";
import { InputControlPrompts, InputRequestControl } from "./InputRequestControl";

const ME = "me-session";
const PEER = "peer-session";
const CID = "aaaaaaaa-1111-4222-8333-444444444444";
const RID = "bbbbbbbb-5555-4666-8777-888888888888";
const noop = () => {};
const sender: InputRequestSender = {
  requestInputControl: noop, withdrawInputControlRequest: noop, inputControlPromptShown: noop, answerInputControlRequest: noop,
};

function controller() {
  return new InputRequestController(() => sender, { newId: () => CID });
}
const owned = inputControlChanged(handoffAdvertised(NO_INPUT_HANDOFF, true), PEER, "owned");
const menu = (c: InputRequestController, handoff = owned, observing = false) =>
  renderToStaticMarkup(<InputRequestControl snapshot={c.getSnapshot()} handoff={handoff} observing={observing}
    ownSessionId={ME} onRequest={noop} onWithdraw={noop} />);

describe("Session menu: Request input control", () => {
  it("is absent until available AND input is owned by another session", () => {
    const c = controller();
    expect(menu(c)).toBe("");
    c.handleMessage({ t: "InputRequestAvailable", c: { available: true } });
    expect(menu(c)).toContain("Request input control");
    expect(menu(c, handoffAdvertised(NO_INPUT_HANDOFF, true))).toBe(""); // shared
    expect(menu(c, owned, true)).toBe(""); // observer / view-only
    expect(menu(c, inputControlChanged(NO_INPUT_HANDOFF, ME, "owned"))).toBe(""); // we own it
  });

  it("shows the waiting text with Withdraw while pending, and swaps to the handing-over text", () => {
    const c = controller();
    c.handleMessage({ t: "InputRequestAvailable", c: { available: true } });
    c.request();
    let html = menu(c);
    expect(html).toContain("Waiting for the other technician…");
    expect(html).toContain("input-request-withdraw");
    expect(html).not.toContain("input-request-ask");
    c.handleMessage({ t: "InputControlRequestPending", c: { client_request_id: CID, request_id: RID, state: "accepted_in_flight" } });
    html = menu(c);
    expect(html).toContain("Handing over…");
    expect(html).not.toContain("input-request-withdraw");
  });

  it("shows a refusal text and offers a new request", () => {
    const c = controller();
    c.handleMessage({ t: "InputRequestAvailable", c: { available: true } });
    c.request();
    c.handleMessage({ t: "InputControlRequestResult", c: { client_request_id: CID, request_id: null, outcome: "busy" } });
    const html = menu(c);
    expect(html).toContain("Input is recovering, try again shortly");
    expect(html).toContain("input-request-ask");
  });
});

describe("holder prompt", () => {
  const prompts = (c: InputRequestController, participants: { session_id: string; display_name?: string }[] = []) =>
    renderToStaticMarkup(<InputControlPrompts controller={c} participants={participants} />);
  const ask = (c: InputRequestController, from = PEER) =>
    c.handleMessage({ t: "InputControlRequested", c: { request_id: RID, from_session: from, expires_in_ms: 30_000 } });

  it("renders nothing without a request, and a non-modal prompt with Allow and Decline when asked", () => {
    const c = controller();
    expect(prompts(c)).toBe("");
    ask(c);
    const html = prompts(c, [{ session_id: PEER, display_name: "Pat" }]);
    expect(html).toContain("Pat asks for keyboard and mouse control");
    expect(html).toContain(">Allow<");
    expect(html).toContain(">Decline<");
    expect(html).not.toMatch(/aria-modal|<dialog/);
  });

  it("falls back to the generic label when no name is known", () => {
    const c = controller();
    ask(c);
    expect(prompts(c)).toContain("Another technician asks for keyboard and mouse control");
  });

  it("renders a hostile from_session and a hostile display name as TEXT only, never markup", () => {
    const hostile = `<img src=x onerror=alert(1)>"'<script>`;
    const c = controller();
    ask(c, hostile);
    const generic = prompts(c);
    expect(generic).not.toContain("<img");
    expect(generic).not.toContain("onerror");
    expect(generic).not.toContain("<script");
    const named = prompts(c, [{ session_id: hostile, display_name: hostile }]);
    expect(named).not.toContain("<img");
    expect(named).not.toContain("<script");
    expect(named).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(named).not.toMatch(/(?:title|alt|aria-label|value)=/); // never in an attribute
  });
});

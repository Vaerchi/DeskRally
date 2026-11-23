/**
 * Chat codec + client tests (M12).
 *
 * The `describe("chat codec")` literals are the CROSS-LANGUAGE CONTRACT: they are byte-for-byte the
 * same strings the Rust `crates/agent-core/src/chat.rs` unit tests assert in their `round_trip`
 * helper, and each file names the other. A field reorder or a rename on either side turns both red.
 */

import { describe, it, expect } from "vitest";
import {
  ChatClient,
  MAX_BODY_CHARS,
  decodeChat,
  encodeChat,
  truncateChatBody,
  type ChatEntry,
  type ChatMessage,
} from "./chat";

const dec = (u: Uint8Array) => new TextDecoder().decode(u);
const enc = (s: string) => new TextEncoder().encode(s);

/** Assert a message's exact canonical JSON and that the JSON decodes back to it (both directions). */
function pin(msg: ChatMessage, json: string) {
  expect(dec(encodeChat(msg))).toBe(json);
  expect(decodeChat(enc(json))).toEqual(msg);
}

describe("chat codec (wire-compat with Rust chat.rs)", () => {
  it("Send → adjacently-tagged JSON, field order from, body", () => {
    pin(
      { t: "Send", c: { from: "Technician", body: "hello there" } },
      `{"t":"Send","c":{"from":"Technician","body":"hello there"}}`,
    );
    pin(
      { t: "Send", c: { from: "Guest", body: "my printer is broken" } },
      `{"t":"Send","c":{"from":"Guest","body":"my printer is broken"}}`,
    );
  });

  it("Posted → the recorded entry, field order seq, from, body, at_unix_ms", () => {
    pin(
      { t: "Posted", c: { entry: { seq: 7, from: "Guest", body: "ok", at_unix_ms: 1700000000000 } } },
      `{"t":"Posted","c":{"entry":{"seq":7,"from":"Guest","body":"ok","at_unix_ms":1700000000000}}}`,
    );
  });

  it("RequestHistory → the resume cursor", () => {
    pin({ t: "RequestHistory", c: { since_seq: 0 } }, `{"t":"RequestHistory","c":{"since_seq":0}}`);
  });

  it("History → entries then truncated, including the empty/truncated reply", () => {
    pin(
      {
        t: "History",
        c: {
          entries: [{ seq: 1, from: "Technician", body: "hi", at_unix_ms: 1700000000001 }],
          truncated: false,
        },
      },
      `{"t":"History","c":{"entries":[{"seq":1,"from":"Technician","body":"hi","at_unix_ms":1700000000001}],"truncated":false}}`,
    );
    pin(
      { t: "History", c: { entries: [], truncated: true } },
      `{"t":"History","c":{"entries":[],"truncated":true}}`,
    );
  });

  it("text a human actually types survives the wire intact", () => {
    // Chat is the ONE channel where a user types arbitrary text straight at the protocol. Quotes,
    // backslashes, newlines, tabs and non-BMP characters must all come back byte-identical — a codec
    // that mangled them would corrupt exactly the support transcript this feature exists to keep.
    // Mirrors Rust's `json_special_characters_survive_the_wire`.
    const nasty = 'he said "hi"\\n\nnewline\ttab 😀 日本語';
    const back = decodeChat(encodeChat({ t: "Send", c: { from: "Guest", body: nasty } }));
    expect(back).toEqual({ t: "Send", c: { from: "Guest", body: nasty } });
    // ...and through an entry too, where the string is nested one level deeper.
    const entry: ChatEntry = { seq: 3, from: "Technician", body: nasty, at_unix_ms: 5 };
    expect(decodeChat(encodeChat({ t: "Posted", c: { entry } }))).toEqual({
      t: "Posted",
      c: { entry },
    });
  });

  it("decode rejects garbage, unknown variants, bad roles and missing fields", () => {
    expect(() => decodeChat(new Uint8Array(0))).toThrow();
    expect(() => decodeChat(enc("not json"))).toThrow();
    expect(() => decodeChat(enc(`{"t":"Nope"}`))).toThrow(/unknown chat variant/);
    // A role the agent cannot mean. Defaulting it would attribute a line to the wrong side of the
    // conversation, which is worse than dropping the frame.
    expect(() => decodeChat(enc(`{"t":"Send","c":{"from":"Nobody","body":"x"}}`))).toThrow();
    // A missing field must be rejected, never defaulted (Rust asserts the same).
    expect(() => decodeChat(enc(`{"t":"Send","c":{"body":"x"}}`))).toThrow();
    expect(() => decodeChat(enc(`{"t":"Send","c":{"from":"Guest"}}`))).toThrow();
    expect(() =>
      decodeChat(enc(`{"t":"Posted","c":{"entry":{"from":"Guest","body":"x","at_unix_ms":1}}}`)),
    ).toThrow(/malformed ChatEntry/);
    expect(() => decodeChat(enc(`{"t":"RequestHistory","c":{}}`))).toThrow();
    // A History whose entries are unparseable is rejected whole rather than half-applied.
    expect(() => decodeChat(enc(`{"t":"History","c":{"entries":[{}],"truncated":false}}`))).toThrow();
    expect(() => decodeChat(enc(`{"t":"History","c":{"entries":[]}}`))).toThrow();
  });
});

describe("truncateChatBody", () => {
  it("passes a short body through untouched and cuts at the character cap", () => {
    expect(truncateChatBody("short")).toBe("short");
    const huge = "x".repeat(MAX_BODY_CHARS * 2);
    expect(Array.from(truncateChatBody(huge)).length).toBe(MAX_BODY_CHARS);
  });

  it("counts code points, so the cut never splits a surrogate pair", () => {
    // A UTF-16 `slice` would cut "😀" in half and put a lone surrogate on the wire. Rust counts
    // `chars()`, so counting code points here is what keeps the two ends cutting at the same place.
    const emoji = "😀".repeat(MAX_BODY_CHARS + 100);
    const cut = truncateChatBody(emoji);
    expect(Array.from(cut).length).toBe(MAX_BODY_CHARS);
    expect(cut.endsWith("😀")).toBe(true);
    expect(cut).toBe("😀".repeat(MAX_BODY_CHARS));
  });
});

/** Collect what a client frames out, decoded. */
function recorder() {
  const sent: ChatMessage[] = [];
  const client = new ChatClient((p) => sent.push(decodeChat(p)), {});
  return { sent, client };
}

const entry = (seq: number, body: string, from: ChatEntry["from"] = "Guest"): ChatEntry => ({
  seq,
  from,
  body,
  at_unix_ms: 1700000000000 + seq,
});

const posted = (e: ChatEntry) => encodeChat({ t: "Posted", c: { entry: e } });
const history = (entries: ChatEntry[], truncated = false) =>
  encodeChat({ t: "History", c: { entries, truncated } });

describe("ChatClient sending", () => {
  it("send() frames a Send from the Technician", () => {
    const { sent, client } = recorder();
    client.send("hello there");
    expect(sent).toEqual([{ t: "Send", c: { from: "Technician", body: "hello there" } }]);
  });

  it("send() cuts an over-long body to the agent's character cap", () => {
    const { sent, client } = recorder();
    client.send("😀".repeat(MAX_BODY_CHARS + 10));
    const msg = sent[0];
    if (msg.t !== "Send") throw new Error("expected a Send");
    expect(Array.from(msg.c.body).length).toBe(MAX_BODY_CHARS);
  });

  it("send() does NOT add the message locally — only the agent's Posted echo does", () => {
    // The agent owns the transcript. A local optimistic copy would show a line that may never have
    // been recorded, and would carry no real sequence number to de-duplicate the echo against.
    const { client } = recorder();
    client.send("did this get through?");
    expect(client.messages).toEqual([]);
    expect(client.lastSeq).toBe(0);
  });
});

describe("ChatClient history cursor", () => {
  it("requestHistory() asks from 0 when it holds nothing", () => {
    const { sent, client } = recorder();
    client.requestHistory();
    expect(sent).toEqual([{ t: "RequestHistory", c: { since_seq: 0 } }]);
  });

  it("requestHistory() asks from the HIGHEST sequence held, not 0", () => {
    // The resume case the cursor exists for: a second request must fetch the gap, not re-pull the
    // whole transcript. Asking from 0 here is the bug this test is aimed at.
    const { sent, client } = recorder();
    client.handleMessage(history([entry(1, "a"), entry(2, "b"), entry(3, "c")]));
    client.requestHistory();
    expect(sent).toEqual([{ t: "RequestHistory", c: { since_seq: 3 } }]);
    // ...and it tracks the high-water mark as new messages land.
    client.handleMessage(posted(entry(9, "later")));
    client.requestHistory();
    expect(sent[1]).toEqual({ t: "RequestHistory", c: { since_seq: 9 } });
  });
});

describe("ChatClient transcript", () => {
  it("de-duplicates by seq: a Posted echo and a History replay of the same entry appear once", () => {
    // The exact reconnect sequence: the agent echoed seq 1 while we were connected, then answered a
    // later RequestHistory with a window that still contains seq 1. A naive append shows it twice.
    const seen: ChatEntry[][] = [];
    const client = new ChatClient(
      () => {},
      { onMessages: (m) => seen.push([...m]) },
    );
    client.handleMessage(posted(entry(1, "hi")));
    client.handleMessage(history([entry(1, "hi"), entry(2, "second")]));
    expect(client.messages.map((e) => e.seq)).toEqual([1, 2]);
    expect(client.messages.map((e) => e.body)).toEqual(["hi", "second"]);
    // The second frame added only seq 2, so exactly two notifications fired (one per change).
    expect(seen.map((m) => m.length)).toEqual([1, 2]);
  });

  it("does not notify when a frame adds nothing new", () => {
    let calls = 0;
    const client = new ChatClient(() => {}, { onMessages: () => (calls += 1) });
    client.handleMessage(posted(entry(1, "hi")));
    client.handleMessage(posted(entry(1, "hi")));
    client.handleMessage(history([entry(1, "hi")]));
    expect(calls).toBe(1);
    expect(client.messages).toHaveLength(1);
  });

  it("sorts by seq, so out-of-order arrivals read in the order they were written", () => {
    const { client } = recorder();
    client.handleMessage(posted(entry(5, "fifth")));
    client.handleMessage(history([entry(2, "second"), entry(1, "first")]));
    client.handleMessage(posted(entry(3, "third")));
    expect(client.messages.map((e) => e.seq)).toEqual([1, 2, 3, 5]);
    expect(client.lastSeq).toBe(5);
  });

  it("reports a truncated History once, and stays reporting it", () => {
    let truncations = 0;
    const client = new ChatClient(() => {}, { onTruncated: () => (truncations += 1) });
    expect(client.truncated).toBe(false);
    client.handleMessage(history([entry(400, "…")], true));
    expect(client.truncated).toBe(true);
    expect(truncations).toBe(1);
    // A later complete reply does not heal the hole in the OLDER messages, so the flag is sticky —
    // telling the operator the conversation is complete when it is not is the failure to avoid.
    client.handleMessage(history([entry(401, "next")], false));
    expect(client.truncated).toBe(true);
    expect(truncations).toBe(1);
  });

  it("keeps the entries' own fields (role and timestamp), not just the text", () => {
    const { client } = recorder();
    client.handleMessage(posted({ seq: 1, from: "Technician", body: "hi", at_unix_ms: 42 }));
    expect(client.messages[0]).toEqual({
      seq: 1,
      from: "Technician",
      body: "hi",
      at_unix_ms: 42,
    });
  });
});

describe("ChatClient tolerance", () => {
  it("handleMessage does NOT throw on garbage — it reports and moves on", () => {
    // It runs inside transport.ts's loop over the frames coalesced into one SCTP message; a throw
    // would discard the innocent sibling frames behind the bad one.
    const errors: string[] = [];
    const client = new ChatClient(() => {}, { onError: (e) => errors.push(e.message) });
    expect(() => client.handleMessage(enc("not json"))).not.toThrow();
    expect(() => client.handleMessage(enc(`{"t":"FutureVariant","c":{}}`))).not.toThrow();
    expect(() => client.handleMessage(new Uint8Array(0))).not.toThrow();
    expect(errors).toHaveLength(3);
    // ...and a good frame arriving after the bad ones is still processed.
    client.handleMessage(posted(entry(1, "still here")));
    expect(client.messages.map((e) => e.body)).toEqual(["still here"]);
  });

  it("ignores controller→agent variants reflected back", () => {
    const { client } = recorder();
    client.handleMessage(encodeChat({ t: "Send", c: { from: "Guest", body: "echo" } }));
    client.handleMessage(encodeChat({ t: "RequestHistory", c: { since_seq: 0 } }));
    expect(client.messages).toEqual([]);
  });
});


describe("hostile peer resource limits", () => {
  const entry = (seq: number, body = "hello"): ChatEntry => ({ seq, body, from: "Guest", at_unix_ms: 1 });
  it("bounds a continuously growing transcript and reports truncation", () => {
    let truncated = 0;
    const client = new ChatClient(() => {}, { onTruncated: () => truncated++ });
    for (let seq = 1; seq <= 1200; seq++) client.handleMessage(encodeChat({ t: "Posted", c: { entry: entry(seq) } }));
    expect(client.messages).toHaveLength(500);
    expect(client.messages[0].seq).toBe(701);
    expect(client.lastSeq).toBe(1200);
    expect(truncated).toBe(1);
  });
  it("rejects oversized bodies, batches and unsafe cursors", () => {
    for (const e of [entry(1, "x".repeat(MAX_BODY_CHARS + 1)), entry(0), entry(Number.MAX_SAFE_INTEGER + 1)]) {
      expect(() => decodeChat(encodeChat({ t: "Posted", c: { entry: e } }))).toThrow();
    }
    expect(() => decodeChat(encodeChat({ t: "History", c: { entries: Array.from({length: 201}, (_, i) => entry(i + 1)), truncated: false } }))).toThrow();
  });
});

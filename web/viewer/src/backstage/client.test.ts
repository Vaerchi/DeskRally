/**
 * Backstage client tests: request encoding, response decoding for every variant, error surfacing
 * (denied / needs_confirmation), and the confirm-retry flow — all against a mock transport that
 * records what was sent and returns envelope fixtures. Plus smoke tests for the two new panels.
 */

import { describe, it, expect, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  AGENT_TOO_OLD_TO_CONFIRM,
  BACKSTAGE_EXEC_PATH,
  BackstageClient,
  auditActionLabel,
  auditOutcomeLabel,
  parseEnvelope,
  type AuditEvent,
  type BackstageTransport,
  type Envelope,
} from "./client";
import {
  SAMPLE_DIR_LISTING,
  SAMPLE_EVENT_LOG,
  SAMPLE_PROCESSES,
  SAMPLE_SERVICES,
  SAMPLE_SYSTEM_INFO,
} from "./fixtures";
import { SystemInfoPanel } from "../components/SystemInfoPanel";
import { EventLogPanel } from "../components/EventLogPanel";

/** A transport that records calls and returns a canned envelope (or one per call). */
function recordingTransport(envelopes: Envelope | Envelope[]) {
  const calls: { path: string; body: string }[] = [];
  const queue = Array.isArray(envelopes) ? [...envelopes] : null;
  const transport: BackstageTransport = async (path, body) => {
    calls.push({ path, body });
    const env = queue ? queue.shift()! : (envelopes as Envelope);
    return JSON.stringify(env);
  };
  return { transport, calls };
}

const OK = (response: Envelope["response"], audit?: Envelope["audit"]): Envelope => ({
  ok: true,
  response,
  ...(audit ? { audit } : {}),
});

const AUDIT = { hash: "abcdef0123456789", outcome: "authorized", action: "ListProcesses" };

describe("BackstageClient request encoding", () => {
  it("posts unit variants with no `data` to the exec path", async () => {
    const { transport, calls } = recordingTransport(OK({ type: "ProcessList", data: [] }));
    const client = new BackstageClient(transport);
    await client.listProcesses();
    expect(calls[0].path).toBe(BACKSTAGE_EXEC_PATH);
    expect(JSON.parse(calls[0].body)).toEqual({ type: "ListProcesses" });
  });

  it("nests args under `data` for the tagged variants", async () => {
    const { transport, calls } = recordingTransport(OK({ type: "EventLog", data: [] }));
    const client = new BackstageClient(transport);

    await client.readEventLog("System", 50);
    await client.browseDirectory("C:\\");
    await client.readRegistry({ path: "HKLM\\X", value_name: "V" });

    expect(JSON.parse(calls[0].body)).toEqual({
      type: "ReadEventLog",
      data: { channel: "System", max: 50 },
    });
    expect(JSON.parse(calls[1].body)).toEqual({ type: "BrowseDirectory", data: { path: "C:\\" } });
    expect(JSON.parse(calls[2].body)).toEqual({
      type: "ReadRegistry",
      data: { path: "HKLM\\X", value_name: "V" },
    });
  });

  it("empty path browses the top level (drive roots)", async () => {
    const { transport, calls } = recordingTransport(OK({ type: "DirectoryListing", data: SAMPLE_DIR_LISTING }));
    const client = new BackstageClient(transport);
    await client.browseDirectory("");
    expect(JSON.parse(calls[0].body)).toEqual({ type: "BrowseDirectory", data: { path: "" } });
  });
});

describe("BackstageClient response decoding", () => {
  it("decodes each response variant into typed data", async () => {
    const cases: { env: Envelope; assert: (e: Envelope) => void }[] = [
      {
        env: OK({ type: "ProcessList", data: SAMPLE_PROCESSES }),
        assert: (e) => {
          if (e.response?.type === "ProcessList") expect(e.response.data[0].pid).toBe(4);
          else throw new Error("wrong variant");
        },
      },
      {
        env: OK({ type: "ServiceList", data: SAMPLE_SERVICES }),
        assert: (e) => {
          if (e.response?.type === "ServiceList") expect(e.response.data[0].name).toBe("Spooler");
          else throw new Error("wrong variant");
        },
      },
      {
        env: OK({ type: "SystemInfo", data: SAMPLE_SYSTEM_INFO }),
        assert: (e) => {
          if (e.response?.type === "SystemInfo") expect(e.response.data.hostname).toBe("ACCT-WS-07");
          else throw new Error("wrong variant");
        },
      },
      {
        env: OK({ type: "EventLog", data: SAMPLE_EVENT_LOG }),
        assert: (e) => {
          if (e.response?.type === "EventLog") expect(e.response.data[0].channel).toBe("System");
          else throw new Error("wrong variant");
        },
      },
      {
        env: OK({ type: "DirectoryListing", data: SAMPLE_DIR_LISTING }),
        assert: (e) => {
          if (e.response?.type === "DirectoryListing")
            expect(e.response.data.path).toBe("C:\\Users\\jdoe\\Documents");
          else throw new Error("wrong variant");
        },
      },
      {
        env: OK({ type: "RegistryValue", data: "hello" }),
        assert: (e) => {
          if (e.response?.type === "RegistryValue") expect(e.response.data).toBe("hello");
          else throw new Error("wrong variant");
        },
      },
      {
        env: OK({ type: "RegistryValue", data: null }),
        assert: (e) => {
          if (e.response?.type === "RegistryValue") expect(e.response.data).toBeNull();
          else throw new Error("wrong variant");
        },
      },
      {
        env: OK({ type: "Ack" }),
        assert: (e) => expect(e.response?.type).toBe("Ack"),
      },
    ];

    for (const c of cases) {
      const { transport } = recordingTransport(c.env);
      const client = new BackstageClient(transport);
      c.assert(await client.exec({ type: "ListProcesses" }));
    }
  });

  it("attaches the audit record from the envelope", async () => {
    const { transport } = recordingTransport(OK({ type: "ProcessList", data: [] }, AUDIT));
    const client = new BackstageClient(transport);
    const env = await client.listProcesses();
    expect(env.audit?.hash).toBe("abcdef0123456789");
    expect(env.audit?.outcome).toBe("authorized");
  });

  it("rejects a malformed envelope missing `ok`", () => {
    expect(() => parseEnvelope("{}")).toThrowError(/missing 'ok'/);
  });
});

describe("BackstageClient error surfacing", () => {
  it("returns a `denied` error without throwing", async () => {
    const env: Envelope = {
      ok: false,
      error: { kind: "denied", message: "operator lacks the ProcessKill capability" },
      audit: { hash: "deadbeef", outcome: "denied" },
    };
    const { transport } = recordingTransport(env);
    const client = new BackstageClient(transport);
    const out = await client.exec({ type: "KillProcess", data: { pid: 1, image: "x", owner: "u" } });
    expect(out.ok).toBe(false);
    expect(out.error?.kind).toBe("denied");
    expect(out.audit?.outcome).toBe("denied"); // audit present even on denial
  });
});

describe("confirm-retry flow", () => {
  const NEEDS: Envelope = {
    ok: false,
    error: { kind: "needs_confirmation", message: "type the machine name to confirm", confirm_token: "tok-1" },
    audit: { hash: "h0", outcome: "needs_confirmation" },
  };
  const ACK: Envelope = { ok: true, response: { type: "Ack" }, audit: { hash: "h1", outcome: "confirmed" } };

  it("retries once, echoing the agent's confirm token in the body (docs/58 §3)", async () => {
    const { transport, calls } = recordingTransport([NEEDS, ACK]);
    const client = new BackstageClient(transport);
    const confirm = vi.fn().mockResolvedValue(true);

    const out = await client.controlService({ service: "Spooler", verb: "restart" }, confirm);

    expect(confirm).toHaveBeenCalledOnce();
    expect(calls).toHaveLength(2);
    expect(calls[0].path).toBe(BACKSTAGE_EXEC_PATH); // first attempt, no confirm
    expect(calls[1].path).toBe(`${BACKSTAGE_EXEC_PATH}?confirm=1`); // retry (the dev HTTP seam)
    // The same request, plus the token as a top-level `confirm` (the session channel has no query).
    expect(JSON.parse(calls[1].body)).toEqual({ ...JSON.parse(calls[0].body), confirm: "tok-1" });
    expect("confirm" in JSON.parse(calls[0].body)).toBe(false);
    expect(out.ok).toBe(true);
    expect(out.response?.type).toBe("Ack");
    expect(out.audit?.outcome).toBe("confirmed");
  });

  it("does NOT retry when the operator cancels, returning the needs_confirmation envelope", async () => {
    const { transport, calls } = recordingTransport([NEEDS, ACK]);
    const client = new BackstageClient(transport);
    const confirm = vi.fn().mockResolvedValue(false);

    const out = await client.killProcess({ pid: 9, image: "x.exe", owner: "u" }, confirm);

    expect(confirm).toHaveBeenCalledOnce();
    expect(calls).toHaveLength(1); // no retry
    expect(out.ok).toBe(false);
    expect(out.error?.kind).toBe("needs_confirmation");
  });

  it("hands the pending envelope to the confirm callback (the dialog shows the resolved target)", async () => {
    const { transport } = recordingTransport([NEEDS, ACK]);
    const client = new BackstageClient(transport);
    const confirm = vi.fn().mockResolvedValue(true);
    await client.deletePath("D:\\old", confirm);
    expect(confirm).toHaveBeenCalledWith(NEEDS);
  });

  it("an agent that sends no token is too old to confirm: no dialog, no retry, a plain message", async () => {
    const OLD: Envelope = {
      ok: false,
      error: { kind: "needs_confirmation", message: "type the machine name to confirm" },
      audit: { hash: "h0", outcome: "needs_confirmation" },
    };
    const { transport, calls } = recordingTransport([OLD, ACK]);
    const client = new BackstageClient(transport);
    const confirm = vi.fn().mockResolvedValue(true);
    const out = await client.writeRegistry({ path: "HKLM\\SYSTEM\\x", value_name: "v", new_value: "n" }, confirm);
    expect(confirm).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
    expect(out.error?.message).toBe(AGENT_TOO_OLD_TO_CONFIRM);
  });

  it("a second needs_confirmation (the target changed) is returned, never retried again", async () => {
    const NEEDS2: Envelope = { ...NEEDS, error: { ...NEEDS.error!, confirm_token: "tok-2" } };
    const { transport, calls } = recordingTransport([NEEDS, NEEDS2, ACK]);
    const client = new BackstageClient(transport);
    const confirm = vi.fn().mockResolvedValue(true);
    const out = await client.deletePath("D:\\old", confirm);
    expect(calls).toHaveLength(2);
    expect(out.error?.confirm_token).toBe("tok-2");
  });

  it("a session client needs the advertised `confirm` feature: a token alone does not retry", async () => {
    const { transport, calls } = recordingTransport([NEEDS, NEEDS, ACK]);
    const client = new BackstageClient(transport, { sessionChannel: true });
    const confirm = vi.fn().mockResolvedValue(true);
    const before = await client.deletePath("D:\\old", confirm);
    expect(confirm).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
    expect(before.error?.message).toBe(AGENT_TOO_OLD_TO_CONFIRM);
    client.allowConfirmation();
    const after = await client.deletePath("D:\\old", confirm);
    expect(confirm).toHaveBeenCalledOnce();
    expect(after.ok).toBe(true);
  });

  it("does not prompt at all when the first attempt already succeeds", async () => {
    const { transport, calls } = recordingTransport(ACK);
    const client = new BackstageClient(transport);
    const confirm = vi.fn().mockResolvedValue(true);

    const out = await client.controlService({ service: "BITS", verb: "start" }, confirm);

    expect(confirm).not.toHaveBeenCalled();
    expect(calls).toHaveLength(1);
    expect(out.ok).toBe(true);
  });
});

// --- New-panel smoke tests -------------------------------------------------

describe("new panel components render the fixtures", () => {
  it("SystemInfoPanel renders identity + humanized resources", () => {
    const html = renderToStaticMarkup(createElement(SystemInfoPanel, { info: SAMPLE_SYSTEM_INFO }));
    expect(html).toContain("ACCT-WS-07");
    expect(html).toContain("Logged-in user");
    expect(html).toContain("jdoe"); // console user surfaced
    expect(html).toContain("Windows 11 Pro");
    expect(html).toContain("GB"); // memory humanized
    expect(html).toContain("d "); // uptime with days, e.g. "4d 07h 29m"
  });

  it("EventLogPanel renders rows, level badges, and null fallbacks", () => {
    const html = renderToStaticMarkup(createElement(EventLogPanel, { rows: SAMPLE_EVENT_LOG }));
    expect(html).toContain("Service Control Manager");
    expect(html).toContain('data-tone="bad"'); // Critical row
    expect(html).toContain("—"); // sparse record null fields
  });

  it("EventLogPanel renders an empty state", () => {
    const html = renderToStaticMarkup(createElement(EventLogPanel, { rows: [] }));
    expect(html).toContain("No events.");
  });
});

describe("audit label coercion (string vs live Rust-enum object)", () => {
  it("reads a bare-string outcome/action (mock/fixture form)", () => {
    const a = { hash: "abc", outcome: "authorized", action: "GetSystemInfo" } as AuditEvent;
    expect(auditOutcomeLabel(a)).toBe("authorized");
    expect(auditActionLabel(a)).toBe("GetSystemInfo");
  });

  it("reads the live agent's object outcome/action without throwing", () => {
    // Exactly the shape the streaming agent sends (Rust `Outcome`/`Action` enums serialized).
    const a = {
      hash: "9e9c596b6759e407",
      outcome: { result: "ok" },
      action: { kind: "consent_signal", policy: "read-only" },
    } as unknown as AuditEvent;
    expect(auditOutcomeLabel(a)).toBe("ok");
    expect(auditActionLabel(a)).toBe("consent_signal");
  });

  it("falls back safely on unexpected shapes", () => {
    const a = { hash: "x", outcome: {} } as unknown as AuditEvent;
    expect(auditOutcomeLabel(a)).toBe("unknown");
    expect(auditActionLabel(a)).toBe("");
  });
});

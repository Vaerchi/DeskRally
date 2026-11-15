import { describe, expect, it, vi } from "vitest";
import { ConsoleApiClient, ConsoleApiError } from "./console_api";
import { runAdhocCommand, type AdhocCommandSpec } from "./adhoc_run";

const SPEC: AdhocCommandSpec = { shell: "powershell", runAs: "user", body: "Get-PSDrive" };

function fakeFetch(responder: (url: string, init?: RequestInit) => Response) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return Promise.resolve(responder(url, init));
  };
  return { fn, calls };
}
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

describe("runAdhocCommand", () => {
  it("authorizes first, then sends exactly the returned command with the mapped shell and run-as", async () => {
    const order: string[] = [];
    const api = {
      requestCommandRun: vi.fn(async (sid: string, shell: string, runAs: string, body: string) => {
        order.push(`request ${sid} ${shell} ${runAs} ${body}`);
        return { request_id: "req-1", shell: "powershell" as const, run_as: "user" as const, command: "& (wrapped)" };
      }),
    };
    const sent: unknown[] = [];
    const out = await runAdhocCommand(SPEC, {
      api,
      currentSessionId: () => "sess-1",
      isCurrent: () => true,
      sendRunCommand: (...a) => {
        order.push("send");
        sent.push(a);
      },
    });
    expect(out).toEqual({ sent: true, requestId: "req-1" });
    expect(order).toEqual(["request sess-1 powershell user Get-PSDrive", "send"]);
    expect(sent).toEqual([["& (wrapped)", "PowerShell", true]]);
  });

  it("maps a cmd grant to the Cmd shell and system to as_user=false", async () => {
    const send = vi.fn();
    await runAdhocCommand({ shell: "cmd", runAs: "system", body: "ipconfig" }, {
      api: { requestCommandRun: async () => ({ request_id: "r", shell: "cmd", run_as: "system", command: "ipconfig" }) },
      currentSessionId: () => "s",
      isCurrent: () => true,
      sendRunCommand: send,
    });
    expect(send).toHaveBeenCalledWith("ipconfig", "Cmd", false);
  });

  it("sends nothing without a session record", async () => {
    const api = { requestCommandRun: vi.fn() };
    const send = vi.fn();
    const out = await runAdhocCommand(SPEC, { api, currentSessionId: () => null, isCurrent: () => true, sendRunCommand: send });
    expect(out.sent).toBe(false);
    expect(api.requestCommandRun).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  it("sends nothing when the control plane refuses, and reports its reason", async () => {
    const send = vi.fn();
    const out = await runAdhocCommand(SPEC, {
      api: {
        requestCommandRun: async () => {
          throw new ConsoleApiError(409, "could not run the command: this session is view-only; commands cannot run");
        },
      },
      currentSessionId: () => "s",
      isCurrent: () => true,
      sendRunCommand: send,
    });
    expect(out).toEqual({ sent: false, stale: false, error: "could not run the command: this session is view-only; commands cannot run" });
    expect(send).not.toHaveBeenCalled();
  });

  it("sends nothing when the session changed while the request was in flight", async () => {
    let session = "sess-1";
    const send = vi.fn();
    const out = await runAdhocCommand(SPEC, {
      api: {
        requestCommandRun: async () => {
          session = "sess-2"; // the operator moved to another machine meanwhile
          return { request_id: "r", shell: "powershell", run_as: "system", command: "x" };
        },
      },
      currentSessionId: () => session,
      isCurrent: () => true,
      sendRunCommand: send,
    });
    expect(out.sent).toBe(false);
    expect(send).not.toHaveBeenCalled();
  });

  it("a run that lands after a newer command started is stale: nothing sent, no error reported", async () => {
    let current = true;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const send = vi.fn();
    const pending = runAdhocCommand(SPEC, {
      api: {
        requestCommandRun: async () => {
          await gate;
          return { request_id: "r", shell: "powershell", run_as: "system", command: "x" };
        },
      },
      currentSessionId: () => "sess-1",
      isCurrent: () => current,
      sendRunCommand: send,
    });
    current = false; // the operator started another command / switched sessions meanwhile
    release();
    expect(await pending).toEqual({ sent: false, stale: true });
    expect(send).not.toHaveBeenCalled();
  });
});

describe("console api: requestCommandRun", () => {
  it("posts the shell/run_as/body to the session's command-run endpoint and returns the grant", async () => {
    const { fn, calls } = fakeFetch(() => json({ request_id: "r", shell: "cmd", run_as: "system", command: "dir" }));
    const c = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok" });
    const grant = await c.requestCommandRun("sess/1", "cmd", "system", "dir");
    expect(grant).toEqual({ request_id: "r", shell: "cmd", run_as: "system", command: "dir" });
    expect(`${calls[0].init?.method} ${calls[0].url}`).toBe("POST /cp/sessions/sess%2F1/command-run");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ shell: "cmd", run_as: "system", body: "dir" });
    expect((calls[0].init?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok");
  });

  it("rejects a malformed grant response instead of sending something", async () => {
    const { fn } = fakeFetch(() => json({ request_id: "r", shell: "bash", run_as: "system", command: "ls" }));
    await expect(new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).requestCommandRun("s", "cmd", "system", "x")).rejects.toBeInstanceOf(ConsoleApiError);
  });
});

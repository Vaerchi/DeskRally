import { describe, expect, it, vi } from "vitest";
import { ConsoleApiClient, ConsoleApiError, type ToolboxItem } from "./console_api";
import { runToolboxScript } from "./toolbox_run";
import { toolboxBodyProblem, toolboxBodySize, filterToolboxItems } from "../components/ToolboxPanel";

const ITEM: ToolboxItem = {
  id: "item-1",
  name: "Disk usage",
  description: "free space",
  scope: "shared",
  shell: "powershell",
  run_as: "user",
  body: "Get-PSDrive",
  body_sha256: "0".repeat(64),
  version: 3,
  updated_at: "2026-10-16T00:00:00Z",
  mine: false,
};

describe("runToolboxScript", () => {
  it("authorizes first, then sends exactly the returned command with the mapped shell and run-as", async () => {
    const order: string[] = [];
    const api = {
      requestToolboxRun: vi.fn(async (id: string, sid: string, v: number) => {
        order.push(`request ${id} ${sid} ${v}`);
        return { request_id: "req-1", shell: "powershell" as const, run_as: "user" as const, command: "& (wrapped)" };
      }),
    };
    const sent: unknown[] = [];
    const out = await runToolboxScript(ITEM, {
      api,
      currentSessionId: () => "sess-1",
      isCurrent: () => true,
      sendRunCommand: (...a) => {
        order.push("send");
        sent.push(a);
      },
    });
    expect(out).toEqual({ sent: true, requestId: "req-1" });
    expect(order).toEqual(["request item-1 sess-1 3", "send"]);
    expect(sent).toEqual([["& (wrapped)", "PowerShell", true]]);
  });

  it("maps a cmd grant to the Cmd shell and system to as_user=false", async () => {
    const send = vi.fn();
    await runToolboxScript(ITEM, {
      api: { requestToolboxRun: async () => ({ request_id: "r", shell: "cmd", run_as: "system", command: "ipconfig" }) },
      currentSessionId: () => "s",
      isCurrent: () => true,
      sendRunCommand: send,
    });
    expect(send).toHaveBeenCalledWith("ipconfig", "Cmd", false);
  });

  it("sends nothing without a session record", async () => {
    const api = { requestToolboxRun: vi.fn() };
    const send = vi.fn();
    const out = await runToolboxScript(ITEM, { api, currentSessionId: () => null, isCurrent: () => true, sendRunCommand: send });
    expect(out.sent).toBe(false);
    expect(api.requestToolboxRun).not.toHaveBeenCalled();
    expect(send).not.toHaveBeenCalled();
  });

  it("sends nothing when the control plane refuses, and reports its reason", async () => {
    const send = vi.fn();
    const out = await runToolboxScript(ITEM, {
      api: {
        requestToolboxRun: async () => {
          throw new ConsoleApiError(409, "could not run the toolbox item: this session is view-only; commands cannot run");
        },
      },
      currentSessionId: () => "s",
      isCurrent: () => true,
      sendRunCommand: send,
    });
    expect(out).toEqual({ sent: false, stale: false, error: "could not run the toolbox item: this session is view-only; commands cannot run" });
    expect(send).not.toHaveBeenCalled();
  });

  it("sends nothing when the session changed while the request was in flight", async () => {
    let session = "sess-1";
    const send = vi.fn();
    const out = await runToolboxScript(ITEM, {
      api: {
        requestToolboxRun: async () => {
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
});

function fakeFetch(responder: (url: string, init?: RequestInit) => Response) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return Promise.resolve(responder(url, init));
  };
  return { fn, calls };
}
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });

describe("runToolboxScript: a superseded run leaves the UI alone", () => {
  for (const [label, respond] of [
    ["success", async () => ({ request_id: "r", shell: "powershell" as const, run_as: "system" as const, command: "x" })],
    ["refusal", async () => {
      throw new ConsoleApiError(409, "refused");
    }],
  ] as const) {
    it(`a ${label} that lands after a newer command started is stale: nothing sent, no error reported`, async () => {
      let current = true;
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      const send = vi.fn();
      const pending = runToolboxScript(ITEM, {
        api: {
          requestToolboxRun: async () => {
            await gate;
            return respond();
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
  }
});

describe("console api: toolbox", () => {
  it("lists with permissions and server limits", async () => {
    const { fn, calls } = fakeFetch(() => json({ items: [ITEM], can_manage_shared: true, max_powershell_bytes: 16384, max_cmd_units: 7800 }));
    const l = await new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).listToolbox();
    expect(calls[0].url).toBe("/cp/toolbox");
    expect(l).toEqual({ items: [ITEM], canManageShared: true, maxPowerShellBytes: 16384, maxCmdUnits: 7800 });
    const { fn: f2 } = fakeFetch(() => json({ items: [], can_manage_shared: "yes" }));
    expect((await new ConsoleApiClient({ baseUrl: "/cp", fetch: f2 }).listToolbox()).canManageShared).toBe(false);
  });

  it("creates with scope, updates and deletes with the expected version, and posts runs", async () => {
    const { fn, calls } = fakeFetch((url, init) => {
      if (url.endsWith("/runs")) return json({ request_id: "r", shell: "cmd", run_as: "system", command: "dir" });
      if (init?.method === "DELETE") return new Response(null, { status: 204 });
      return json({ item: ITEM }, init?.method === "POST" ? 201 : 200);
    });
    const c = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok" });
    const input = { name: "n", description: "", shell: "cmd" as const, run_as: "system" as const, body: "dir" };
    await c.createToolboxItem("personal", input);
    await c.updateToolboxItem("a/b", 4, input);
    await c.deleteToolboxItem("a/b", 5);
    await c.requestToolboxRun("a/b", "sess", 6);
    expect(calls.map((x) => `${x.init?.method} ${x.url}`)).toEqual([
      "POST /cp/toolbox",
      "PUT /cp/toolbox/a%2Fb",
      "DELETE /cp/toolbox/a%2Fb?expected_version=5",
      "POST /cp/toolbox/a%2Fb/runs",
    ]);
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ ...input, scope: "personal" });
    expect(JSON.parse(calls[1].init?.body as string)).toEqual({ ...input, expected_version: 4 });
    expect(JSON.parse(calls[3].init?.body as string)).toEqual({ session_id: "sess", expected_version: 6 });
    expect((calls[0].init?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok");
  });

  it("rejects a malformed run response instead of sending something", async () => {
    const { fn } = fakeFetch(() => json({ request_id: "r", shell: "bash", run_as: "system", command: "ls" }));
    await expect(new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).requestToolboxRun("i", "s", 1)).rejects.toBeInstanceOf(ConsoleApiError);
  });
});

describe("toolbox size rules (client mirror)", () => {
  const limits = { maxPowerShellBytes: 16384, maxCmdUnits: 7800 };
  it("counts PowerShell in UTF-8 bytes and cmd in UTF-16 units", () => {
    expect(toolboxBodySize("powershell", "€")).toBe(3);
    expect(toolboxBodySize("cmd", "€")).toBe(1);
    expect(toolboxBodySize("cmd", "😀")).toBe(2);
    expect(toolboxBodyProblem("powershell", "a".repeat(16384), limits)).toBeNull();
    expect(toolboxBodyProblem("powershell", "€".repeat(5462), limits)).toMatch(/at most 16384 bytes/);
    expect(toolboxBodyProblem("cmd", "€".repeat(7800), limits)).toBeNull();
    expect(toolboxBodyProblem("cmd", "😀".repeat(3900) + "a", limits)).toMatch(/at most 7800/);
    expect(toolboxBodyProblem("cmd", "a\nb", limits)).toMatch(/single line/);
    expect(toolboxBodyProblem("powershell", "  ", limits)).toMatch(/empty/);
    expect(toolboxBodyProblem("powershell", "a\u0000", limits)).toMatch(/NUL/);
  });
  it("filters by name or description", () => {
    expect(filterToolboxItems([ITEM], "free").length).toBe(1);
    expect(filterToolboxItems([ITEM], "nope").length).toBe(0);
  });
});

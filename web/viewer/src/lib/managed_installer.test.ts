import { expect, it } from "vitest";
import { ConsoleApiClient, CSRF_HEADER_NAME, parseInstallerWarnings } from "./console_api";

it("downloads through authenticated POST with CSRF and never places enrollment data in the URL", async () => {
  const controller = new AbortController();
  const api = new ConsoleApiClient({ cookies: () => "rmt_csrf=test-csrf", fetch: async (url, init) => {
    expect(url).toBe("/cp/managed-installer");
    expect(init?.method).toBe("POST"); expect(init?.credentials).toBe("include");
    expect(init?.cache).toBe("no-store"); expect(init?.signal).toBe(controller.signal);
    expect((init?.headers as Record<string,string>)[CSRF_HEADER_NAME]).toBe("test-csrf");
    expect(JSON.parse(init?.body as string)).toEqual({ group_id: "home" });
    return new Response("synthetic-zip", { headers: { "content-type": "application/zip" } });
  }});
  expect(await (await api.downloadManagedInstaller("home", controller.signal)).text()).toBe("synthetic-zip");
});

it("refuses HTML, empty downloads and error responses rather than saving them as installers", async () => {
  for (const response of [new Response("login page"), new Response("", {headers:{"content-type":"application/zip"}}), new Response("denied", {status:403})]) {
    const api = new ConsoleApiClient({ fetch: async () => response });
    await expect(api.downloadManagedInstaller("home", new AbortController().signal)).rejects.toThrow();
  }
});

it("cancels an oversized stream even without Content-Length", async () => {
  let cancelled = false;
  const chunk = new Uint8Array(1024 * 1024);
  const response = new Response(new ReadableStream({ pull(c) { c.enqueue(chunk); }, cancel() { cancelled = true; } }), { headers:{"content-type":"application/zip"} });
  const api = new ConsoleApiClient({ fetch: async () => response });
  await expect(api.downloadManagedInstaller("home",new AbortController().signal)).rejects.toThrow("exceeds");
  expect(cancelled).toBe(true);
});

it("only explicit server availability enables the installer", async () => {
  for (const [value, expected] of [[true,true],[false,false],["true",false],[undefined,false]]) {
    const api = new ConsoleApiClient({fetch: async () => new Response(JSON.stringify({available:value}))});
    expect(await api.managedInstallerAvailable()).toBe(expected);
  }
});

it("reads deployment-pass warnings for admins and nothing from a baked or older server", async () => {
  const pass = { available: true, mode: "pass", deployment_pass: { warnings: ["The deployment pass expires at 2026-11-01T00:00:00Z. Renew it."] } };
  const api = new ConsoleApiClient({ fetch: async () => new Response(JSON.stringify(pass)) });
  expect(await api.managedInstallerWarnings()).toEqual(["The deployment pass expires at 2026-11-01T00:00:00Z. Renew it."]);
  for (const body of [{ available: true, mode: "baked" }, { available: true }, null, { deployment_pass: { warnings: "not a list" } }]) {
    expect(parseInstallerWarnings(body)).toEqual([]);
  }
});

it("keeps only bounded strings from the warnings list", () => {
  const long = "x".repeat(1000);
  const got = parseInstallerWarnings({ deployment_pass: { warnings: [1, null, "", "a", { html: "<b>" }, long, "b", "c", "d"] } });
  expect(got).toEqual(["a", "x".repeat(400), "b", "c"]);
});

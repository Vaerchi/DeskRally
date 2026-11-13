/**
 * Login against a REAL Postgres-backed control plane — the branch nothing else tests.
 *
 * WHY THIS EXISTS. `main()` has two modes: production ⇒ Postgres stores and the real authenticator;
 * `CP_INSECURE_DEV=1` ⇒ `StubAuthenticator`, which treats every request as a full-capability owner.
 * (The mode used to be inferred from `DATABASE_URL` being absent, which is docs/25 F13 — it now has
 * to be declared, and production refuses to start without a DSN.)
 * **Every other spec in this directory spawns the control plane with `CP_INSECURE_DEV: "1"`.** So the
 * entire production authentication path had never been executed by any test, and it contained two
 * independent blockers, each of which alone made the product impossible to log into:
 *
 *   1. No way to create the first account existed at all. Only `/auth/login` and `/auth/logout` are
 *      unauthenticated; every user-creating route needs an already-authenticated admin; no migration
 *      seeds a tenant. The seeded owner lived ONLY in the DEV branch.
 *   2. The console posted `{username, password, totp}` while the server decodes
 *      `{tenant, email, password, totp_code}`. Only `password` overlapped, so login could never
 *      succeed — and it failed as the deliberately generic 401, indistinguishable from a wrong
 *      password.
 *
 * Both were found by hand while writing a deployment runbook. This spec is the harness catching them
 * instead: it runs the SAME three commands an operator runs (`migrate`, `bootstrap`, then serve),
 * and posts the SAME body the browser client builds.
 *
 * It deliberately drives HTTP rather than the browser. The login overlay only appears after a
 * `/grant/mint` returns 401, so reaching it in a browser needs a live agent session — a lot of
 * machinery between the test and the thing under test. The contract that actually broke is the
 * request body and the session cookie, and those are exercised directly here.
 */

import { test, expect } from "@playwright/test";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { CP_PORT } from "./ports";
import { ControlPlaneClient } from "../src/lib/controlplane";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");
const MIGRATIONS = resolve(CP_DIR, "migrations");

// Its own port: this control plane runs with a REAL DATABASE_URL and must not be mistaken for the
// DEV one the other specs share.
const PORT = String(Number(CP_PORT) + 7);
const BASE = `http://127.0.0.1:${PORT}`;

// A fresh tenant slug per run, which is what makes this re-runnable against a database that already
// has state: `bootstrap` refuses a tenant that already has a user, by design.
const TENANT = `e2e-auth-${Date.now()}`;
const EMAIL = `owner@${TENANT}.test`;

/**
 * Its OWN database, provisioned by scripts/verify-all.ps1.
 *
 * It cannot share the Go tests' database: `resetSchema` there installs a CURATED SUBSET of the
 * migrations with no `schema_migration` ledger, so `migrate` answers ErrNeedsBaseline and
 * `cp_create_tenant` (migration 0006, opt-in for those tests) does not exist. Isolation here is
 * correctness, not tidiness.
 */
const DB = process.env.E2E_DATABASE_URL ?? "";

let cpProc: ChildProcess | undefined;
let password = "";
let skipReason: string | null = null;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn: () => Promise<boolean>, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await fn().catch(() => false)) return true;
    await sleep(250);
  }
  return false;
}

test.describe("login against a real Postgres control plane", () => {
  test.beforeAll(async () => {
    test.setTimeout(180_000);

    if (!existsSync(CP_EXE)) {
      skipReason = `${CP_EXE} is missing — globalSetup should have built it`;
      return;
    }
    if (DB === "") {
      // Deliberately a hard message rather than a quiet skip: the gate counts a skip as a FAILURE,
      // and this spec silently not running is exactly how the production path went untested before.
      skipReason =
        "E2E_DATABASE_URL is not set, so the REAL authenticator cannot be exercised. " +
        "scripts/verify-all.ps1 creates that database and exports it for the Playwright stage. " +
        "To run this spec alone: createdb rmt_e2e_auth, then set E2E_DATABASE_URL to it.";
      return;
    }

    try {
      // 1. The operator's first command. Idempotent, so a database another run already migrated is
      //    fine — the ledger makes a second pass a no-op.
      execFileSync(CP_EXE, ["migrate", "-dir", MIGRATIONS], {
        cwd: CP_DIR,
        env: { ...process.env, MIGRATE_DATABASE_URL: DB },
        stdio: "pipe",
      });

      // 2. The command that did not exist until it was needed. Its printed password is the ONLY
      //    copy — nothing stores it in recoverable form — so parse it the way an operator reads it.
      const out = execFileSync(CP_EXE, ["bootstrap", "-tenant", TENANT, "-email", EMAIL], {
        cwd: CP_DIR,
        env: { ...process.env, DATABASE_URL: DB },
        stdio: "pipe",
      }).toString();
      password = /^password\s+(\S+)$/m.exec(out)?.[1] ?? "";
      if (password === "") {
        skipReason = `bootstrap printed no password; output was:\n${out}`;
        return;
      }
    } catch (e) {
      skipReason = `migrate/bootstrap failed: ${(e as Error).message}`;
      return;
    }

    // 3. Serve with the REAL authenticator. DATABASE_URL set is the whole point of this file.
    //
    // CP_INSECURE_ALLOW_PRIVILEGED_DB is needed because this DSN connects as `postgres`, and
    // production startup now refuses a SUPERUSER/BYPASSRLS role outright (docs/25 F13): row-level
    // security does not apply to such a role, so tenant isolation would be silently absent.
    //
    // BE CLEAR ABOUT WHAT THAT COSTS THIS SPEC: running with the escape means this file proves the
    // real AUTHENTICATOR works end to end, and proves nothing whatever about tenant isolation —
    // every query here bypasses RLS. Isolation is proven separately and properly in
    // `control-plane/rls_test.go`, which builds its own `rmt_app` pool and asserts that role is
    // neither superuser nor BYPASSRLS before testing cross-tenant visibility. Do not read a green
    // run of this spec as evidence that RLS is in force.
    cpProc = spawn(CP_EXE, [], {
      cwd: CP_DIR,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        CP_LISTEN: `127.0.0.1:${PORT}`,
        DATABASE_URL: DB,
        CP_INSECURE_ALLOW_PRIVILEGED_DB: "1",
      },
    });
    cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp:real] ${d.toString()}`));
    cpProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[cp:real:err] ${d.toString()}`));

    if (!(await waitFor(async () => (await fetch(`${BASE}/healthz`)).ok, 20_000))) {
      skipReason = `the Postgres-backed control plane did not come up on ${BASE}`;
    }
  });

  test.afterAll(async () => {
    await stopProc(cpProc);
  });

  /**
   * Logs in through the REAL `ControlPlaneClient`, not a hand-written body.
   *
   * This is the point of the whole file. A spec that posted its own JSON literal would pass
   * whatever the console actually sends — which is exactly the hole the outage came through, since
   * `controlplane.test.ts` was happily pinning the WRONG shape. Driving the shipped client means a
   * change to its field names fails HERE, against a real server, rather than being ratified by a
   * unit test that only compares the client to itself.
   *
   * The fetch wrapper exists because the client returns nothing on success and node's fetch does
   * not manage a cookie jar; the response is needed to assert the session cookie.
   */
  function clientFor(): { client: ControlPlaneClient; lastResponse: () => Response | undefined } {
    let last: Response | undefined;
    const client = new ControlPlaneClient({
      baseUrl: BASE,
      fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
        last = await fetch(input as string, init);
        return last.clone();
      },
    });
    return { client, lastResponse: () => last };
  }

  test("the bootstrapped owner can log in, and the session authorizes a protected route", async () => {
    test.skip(skipReason !== null, skipReason ?? "");

    const { client, lastResponse } = clientFor();
    await expect(
      client.login(TENANT, EMAIL, password),
      "the SHIPPED console client could not log into a real control plane — the two disagree " +
        "about the request body, which fails as a generic 401 indistinguishable from a bad password",
    ).resolves.toBeUndefined();

    const res = lastResponse()!;

    // The session cookie IS the console's authentication; a 2xx with no cookie authorizes nothing.
    const cookie = res.headers.get("set-cookie");
    expect(cookie, "login succeeded but set no session cookie").toBeTruthy();

    // And it must actually authorize. Without this the test proves a status code, not a login.
    const jar = (cookie ?? "").split(";")[0];
    const machines = await fetch(`${BASE}/machines`, { headers: { cookie: jar } });
    expect(
      machines.status,
      `the session cookie did not authorize GET /machines (${machines.status})`,
    ).toBeLessThan(300);
  });

  test("a wrong password is refused", async () => {
    test.skip(skipReason !== null, skipReason ?? "");

    // The negative control. Without it, a control plane that accepted ANY credential — which is
    // precisely what StubAuthenticator does, and what every other spec in this directory runs
    // against — would satisfy the test above.
    const { client, lastResponse } = clientFor();
    await expect(client.login(TENANT, EMAIL, `${password}-wrong`)).rejects.toThrow();
    expect(
      lastResponse()?.status,
      "a wrong password was ACCEPTED — is this really the real authenticator?",
    ).toBe(401);
  });

  test("the pre-fix console body does NOT authenticate", async () => {
    test.skip(skipReason !== null, skipReason ?? "");

    // The regression guard for the second blocker. `{username, password, totp}` is what the console
    // sent for months; the server decodes none of those names except `password`, so it must fail.
    // If this ever starts passing, someone has taught the server to accept both spellings and the
    // ambiguity that caused the outage is back.
    const res = await fetch(`${BASE}/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: EMAIL, password }),
    });
    expect(res.status, "the OLD console payload authenticated; the field-name ambiguity is back").toBe(401);
  });

  test("an unauthenticated request to a protected route is refused", async () => {
    test.skip(skipReason !== null, skipReason ?? "");

    // Proves the middleware is actually enforcing here. Under StubAuthenticator this returns 200,
    // so this single assertion is what distinguishes a real control plane from the dev one — and it
    // is the assertion that would have shown, at any point, that no test was exercising production.
    const res = await fetch(`${BASE}/machines`);
    expect(
      res.status,
      "GET /machines answered without a session — this control plane is NOT using the real " +
        "authenticator, so nothing else in this file proves what it claims",
    ).toBe(401);
  });
});

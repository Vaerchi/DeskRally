import { describe, it, expect } from "vitest";
import appSource from "../App.tsx?raw";
import { ControlPlaneError } from "./controlplane";
import { resumeGrant, GrantOpGuard, GRANT_RESUME_BACKOFF_MS, type GrantResumeDeps } from "./grant_resume";

const NEW_SESSION = "33333333-3333-4333-8333-333333333333";

function harness(over: Partial<GrantResumeDeps> & { mints?: Array<string | ControlPlaneError> } = {}) {
  const minted: string[] = [];
  const installed: string[] = [];
  const sleeps: number[] = [];
  const queue = [...(over.mints ?? ["GRANT-1"])];
  const deps: GrantResumeDeps = {
    hadGrant: true,
    sessionId: NEW_SESSION,
    mint: async (sessionId) => {
      minted.push(sessionId);
      const next = queue.length > 1 ? queue.shift()! : queue[0];
      if (next instanceof ControlPlaneError) throw next;
      return next;
    },
    install: (g) => installed.push(g),
    isCurrent: () => true,
    sleep: async (ms) => { sleeps.push(ms); },
    ...over,
  };
  return { deps, minted, installed, sleeps };
}

describe("resumeGrant (re-mint after a session resumes)", () => {
  it("resume with a prior grant: exactly one mint for the NEW session id, then one install of the fresh grant", async () => {
    const h = harness();
    expect(await resumeGrant(h.deps)).toBe("installed");
    expect(h.minted).toEqual([NEW_SESSION]);
    expect(h.installed).toEqual(["GRANT-1"]);
  });

  it("never held a grant: nothing is minted or installed", async () => {
    const h = harness({ hadGrant: false });
    expect(await resumeGrant(h.deps)).toBe("skipped");
    expect(h.minted).toEqual([]);
    expect(h.installed).toEqual([]);
  });

  it("nothing to bind to (direct-connect, no session id): skipped", async () => {
    const h = harness({ sessionId: null });
    expect(await resumeGrant(h.deps)).toBe("skipped");
    expect(h.minted).toEqual([]);
  });

  it("403 is final: no retry loop, nothing installed (the panel's Get access path stays)", async () => {
    const h = harness({ mints: [new ControlPlaneError(403, "capability denied")] });
    expect(await resumeGrant(h.deps)).toBe("denied");
    expect(h.minted).toHaveLength(1);
    expect(h.installed).toEqual([]);
    expect(h.sleeps).toEqual([]);
  });

  it("401 is final and reported to the auth boundary", async () => {
    let unauth = 0;
    const h = harness({ mints: [new ControlPlaneError(401, "unauthorized")], onUnauthorized: () => unauth++ });
    expect(await resumeGrant(h.deps)).toBe("denied");
    expect(unauth).toBe(1);
    expect(h.minted).toHaveLength(1);
  });

  it("429 backs off (2s, then 6s) and re-mints, installing once it succeeds", async () => {
    const limited = new ControlPlaneError(429, "rate limited");
    const h = harness({ mints: [limited, limited, "GRANT-OK"] });
    expect(await resumeGrant(h.deps)).toBe("installed");
    expect(h.sleeps).toEqual([2_000, 6_000]);
    expect(h.minted).toHaveLength(3);
    expect(h.installed).toEqual(["GRANT-OK"]);
  });

  it("429 forever gives up after the backoff budget instead of hammering the endpoint", async () => {
    const h = harness({ mints: [new ControlPlaneError(429, "rate limited")] });
    expect(await resumeGrant(h.deps)).toBe("gave-up");
    expect(h.minted).toHaveLength(GRANT_RESUME_BACKOFF_MS.length + 1);
    expect(h.sleeps).toEqual([...GRANT_RESUME_BACKOFF_MS]);
    expect(h.installed).toEqual([]);
  });

  it("a 500 or a network failure is not retried", async () => {
    const h = harness({ mints: [new ControlPlaneError(500, "boom")] });
    expect(await resumeGrant(h.deps)).toBe("gave-up");
    expect(h.minted).toHaveLength(1);
    const n = harness();
    n.deps.mint = async () => { throw new TypeError("network"); };
    expect(await resumeGrant(n.deps)).toBe("gave-up");
  });

  it("a session replaced while the mint was in flight never receives the grant", async () => {
    let current = true;
    const h = harness({ isCurrent: () => current });
    const origMint = h.deps.mint;
    h.deps.mint = async (s) => { const g = await origMint(s); current = false; return g; };
    expect(await resumeGrant(h.deps)).toBe("stale");
    expect(h.installed).toEqual([]);
  });

  it("a session replaced during the 429 backoff is not re-minted for", async () => {
    let current = true;
    const h = harness({ mints: [new ControlPlaneError(429, "rate limited")], isCurrent: () => current, sleep: async () => { current = false; } });
    expect(await resumeGrant(h.deps)).toBe("stale");
    expect(h.minted).toHaveLength(1);
  });

  it("always mints fresh: two resumes mint twice and never re-send the first grant", async () => {
    const h = harness({ mints: ["G-A", "G-B"] });
    await resumeGrant(h.deps);
    await resumeGrant(h.deps);
    expect(h.installed).toEqual(["G-A", "G-B"]);
    expect(h.minted).toHaveLength(2);
  });
});

describe("GrantOpGuard (one grant operation per session)", () => {
  it("an automatic resume never starts while a manual one is in flight", () => {
    const g = new GrantOpGuard();
    const manual = g.begin("manual", NEW_SESSION);
    expect(manual).not.toBeNull();
    expect(g.begin("auto", NEW_SESSION)).toBeNull();
  });

  it("manual Get access DURING the automatic 429 backoff supersedes it: the automatic one never installs", async () => {
    const g = new GrantOpGuard();
    const auto = g.begin("auto", NEW_SESSION)!;
    const installed: string[] = [];
    let minted = 0;
    const out = await resumeGrant({
      hadGrant: true,
      sessionId: NEW_SESSION,
      mint: async () => {
        minted++;
        if (minted === 1) throw new ControlPlaneError(429, "rate limited");
        return "AUTO-GRANT";
      },
      install: (x) => installed.push(x),
      isCurrent: () => g.owns(auto),
      sleep: async () => { g.begin("manual", NEW_SESSION); installed.push("MANUAL-GRANT"); },
    });
    expect(out).toBe("stale");
    expect(minted).toBe(1);
    expect(installed).toEqual(["MANUAL-GRANT"]);
  });

  it("an automatic mint that resolves AFTER the manual install does not overwrite it", async () => {
    const g = new GrantOpGuard();
    const auto = g.begin("auto", NEW_SESSION)!;
    const installed: string[] = [];
    let release!: (v: string) => void;
    const slow = new Promise<string>((r) => (release = r));
    const run = resumeGrant({
      hadGrant: true, sessionId: NEW_SESSION,
      mint: () => slow, install: (x) => installed.push(x), isCurrent: () => g.owns(auto),
    });
    const manual = g.begin("manual", NEW_SESSION)!;
    if (g.owns(manual)) installed.push("MANUAL-GRANT");
    release("AUTO-GRANT");
    expect(await run).toBe("stale");
    expect(installed).toEqual(["MANUAL-GRANT"]);
  });

  it("end() frees the slot only for the owner; reset() (teardown) revokes everyone", () => {
    const g = new GrantOpGuard();
    const a = g.begin("auto", NEW_SESSION)!;
    const m = g.begin("manual", NEW_SESSION)!;
    g.end(a);
    expect(g.owns(m)).toBe(true);
    g.reset();
    expect(g.owns(m)).toBe(false);
    expect(g.begin("auto", NEW_SESSION)).not.toBeNull();
  });
});

// App.tsx is not collected by vitest, so pin its wiring by source text (the e2e in
// supervisor_session_recovery.spec.ts proves the behaviour; this catches a silent unplug).
describe("App.tsx wiring of grant resume", () => {
  const src = appSource.replace(/\r\n/g, "\n");
  it("remembers the grant only after the agent acks it, and clears it (and the op guard) on a non-recovery teardown", () => {
    expect(src).toMatch(/onGrantInstalled: \(\) => \{\n\s+grantHeldRef\.current = true;/);
    expect(src).toMatch(/if \(!preserveRecovery\) \{[^}]*grantHeldRef\.current = false;/);
    expect(src).toContain("grantOpRef.current.reset();");
  });
  it("re-mints only on a recovering connect with a prior grant, claiming the shared guard as automatic", () => {
    expect(src).toMatch(/recovering && grantHeldRef\.current && resumeSessionId\n\s+\? grantOpRef\.current\.begin\("auto", resumeSessionId\)/);
    expect(src).toContain("const owns = () => isCurrent() && controlRef.current === control && guard.owns(resumeToken);");
    expect(src).toContain("isCurrent: owns,");
  });
  it("a denied (401/403) resume forgets the held grant so later recoveries do not mint again", () => {
    expect(src).toContain('if (outcome === "denied" && owns()) grantHeldRef.current = false;');
  });
  it("wires 401 to the auth boundary and surfaces non-retried failures in the panel", () => {
    expect(src).toContain("onUnauthorized: () => { if (owns()) authSession.expire(); },");
    expect(src).toContain("setGrantResumeNotice(");
    expect(src).toContain("grantNotice={grantResumeNotice}");
  });
  it("manual Get access takes the guard and checks ownership right before installing", () => {
    expect(src).toContain('guard.begin("manual", grantSessionId)');
    expect(src).toContain("control === controlRef.current && guard.owns(token)");
  });
});

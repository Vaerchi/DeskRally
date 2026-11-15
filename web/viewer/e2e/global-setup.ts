/**
 * Playwright globalSetup: build the Go server binaries the specs spawn, ONCE per run.
 *
 * # The defect this exists to close
 *
 * Every control-plane spec used to build its own binary guarded by `if (!existsSync(exe))`. That
 * makes the FIRST run build it and **every run after that reuse whatever is on disk, forever.** So a
 * change to the control plane was not exercised by any browser spec until somebody happened to delete
 * `control-plane/controlplane.exe` by hand — and nothing in the suite, or the gate, could tell you
 * that had not happened. The specs passed. They were testing a different program.
 *
 * It was found the way these things are always found: a new e2e asserting a brand-new control-plane
 * behaviour failed, with the behaviour demonstrably working in the Go tests AND on the VM. The
 * control plane under test was three hours old.
 *
 * This is the same shape as the missing `typecheck` suite (docs/07 loop 82): a whole defect class the
 * gate structurally could not see, because the check that would have caught it was never run.
 *
 * # Why globalSetup rather than an unconditional build per spec
 *
 * An unconditional `go build` in each `beforeAll` is correct but costs a cached rebuild per spec —
 * measured at ~3.3 s (control plane) + ~4.0 s (signaling) on this machine, which across ~15 spec
 * files is minutes of gate time for no added safety. Here it happens once: ~7 s when nothing changed,
 * ~30 s after a Go edit. Playwright re-evaluates the CONFIG in every worker, but globalSetup runs
 * exactly once, before any worker starts.
 *
 * Specs no longer build anything. They assert the binary exists and fail loudly if it does not, so a
 * missing binary is a hard error rather than a silent fallback to something stale.
 */
import { execFileSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// This project is ESM, so there is no `__dirname` — resolve from import.meta.url exactly as the specs do.
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");

/** The binaries the e2e specs spawn, with where and how to build each. */
export const GO_BINARIES = [
  {
    exe: resolve(REPO, "control-plane", "controlplane.exe"),
    dir: resolve(REPO, "control-plane"),
    target: "./cmd/controlplane",
  },
  {
    exe: resolve(REPO, "server", "signaling", "signaling.exe"),
    dir: resolve(REPO, "server", "signaling"),
    target: ".",
  },
  // The hostname-theming fixture (docs/66 stage 2): the REAL control-plane handler over in-memory branding and
  // hostname stores, with an edge stand-in that takes the authority from a header. join_brand_host.spec.ts spawns it.
  // TEST-ONLY: it binds loopback addresses only and is never part of a release.
  {
    exe: resolve(REPO, "control-plane", "cpthemefixture.exe"),
    dir: resolve(REPO, "control-plane"),
    target: "./cmd/cpthemefixture",
  },
] as const;

export default function globalSetup(): void {
  for (const { exe, dir, target } of GO_BINARIES) {
    const before = existsSync(exe) ? statSync(exe).mtimeMs : 0;
    const started = Date.now();
    // UNCONDITIONAL. `go build` is incremental and content-addressed, so this is a no-op when nothing
    // changed and a real rebuild when something did — which is the entire point. Do not reintroduce an
    // existsSync guard here: "the file is present" says nothing about which source produced it.
    execFileSync("go", ["build", "-o", exe, target], { cwd: dir, stdio: "inherit" });
    const after = statSync(exe).mtimeMs;
    const ms = Date.now() - started;
    // Log whether the binary actually CHANGED. On a run that is meant to exercise a Go change, seeing
    // "unchanged" here is the signal that something is wrong with the build inputs, not with the test.
    console.log(
      `[e2e:setup] ${exe.replace(REPO, ".")} ${after !== before ? "REBUILT" : "unchanged"} in ${ms}ms`,
    );
  }
}

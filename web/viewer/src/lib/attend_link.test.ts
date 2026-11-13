import { describe, expect, it } from "vitest";
import { attendLaunchUri, canonicalOrigin, deploymentScheme, validatedAttendCode } from "./attend_link";

describe("validatedAttendCode", () => {
  it("accepts new 8-character and legacy 13-character codes", () => {
    expect(validatedAttendCode("7k3m9r2t")).toBe("7K3M9R2T");
    for (const bad of ["1234567", "123456789", "7K3M-9R2T", "1234567I", "1234567U"]) expect(validatedAttendCode(bad)).toBe("");
    expect(validatedAttendCode("0123456789abc")).toBe("0123456789ABC");
    for (const raw of ["", "0123456789AB", "0123456789ABCD", "0123456789ABC\n",
      "0123456789ABI", "0123456789ABL", "0123456789ABO", "0123456789ABU",
      "ABC;whoami", "ABC&whoami", "$(whoami)", "`whoami`", "ABC%26whoami"]) {
      expect(validatedAttendCode(raw), raw).toBe("");
    }
  });
});

describe("deploymentScheme", () => {
  // THE CROSS-LANGUAGE GOLDEN VECTORS. These exact `(origin → scheme)` pairs are asserted
  // byte-for-byte in `crates/agent-windows/src/uri.rs` too (deployment_scheme_golden_vectors_...).
  // If either side's canonicalization or FNV-1a drifts, one suite goes red — which is the point:
  // the agent registers the scheme and the console must emit a link for the SAME one.
  it("matches the agent's golden vectors byte-for-byte", () => {
    expect(deploymentScheme("https://cp.example.com")).toBe("rmt-ef00d58d898ca752");
    expect(deploymentScheme("https://cp.example.com:8443")).toBe("rmt-7e8af514034ea1b1");
    expect(deploymentScheme("https://support.example.com")).toBe("rmt-caf7983af7c5a89a");
    expect(deploymentScheme("http://127.0.0.1:5173")).toBe("rmt-a099e98b44c17566");
    expect(deploymentScheme("http://localhost")).toBe("rmt-06dafc8df10020c4");
  });

  it("collapses every spelling of one origin to a single scheme", () => {
    // The console passes `window.location.origin` (already canonical); the agent's configured
    // `control_plane_url` may carry a path, a default port, case, or userinfo. All must agree.
    const base = deploymentScheme("https://cp.example.com");
    for (const equivalent of [
      "https://cp.example.com/",
      "https://cp.example.com/cp",
      "https://cp.example.com:443",
      "HTTPS://CP.EXAMPLE.COM",
      "https://tech@cp.example.com/cp",
      "https://cp.example.com/cp?x=1#f",
    ]) {
      expect(deploymentScheme(equivalent)).toBe(base);
    }
    // Genuinely different origins must not collide.
    expect(deploymentScheme("http://cp.example.com")).not.toBe(base);
    expect(deploymentScheme("https://cp.example.com:8443")).not.toBe(base);
  });

  it("canonicalizes to the origin the way window.location.origin does", () => {
    expect(canonicalOrigin("https://cp.example.com/cp")).toBe("https://cp.example.com");
    expect(canonicalOrigin("https://cp.example.com:443/")).toBe("https://cp.example.com");
    expect(canonicalOrigin("http://localhost:80")).toBe("http://localhost");
    expect(canonicalOrigin("http://localhost:5173")).toBe("http://localhost:5173");
    expect(canonicalOrigin("HTTPS://User@CP.Example.com/x")).toBe("https://cp.example.com");
    // Userinfo that itself contains '@': lastIndexOf must be used, not indexOf.
    // Mutation indexOf("@") → host becomes "name@cp.example.com" instead of "cp.example.com".
    expect(canonicalOrigin("https://user@name@cp.example.com")).toBe("https://cp.example.com");
  });

  it("returns bare host+port when input carries no scheme (else arm of scheme-ternary)", () => {
    // A scheme-less input (no '://') leaves `scheme` empty; the ternary must return
    // `${host}${portPart}` — NOT `${scheme}://${host}${portPart}` which would yield '://host'.
    expect(canonicalOrigin("cp.example.com")).toBe("cp.example.com");
    expect(canonicalOrigin("cp.example.com:8080")).toBe("cp.example.com:8080");
    expect(canonicalOrigin("  cp.example.com  ")).toBe("cp.example.com");
  });

  it("handles IPv6 bracketed literals (lines 65-70 branch)", () => {
    // Non-default port is preserved.
    expect(canonicalOrigin("https://[::1]:8080")).toBe("https://[::1]:8080");
    // No port after the closing bracket.
    expect(canonicalOrigin("https://[::1]")).toBe("https://[::1]");
    // Default HTTPS port (443) is stripped, matching window.location.origin behaviour.
    expect(canonicalOrigin("https://[::1]:443")).toBe("https://[::1]");
    // Default HTTP port (80) is stripped.
    expect(canonicalOrigin("http://[::1]:80")).toBe("http://[::1]");
    // Path, query and fragment are discarded.
    expect(canonicalOrigin("https://[::1]:8080/path?q=1#f")).toBe("https://[::1]:8080");
    // Userinfo before '@' is stripped; IPv6 host and port survive.
    expect(canonicalOrigin("https://admin@[::1]:8080/cp")).toBe("https://[::1]:8080");
    // Userinfo containing '@' before an IPv6 literal: lastIndexOf must be used.
    // Mutation indexOf("@") → host becomes "admin@[::1]" instead of "[::1]".
    expect(canonicalOrigin("https://user@admin@[::1]:8080/cp")).toBe("https://[::1]:8080");
    // Longer address with non-default port.
    expect(canonicalOrigin("https://[2001:db8::1]:9000")).toBe("https://[2001:db8::1]:9000");
    // Longer address with no port.
    expect(canonicalOrigin("https://[2001:db8::1]")).toBe("https://[2001:db8::1]");
  });
});

describe("attendLaunchUri", () => {
  it("builds the namespaced rmt-<fp>://attend URI the agent's parser accepts", () => {
    // The scheme is derived from the SAME origin the `cp` param carries, so the agent registered
    // for this deployment is the one the shell launches.
    expect(attendLaunchUri("ABCD1234EFGH", "https://support.example.com")).toBe(
      "rmt-caf7983af7c5a89a://attend?code=ABCD1234EFGH&cp=https%3A%2F%2Fsupport.example.com%2Fcp",
    );
  });

  it("offers no link at all when there is no code", () => {
    // A link to `<CODE>` would be a button that cannot work. The copy-paste command is still
    // useful with a placeholder in it; a dead link is not.
    expect(attendLaunchUri("", "https://support.example.com")).toBeNull();
    expect(attendLaunchUri("   ", "https://support.example.com")).toBeNull();
  });

  it("percent-encodes the control-plane URL rather than embedding its separators raw", () => {
    // The agent's parser splits on `&` and `=` and REFUSES a raw `#`/space instead of guessing, so
    // an un-encoded value fails closed rather than arriving truncated. `:` and `/` are exactly the
    // characters that would truncate `cp` at the scheme.
    const uri = attendLaunchUri("CODE", "http://127.0.0.1:5173")!;
    expect(uri).toContain("cp=http%3A%2F%2F127.0.0.1%3A5173%2Fcp");
    expect(uri).not.toContain("cp=http://");
    // …and the scheme is this deployment's, not bare `rmt`.
    expect(uri.startsWith("rmt-a099e98b44c17566://")).toBe(true);
  });

  it("encodes a code containing characters the agent would refuse raw", () => {
    // The agent's allow-list refuses these outright; the point here is that the browser side never
    // emits them raw, so a refusal is always about the CODE and never about our encoding.
    const uri = attendLaunchUri("A B#C", "https://x.example")!;
    expect(uri).toContain("code=A%20B%23C");
    expect(uri).not.toMatch(/code=A B/);
    // `+` must never appear as a stand-in for a space: the agent reads `+` literally.
    expect(uri).not.toContain("code=A+B");
  });

  it("does not double a trailing slash on the origin", () => {
    expect(attendLaunchUri("C", "https://x.example/")).toContain("cp=https%3A%2F%2Fx.example%2Fcp");
  });
});

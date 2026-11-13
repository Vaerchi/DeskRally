import { describe, expect, it } from "vitest";

import { tenantFromHostname } from "./tenant_from_host";

describe("tenantFromHostname", () => {
  it("takes the subdomain of a real deployment hostname", () => {
    expect(tenantFromHostname("main.deskrally.com")).toBe("main");
    expect(tenantFromHostname("acme.example.co.uk")).toBe("acme");
  });

  it("normalises case and a trailing root dot", () => {
    expect(tenantFromHostname("DeskRally.Example.COM")).toBe("deskrally");
    expect(tenantFromHostname("bridge.example.com.")).toBe("bridge");
  });

  // An apex domain has no tenant label. Returning "example" here would prefill a confident wrong
  // answer on every single-domain deployment — worse than prefilling nothing, because the operator
  // must first notice it is wrong.
  it("returns nothing for an apex domain", () => {
    expect(tenantFromHostname("example.com")).toBe("");
  });

  it("returns nothing where no subdomain can name a tenant", () => {
    for (const h of ["localhost", "", "   ", "127.0.0.1", "192.168.1.50", "::1", "[::1]", "www.example.com"]) {
      expect(tenantFromHostname(h), `hostname ${h!}`).toBe("");
    }
  });

  // The dev and e2e consoles are served from localhost, so the field must simply start empty there
  // rather than prefilling something that then fails against a real control plane.
  it("is empty in dev, which is what keeps the field usable there", () => {
    expect(tenantFromHostname("localhost")).toBe("");
  });
});

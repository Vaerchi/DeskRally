/**
 * The pure rules of the platform operator's hostname and branding-review screens (docs/66 2k): status wording, which
 * actions a row offers, the approve gate and the exact approve body, and how a refusal reads.
 */

import { describe, expect, it } from "vitest";
import { ConsoleApiError } from "./console_api";
import type { BrandingReviewResult, HostnameAssignment } from "./console_api";
import {
  approveBlock,
  assignWarnings,
  buildApproveRequest,
  draftBrand,
  draftLogoSrc,
  groupFindings,
  hostnameActions,
  hostnameStatusLabel,
  reasonOk,
  reviewFailure,
  STALE_TEXT,
} from "./platform_branding";

const NOW = new Date("2026-11-05T12:00:00Z");
const HASH = "ab".repeat(32);
const REV = "11111111-1111-4111-8111-111111111111";
const ASG = "22222222-2222-4222-8222-222222222222";

const asg = (over: Partial<HostnameAssignment>): HostnameAssignment => ({
  id: "a1",
  host: "acme.example.test",
  tenant_id: "t1",
  kind: "subdomain",
  state: "active",
  created_by: "op",
  created_at: "2026-10-01T00:00:00Z",
  ...over,
});

function review(over: Partial<BrandingReviewResult["review"]> = {}, findings: BrandingReviewResult["findings"] = []): BrandingReviewResult {
  return {
    review: {
      tenant_id: "t1",
      draft: {
        id: REV,
        seq: 3,
        product_name: "Acme IT",
        accent_color: "#1d4ed8",
        support_text: "Call us first.",
        support_contact: { kind: "email", value: "help@acme.example.test" },
        logo_sha256: "",
        has_logo: false,
        normalized_hash: HASH,
        created_by: "owner",
        created_at: "2026-11-05T10:00:00Z",
      },
      published_revision_id: "",
      published_revision_hash: "",
      published_assignment_id: "",
      assignment: { id: ASG, host: "acme.example.test", state: "active" },
      review_generation: 7,
      ...over,
    },
    logo_png_base64: "",
    findings,
  };
}

const FIND = [
  { code: "mixed_script", message: "mixes scripts" },
  { code: "brand_denylist", message: "resembles a denylisted name" },
];

describe("hostname status wording", () => {
  it("names pending and active as they are", () => {
    expect(hostnameStatusLabel(asg({ state: "pending" }), NOW)).toBe("pending");
    expect(hostnameStatusLabel(asg({ state: "active" }), NOW)).toBe("active");
  });
  it("a released host is quarantined until its UTC date while the quarantine runs, released after", () => {
    const r = asg({ state: "released", released_at: "2026-11-01T00:00:00Z", quarantined_until: "2026-12-01T00:00:00Z" });
    expect(hostnameStatusLabel(r, NOW)).toBe("quarantined until 2026-12-01");
    expect(hostnameStatusLabel(r, new Date("2026-12-01T00:00:00Z"))).toBe("released");
    expect(hostnameStatusLabel(asg({ state: "released" }), NOW)).toBe("released");
  });
  it("only a released row can be quarantined", () => {
    expect(hostnameStatusLabel(asg({ state: "active", quarantined_until: "2027-01-01T00:00:00Z" }), NOW)).toBe("active");
  });
});

describe("which actions a row offers", () => {
  it("pending: activate or release; active: release", () => {
    const p = asg({ state: "pending" });
    expect(hostnameActions(p, [p])).toEqual(["activate", "release"]);
    const a = asg({ state: "active" });
    expect(hostnameActions(a, [a])).toEqual(["release"]);
  });
  it("a released host can be reactivated only when nothing else holds the host or the tenant", () => {
    const old = asg({ id: "old", state: "released", released_at: "2026-10-20T00:00:00Z" });
    expect(hostnameActions(old, [old])).toEqual(["reactivate"]);
    expect(hostnameActions(old, [old, asg({ id: "live", state: "pending" })])).toEqual([]);
    expect(hostnameActions(old, [old, asg({ id: "other", host: "other.example.test", state: "active" })])).toEqual([]);
    expect(hostnameActions(old, [old, asg({ id: "other", host: "x.example.test", tenant_id: "t2", state: "active" })])).toEqual(["reactivate"]);
  });
  it("only the newest released row of a host is offered for reactivation", () => {
    const older = asg({ id: "o", state: "released", released_at: "2026-09-01T00:00:00Z" });
    const newer = asg({ id: "n", state: "released", released_at: "2026-10-01T00:00:00Z" });
    expect(hostnameActions(older, [older, newer])).toEqual([]);
    expect(hostnameActions(newer, [older, newer])).toEqual(["reactivate"]);
  });
});

describe("findings sharing a code", () => {
  const dup = [...FIND, { code: "brand_denylist", message: "resembles another denylisted name" }];
  it("form one checklist entry carrying every message", () => {
    expect(groupFindings(dup)).toEqual([
      { code: "mixed_script", messages: ["mixes scripts"] },
      { code: "brand_denylist", messages: ["resembles a denylisted name", "resembles another denylisted name"] },
    ]);
  });
  it("are acknowledged once and sent once", () => {
    const r = review({}, dup);
    const ack = new Set(["mixed_script", "brand_denylist"]);
    expect(approveBlock(r, ack, "ok")).toBeNull();
    expect(buildApproveRequest(r, ack, "ok")?.acknowledge).toEqual(["mixed_script", "brand_denylist"]);
  });
});

describe("released_at ordering", () => {
  it("compares instants, not strings (trimmed fractional zeros)", () => {
    const a = asg({ id: "a", state: "released", released_at: "2026-10-01T00:00:00Z" });
    const b = asg({ id: "b", state: "released", released_at: "2026-10-01T00:00:00.5Z" });
    expect(hostnameActions(a, [a, b])).toEqual([]);
    expect(hostnameActions(b, [a, b])).toEqual(["reactivate"]);
  });
});

describe("look-alike warnings of an assign", () => {
  it("reads the warnings from a 409 body and from nothing else", () => {
    const w = [{ code: "idn_label", message: "punycode" }];
    expect(assignWarnings(new ConsoleApiError(409, "x", "conflict", "", { warnings: w }))).toEqual(w);
    expect(assignWarnings(new ConsoleApiError(409, "x", "conflict", "", {}))).toBeNull();
    expect(assignWarnings(new ConsoleApiError(400, "x", undefined, "", { warnings: w }))).toBeNull();
    expect(assignWarnings(new Error("x"))).toBeNull();
  });
});

describe("reason", () => {
  it("is required, trimmed, and at most 500 bytes", () => {
    expect(reasonOk("")).toBe(false);
    expect(reasonOk("   ")).toBe(false);
    expect(reasonOk("looks fine")).toBe(true);
    expect(reasonOk("a".repeat(500))).toBe(true);
    expect(reasonOk("a".repeat(501))).toBe(false);
    expect(reasonOk("é".repeat(251))).toBe(false); // 502 bytes
  });
});

describe("the approve gate", () => {
  it("allows a review with no findings without a reason", () => {
    expect(approveBlock(review(), new Set(), "")).toBeNull();
  });
  it("blocks until EVERY finding is acknowledged", () => {
    const r = review({}, FIND);
    expect(approveBlock(r, new Set(), "ok")).toBe("unacknowledged");
    expect(approveBlock(r, new Set(["mixed_script"]), "ok")).toBe("unacknowledged");
    expect(approveBlock(r, new Set(["mixed_script", "brand_denylist"]), "ok")).toBeNull();
  });
  it("blocks acknowledged findings without a reason, and ignores a stale acknowledgement of a code that is gone", () => {
    const r = review({}, FIND);
    const all = new Set(["mixed_script", "brand_denylist"]);
    expect(approveBlock(r, all, "")).toBe("no_reason");
    expect(approveBlock(r, all, "   ")).toBe("no_reason");
    expect(approveBlock(review({}, [FIND[0]]), new Set(["gone"]), "ok")).toBe("unacknowledged");
  });
  it("blocks without a draft or without a hostname, and when this revision is already published for this assignment", () => {
    expect(approveBlock(review({ draft: null }), new Set(), "")).toBe("no_draft");
    expect(approveBlock(review({ assignment: null }), new Set(), "")).toBe("no_hostname");
    expect(approveBlock(review({ published_revision_id: REV, published_assignment_id: ASG }), new Set(), "")).toBe("already_published");
    // published for a DIFFERENT assignment: it must be approved again (docs/66 2c.2)
    expect(approveBlock(review({ published_revision_id: REV, published_assignment_id: "33333333-3333-4333-8333-333333333333" }), new Set(), "")).toBeNull();
  });
});

describe("the approve request", () => {
  it("carries exactly the ids, hash and generation the review showed", () => {
    expect(buildApproveRequest(review(), new Set(), "")).toEqual({
      revision_id: REV,
      normalized_hash: HASH,
      assignment_id: ASG,
      review_generation: 7,
      acknowledge: [],
      override_reason: "",
    });
  });
  it("lists every finding code and the trimmed reason when there are findings", () => {
    const req = buildApproveRequest(review({}, FIND), new Set(["brand_denylist", "mixed_script", "stale_code"]), "  checked with the customer ");
    expect(req?.acknowledge).toEqual(["mixed_script", "brand_denylist"]);
    expect(req?.override_reason).toBe("checked with the customer");
  });
  it("is null whenever the gate blocks", () => {
    expect(buildApproveRequest(review({}, FIND), new Set(), "x")).toBeNull();
    expect(buildApproveRequest(review({ assignment: null }), new Set(), "")).toBeNull();
  });
});

describe("a refused approve or withdraw", () => {
  it("409 stale says the tenant changed something: reload", () => {
    const f = reviewFailure(new ConsoleApiError(409, "could not approve: review is stale", "conflict", "stale", { code: "stale" }));
    expect(f).toEqual({ kind: "stale", message: STALE_TEXT });
    expect(STALE_TEXT).toContain("changed something since you opened this review: reload");
  });
  it("409 findings carries the server's list", () => {
    const f = reviewFailure(new ConsoleApiError(409, "x", "conflict", "findings", { code: "findings", findings: [{ code: "mixed_script", message: "m" }, 5, { nocode: 1 }] }));
    expect(f.kind).toBe("findings");
    expect(f.kind === "findings" && f.findings).toEqual([{ code: "mixed_script", message: "m" }]);
  });
  it("anything else is the plain message", () => {
    expect(reviewFailure(new ConsoleApiError(500, "could not approve: boom", "server"))).toEqual({ kind: "other", message: "could not approve: boom" });
    expect(reviewFailure(new ConsoleApiError(409, "could not approve: hostname busy", "conflict", "busy")).kind).toBe("other");
  });
});

describe("the draft as the join page's brand", () => {
  it("maps every public field and a known contact kind", () => {
    expect(draftBrand(review().review.draft!)).toEqual({
      name: "Acme IT",
      accent: "#1d4ed8",
      logoRev: "",
      supportText: "Call us first.",
      contact: { kind: "email", value: "help@acme.example.test" },
    });
  });
  it("no contact kind is no contact; an unknown kind is no contact; a bad logo hash is no logo", () => {
    const d = review().review.draft!;
    expect(draftBrand({ ...d, support_contact: { kind: "", value: "" } }).contact).toBeNull();
    expect(draftBrand({ ...d, support_contact: { kind: "fax", value: "1" } }).contact).toBeNull();
    expect(draftBrand({ ...d, logo_sha256: "zz" }).logoRev).toBe("");
  });
  it("a logo address is a PNG data URI only for real base64", () => {
    expect(draftLogoSrc("iVBORw0KGgo=")).toBe("data:image/png;base64,iVBORw0KGgo=");
    expect(draftLogoSrc("")).toBeUndefined();
    expect(draftLogoSrc("a b\"onerror=")).toBeUndefined();
  });
});

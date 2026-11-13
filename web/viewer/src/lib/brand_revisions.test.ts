import { describe, expect, it } from "vitest";
import {
  buildRevisionInput,
  describeBrandingStatus,
  describeSubmitFailure,
  formatWhen,
  parseBrandingRevisions,
  parseBrandRevisionResult,
  prefillBrandForm,
  type BrandingRevisionsView,
  type BrandRevision,
} from "./brand_revisions";
import { checkBrandForm } from "./brand_text";

const rev = (over: Partial<BrandRevision> = {}): BrandRevision => ({
  id: "r1",
  seq: 1,
  productName: "Acme Support",
  accent: "#35654a",
  supportText: "Call us",
  contact: { kind: "phone", value: "15550100199" },
  logoSha256: "",
  hasLogo: false,
  normalizedHash: "h",
  createdAt: "2026-11-05T14:03:09Z",
  ...over,
});

const view = (over: Partial<BrandingRevisionsView> = {}): BrandingRevisionsView => ({
  draft: null,
  published: null,
  assignment: null,
  live: false,
  draftIsPublished: false,
  publishedAt: null,
  withdrawn: null,
  logoUploadSupported: true,
  ...over,
});

const wire = (r: BrandRevision) => ({
  id: r.id,
  seq: r.seq,
  product_name: r.productName,
  accent_color: r.accent,
  support_text: r.supportText,
  support_contact: r.contact,
  logo_sha256: r.logoSha256,
  has_logo: r.hasLogo,
  normalized_hash: r.normalizedHash,
  created_by: "u",
  created_at: r.createdAt,
});

describe("parseBrandingRevisions", () => {
  it("reads the server shape", () => {
    const v = parseBrandingRevisions({
      state: { draft: wire(rev()), published: null, assignment: { id: "a1", host: "acme.example.com", state: "active" }, live: false, draft_is_published: false },
      logo_upload_supported: true,
    });
    expect(v).not.toBeNull();
    expect(v!.draft!.productName).toBe("Acme Support");
    expect(v!.draft!.contact).toEqual({ kind: "phone", value: "15550100199" });
    expect(v!.assignment).toEqual({ id: "a1", host: "acme.example.com", state: "active" });
    expect(v!.logoUploadSupported).toBe(true);
  });
  it("treats an absent logo_upload_supported as not supported (the logo field stays hidden)", () => {
    expect(parseBrandingRevisions({ state: {} })!.logoUploadSupported).toBe(false);
    expect(parseBrandingRevisions({ state: {}, logo_upload_supported: false })!.logoUploadSupported).toBe(false);
  });
  it("is null for a malformed body, never an invented empty state", () => {
    expect(parseBrandingRevisions(null)).toBeNull();
    expect(parseBrandingRevisions({})).toBeNull();
    expect(parseBrandingRevisions({ state: { draft: { id: 5 } } })).toBeNull();
    expect(parseBrandingRevisions({ state: { assignment: { host: 1, state: "active" } } })).toBeNull();
  });
  it("an unknown contact kind reads as no contact", () => {
    const v = parseBrandingRevisions({ state: { draft: { ...wire(rev()), support_contact: { kind: "fax", value: "1" } } } });
    expect(v!.draft!.contact).toEqual({ kind: "", value: "" });
  });
});

describe("parseBrandRevisionResult", () => {
  it("reads created true and false", () => {
    expect(parseBrandRevisionResult({ revision: wire(rev()), created: true })!.created).toBe(true);
    expect(parseBrandRevisionResult({ revision: wire(rev()), created: false })!.created).toBe(false);
  });
  it("needs a boolean created and a revision", () => {
    expect(parseBrandRevisionResult({ revision: wire(rev()) })).toBeNull();
    expect(parseBrandRevisionResult({ created: true })).toBeNull();
  });
});

describe("formatWhen", () => {
  it("is fixed UTC text", () => {
    expect(formatWhen("2026-11-05T14:03:09Z")).toBe("2026-11-05 14:03 UTC");
    expect(formatWhen("2026-11-05T16:03:09+02:00")).toBe("2026-11-05 14:03 UTC");
  });
  it("does not print Invalid Date", () => {
    expect(formatWhen("")).toBe("an unknown time");
    expect(formatWhen("yesterday")).toBe("an unknown time");
  });
});

describe("describeBrandingStatus", () => {
  it("no assignment: tells the Owner to ask the platform operator", () => {
    expect(describeBrandingStatus(view()).hostname).toBe("Not assigned: ask your platform operator");
    expect(describeBrandingStatus(view()).hostnameState).toBe("");
  });
  it("names the assigned host and its state", () => {
    const a = (state: string) => describeBrandingStatus(view({ assignment: { id: "a", host: "acme.example.com", state } }));
    expect(a("active")).toMatchObject({ hostname: "acme.example.com", hostnameState: "active" });
    expect(a("pending").hostnameState).toContain("pending");
    expect(a("odd").hostnameState).toBe("odd");
  });
  it("nothing submitted", () => {
    expect(describeBrandingStatus(view()).approval).toBe("Nothing submitted yet");
  });
  it("a draft with nothing published and no withdrawal says only that nothing is published, with its time (no claim of never approved)", () => {
    const s = describeBrandingStatus(view({ draft: rev() }));
    expect(s.approval).toBe("Nothing published. Draft waiting for approval (submitted 2026-11-05 14:03 UTC)");
    expect(s.approval).not.toContain("withdrawn");
    expect(s.approval).toContain("2026-11-05 14:03 UTC");
    expect(s.live).toContain("neutral");
  });
  it("draft equal to the published revision is published", () => {
    const r = rev();
    const s = describeBrandingStatus(view({ draft: r, published: r, draftIsPublished: true, live: true, publishedAt: "2026-11-07T08:30:00Z", assignment: { id: "a", host: "h.example.com", state: "active" } }));
    expect(s.approval).toBe("Published 2026-11-07 08:30 UTC (submitted 2026-11-05 14:03 UTC)");
    expect(s.approval).not.toContain("waiting");
    expect(s.live).toMatch(/^Yes/);
  });
  it("a newer draft over a published revision shows both", () => {
    const s = describeBrandingStatus(view({ draft: rev({ createdAt: "2026-11-06T09:00:00Z" }), published: rev(), live: true, publishedAt: "2026-11-07T08:30:00Z", assignment: { id: "a", host: "h.example.com", state: "active" } }));
    expect(s.approval).toContain("2026-11-05 14:03 UTC");
    expect(s.approval).toContain("newer draft (submitted 2026-11-06 09:00 UTC) is waiting for approval");
  });
  it("a withdrawn publication says when and that guests see the neutral page", () => {
    const s = describeBrandingStatus(view({ draft: rev(), withdrawn: { at: "2026-11-08T10:15:00Z", revisionId: "r1" } }));
    expect(s.approval).toBe("Withdrawn 2026-11-08 10:15 UTC \u2014 guests see the neutral page. A draft (submitted 2026-11-05 14:03 UTC) is waiting for approval");
    expect(s.approval).not.toContain("Nothing published");
    expect(s.live).toContain("neutral");
  });
  it("a published revision without an approval time (older server) is not given an invented one", () => {
    const s = describeBrandingStatus(view({ draft: rev(), published: rev(), draftIsPublished: true }));
    expect(s.approval).toBe("Published: the revision submitted 2026-11-05 14:03 UTC");
  });
  it("published but not live says why", () => {
    const noHost = describeBrandingStatus(view({ draft: rev(), published: rev(), draftIsPublished: true }));
    expect(noHost.live).toMatch(/^No.*hostname is assigned/);
    const pending = describeBrandingStatus(view({ draft: rev(), published: rev(), draftIsPublished: true, assignment: { id: "a", host: "h.example.com", state: "pending" } }));
    expect(pending.live).toMatch(/^No.*hostname is active/);
  });
});

describe("parseBrandingRevisions: published_at and withdrawn", () => {
  const state = (extra: Record<string, unknown>) => ({ state: { draft: null, published: null, assignment: null, live: false, draft_is_published: false, ...extra }, logo_upload_supported: true });
  it("reads both optional fields", () => {
    expect(parseBrandingRevisions(state({ published_at: "2026-11-07T08:30:00Z" }))?.publishedAt).toBe("2026-11-07T08:30:00Z");
    const w = parseBrandingRevisions(state({ withdrawn: { at: "2026-11-08T10:15:00Z", revision_id: "r1" } }));
    expect(w?.withdrawn).toEqual({ at: "2026-11-08T10:15:00Z", revisionId: "r1" });
    expect(parseBrandingRevisions(state({ withdrawn: { at: "2026-11-08T10:15:00Z" } }))?.withdrawn).toEqual({ at: "2026-11-08T10:15:00Z", revisionId: "" });
  });
  it("an older server's draft-only payload, and a malformed withdrawal, never read as 'never approved'", () => {
    const d = { ...wire(rev()) };
    for (const extra of [{ draft: d }, { draft: d, withdrawn: { at: 5 } }, { draft: d, withdrawn: "x" }]) {
      const v = parseBrandingRevisions(state(extra));
      expect(v).not.toBeNull();
      const s = describeBrandingStatus(v!);
      expect(s.approval).toBe("Nothing published. Draft waiting for approval (submitted 2026-11-05 14:03 UTC)");
      expect(s.approval).not.toMatch(/never approved/i);
    }
  });
  it("absent or malformed means not said", () => {
    const v = parseBrandingRevisions(state({}));
    expect(v?.publishedAt).toBeNull();
    expect(v?.withdrawn).toBeNull();
    expect(parseBrandingRevisions(state({ published_at: 5, withdrawn: { at: 5 } }))).toMatchObject({ publishedAt: null, withdrawn: null });
  });
});

describe("prefillBrandForm", () => {
  const consoleB = { product_name: "Console Name", accent_color: "#112233", logo_data_uri: "data:image/png;base64,AAAA" };
  it("starts from the draft before the published revision", () => {
    const p = prefillBrandForm(view({ draft: rev({ productName: "Draft Name" }), published: rev({ productName: "Pub Name" }) }), consoleB);
    expect(p.source).toBe("draft");
    expect(p.values.productName).toBe("Draft Name");
    expect(p.note).not.toMatch(/console/i);
  });
  it("then the published revision", () => {
    const p = prefillBrandForm(view({ published: rev({ productName: "Pub Name", hasLogo: true, logoSha256: "ab" }) }), consoleB);
    expect(p.source).toBe("published");
    expect(p.values.productName).toBe("Pub Name");
    expect(p.logo).toEqual({ kind: "kept", sha256: "ab" });
  });
  it("then the console appearance, labelled as copied and not submitted", () => {
    const p = prefillBrandForm(view(), consoleB);
    expect(p.source).toBe("console");
    expect(p.values).toEqual({ productName: "Console Name", accent: "#112233", supportText: "", contactKind: "", contactValue: "" });
    expect(p.logo).toEqual({ kind: "console", dataUri: "data:image/png;base64,AAAA" });
    expect(p.note).toBe("Copied from your console appearance; not submitted yet.");
  });
  it("a console appearance without a logo or a name has none", () => {
    expect(prefillBrandForm(view(), { product_name: "", accent_color: "", logo_data_uri: "" }).logo).toEqual({ kind: "none" });
    expect(prefillBrandForm(view(), null).values.productName).toBe("");
  });
  it("a draft with a contact fills the contact fields", () => {
    const p = prefillBrandForm(view({ draft: rev({ contact: { kind: "email", value: "a@b.co" } }) }), null);
    expect(p.values.contactKind).toBe("email");
    expect(p.values.contactValue).toBe("a@b.co");
  });
});

describe("buildRevisionInput", () => {
  const values = { productName: "  Acme   Support ", accent: "#35654A", supportText: "Hi", contactKind: "phone" as const, contactValue: "+1 555 010 0199" };
  const check = checkBrandForm(values);
  it("sends canonical values for fields that passed", () => {
    const i = buildRevisionInput(values, check, { kind: "none" }, true)!;
    expect(i).toEqual({ product_name: "Acme Support", accent_color: "#35654a", support_text: "Hi", support_contact: { kind: "phone", value: "15550100199" } });
  });
  it("sends what was typed for a field the inline check refused (the server explains why)", () => {
    const bad = { ...values, productName: "Ab" };
    expect(buildRevisionInput(bad, checkBrandForm(bad), { kind: "none" }, true)!.product_name).toBe("Ab");
  });
  it("keep_logo for a kept logo, logo_data_uri for a new one, neither for none", () => {
    expect(buildRevisionInput(values, check, { kind: "kept", sha256: "x" }, true)).toMatchObject({ keep_logo: true });
    const withNew = buildRevisionInput(values, check, { kind: "new", dataUri: "data:image/png;base64,AA" }, true)!;
    expect(withNew.logo_data_uri).toBe("data:image/png;base64,AA");
    expect(withNew.keep_logo).toBeUndefined();
    const none = buildRevisionInput(values, check, { kind: "none" }, true)!;
    expect(none.keep_logo).toBeUndefined();
    expect(none.logo_data_uri).toBeUndefined();
  });
  it("never sends a logo when uploads are unsupported (the field is hidden)", () => {
    const i = buildRevisionInput(values, check, { kind: "new", dataUri: "data:image/png;base64,AA" }, false)!;
    expect(i.logo_data_uri).toBeUndefined();
    expect(i.keep_logo).toBeUndefined();
  });
  it("still keeps the draft's logo when uploads are unsupported (keep_logo needs no converter)", () => {
    const i = buildRevisionInput(values, check, { kind: "kept", sha256: "x" }, false)!;
    expect(i.keep_logo).toBe(true);
    expect(i.logo_data_uri).toBeUndefined();
  });
  it("waits for a console logo that is not downscaled yet", () => {
    expect(buildRevisionInput(values, check, { kind: "console", dataUri: "data:image/png;base64,AA" }, true)).toBeNull();
  });
});

describe("describeSubmitFailure", () => {
  it("the 20-per-hour budget, in plain words", () => {
    const p = describeSubmitFailure(429, "too many branding revisions; retry later", "");
    expect(p.message).toContain("20 per hour");
    expect(p.field).toBe("");
  });
  it("a busy logo converter is not called a budget", () => {
    const p = describeSubmitFailure(429, "logo conversion is busy; retry shortly", "");
    expect(p.field).toBe("logo");
    expect(p.message).toMatch(/busy/i);
    expect(p.message).not.toMatch(/Wait a minute/);
  });
  it("the logo budget is told apart from the revision budget", () => {
    const p = describeSubmitFailure(429, "too many logo uploads; retry later", "");
    expect(p.field).toBe("logo");
    expect(p.message).not.toContain("20 per hour");
  });
  it("a field refusal carries the server's own text and field", () => {
    expect(describeSubmitFailure(400, "must be 3 to 100 characters", "product_name")).toEqual({ field: "product_name", message: "must be 3 to 100 characters" });
  });
  it("403, 501 and 503 are explained", () => {
    expect(describeSubmitFailure(403, "x", "").message).toContain("Owner");
    expect(describeSubmitFailure(501, "x", "").field).toBe("logo");
    expect(describeSubmitFailure(503, "x", "").message).toContain("busy");
  });
  it("anything else shows the server's text, or the status when there is none", () => {
    expect(describeSubmitFailure(500, "boom", "").message).toBe("boom");
    expect(describeSubmitFailure(500, "", "").message).toContain("HTTP 500");
  });
});

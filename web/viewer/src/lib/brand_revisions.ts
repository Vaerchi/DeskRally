/**
 * The Owner's PUBLIC join-page branding, client side (docs/66 2.7, 2a.3, 2h, 2j): the shapes of
 * `GET|POST /tenant/branding/revisions`, the wording of the status row, what the form starts from, and how a refusal is
 * put into words. Pure, so vitest covers every rule; the React parts are `components/PublicJoinSection.tsx`.
 *
 * Two separate things live in the Appearance panel and must stay visibly separate: the CONSOLE appearance (the existing
 * `PUT /tenant/branding`, themes the team's own console at once) and the PUBLIC JOIN PAGE (an immutable revision that
 * guests see only after a platform operator approves it, on the tenant's own hostname).
 */

import type { BrandContactKind } from "./host_branding";
import type { BrandFormCheck, BrandFormValues } from "./brand_text";
import type { TenantBranding } from "./console_api";

/** One immutable revision as the control plane returns it (`BrandingRevision`; the logo bytes are never sent back to an Owner). */
export interface BrandRevision {
  id: string;
  seq: number;
  productName: string;
  accent: string;
  supportText: string;
  contact: { kind: BrandContactKind | ""; value: string };
  logoSha256: string;
  hasLogo: boolean;
  normalizedHash: string;
  createdAt: string;
}

export interface BrandAssignment {
  id: string;
  host: string;
  state: string;
}

/** `GET /tenant/branding/revisions`. */
export interface BrandingRevisionsView {
  draft: BrandRevision | null;
  published: BrandRevision | null;
  assignment: BrandAssignment | null;
  /** Guests see the published revision on the active hostname right now. */
  live: boolean;
  /** The draft and the published revision are the same row. */
  draftIsPublished: boolean;
  /** When an operator approved the published revision (RFC 3339); null when nothing is published or the server did not say. */
  publishedAt: string | null;
  /** The last publication was withdrawn by an operator and nothing has been approved since; null when none is recorded, which does NOT mean "never approved" (older servers omit it and the 0075 backfill leaves unknown histories out). */
  withdrawn: { at: string; revisionId: string } | null;
  /** False when the server cannot convert logos on this platform: the console must hide the logo field. */
  logoUploadSupported: boolean;
}

/** The body of `POST /tenant/branding/revisions`. */
export interface BrandRevisionInput {
  product_name: string;
  accent_color: string;
  support_text: string;
  support_contact: { kind: BrandContactKind | ""; value: string };
  /** A raster data URI of the (already downscaled) PNG; mutually exclusive with keep_logo. */
  logo_data_uri?: string;
  keep_logo?: boolean;
}

export interface BrandRevisionResult {
  revision: BrandRevision;
  /** False: the input equalled the current draft (HTTP 200), nothing was created. */
  created: boolean;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function parseRevision(raw: unknown): BrandRevision | null {
  if (!isObj(raw)) return null;
  const c = raw.support_contact;
  if (
    typeof raw.id !== "string" || typeof raw.product_name !== "string" || typeof raw.accent_color !== "string" ||
    typeof raw.support_text !== "string" || !isObj(c) || typeof c.kind !== "string" || typeof c.value !== "string"
  ) {
    return null;
  }
  const kind = c.kind === "phone" || c.kind === "email" || c.kind === "url" ? c.kind : "";
  return {
    id: raw.id,
    seq: typeof raw.seq === "number" ? raw.seq : 0,
    productName: raw.product_name,
    accent: raw.accent_color,
    supportText: raw.support_text,
    contact: { kind, value: kind === "" ? "" : c.value },
    logoSha256: typeof raw.logo_sha256 === "string" ? raw.logo_sha256 : "",
    hasLogo: raw.has_logo === true,
    normalizedHash: typeof raw.normalized_hash === "string" ? raw.normalized_hash : "",
    createdAt: typeof raw.created_at === "string" ? raw.created_at : "",
  };
}

function parseAssignment(raw: unknown): BrandAssignment | null {
  if (!isObj(raw) || typeof raw.host !== "string" || typeof raw.state !== "string") return null;
  return { id: typeof raw.id === "string" ? raw.id : "", host: raw.host, state: raw.state };
}

/** Null when the body is not the documented shape (the caller reports "malformed", never an invented empty state). */
export function parseBrandingRevisions(body: unknown): BrandingRevisionsView | null {
  if (!isObj(body) || !isObj(body.state)) return null;
  const s = body.state;
  const draft = s.draft == null ? null : parseRevision(s.draft);
  const published = s.published == null ? null : parseRevision(s.published);
  const assignment = s.assignment == null ? null : parseAssignment(s.assignment);
  if ((s.draft != null && draft === null) || (s.published != null && published === null) || (s.assignment != null && assignment === null)) return null;
  return {
    draft,
    published,
    assignment,
    live: s.live === true,
    draftIsPublished: s.draft_is_published === true,
    // Both are optional on the wire (older servers omit them): absent means "not said", never an invented time.
    publishedAt: typeof s.published_at === "string" ? s.published_at : null,
    withdrawn: isObj(s.withdrawn) && typeof s.withdrawn.at === "string"
      ? { at: s.withdrawn.at, revisionId: typeof s.withdrawn.revision_id === "string" ? s.withdrawn.revision_id : "" }
      : null,
    // Absent means "not supported": a field the console would show must be one the server said it can serve.
    logoUploadSupported: body.logo_upload_supported === true,
  };
}

export function parseBrandRevisionResult(body: unknown): BrandRevisionResult | null {
  if (!isObj(body) || typeof body.created !== "boolean") return null;
  const revision = parseRevision(body.revision);
  return revision === null ? null : { revision, created: body.created };
}

// ---- the status row --------------------------------------------------------------------------------------

/** "2026-11-05 14:03 UTC" from an RFC 3339 time; fixed, so the wording is testable. */
export function formatWhen(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "an unknown time";
  return `${new Date(t).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export interface BrandStatusRows {
  /** The assigned public hostname, or the "ask your platform operator" sentence. */
  hostname: string;
  /** Its state in words ("" when there is none). */
  hostnameState: string;
  /** Draft waiting / published / nothing submitted, with when. */
  approval: string;
  /** Whether the live join page shows the published revision. */
  live: string;
}

/**
 * The read-only status wording. The Owner API tells an Owner what is drafted, what is published and when it was approved,
 * whether it is live, and whether the last publication was withdrawn (and when). It never says which operator or why.
 */
export function describeBrandingStatus(v: BrandingRevisionsView): BrandStatusRows {
  const a = v.assignment;
  const hostname = a === null ? "Not assigned: ask your platform operator" : a.host;
  const hostnameState = a === null ? "" : a.state === "active" ? "active" : a.state === "pending" ? "pending activation by your platform operator" : a.state;
  let approval: string;
  const drafted = v.draft === null ? "" : ` (submitted ${formatWhen(v.draft.createdAt)})`;
  if (v.published !== null) {
    const was = v.publishedAt === null ? `the revision submitted ${formatWhen(v.published.createdAt)}` : `${formatWhen(v.publishedAt)} (submitted ${formatWhen(v.published.createdAt)})`;
    approval = v.publishedAt === null ? `Published: ${was}` : `Published ${was}`;
    if (v.draft !== null && !v.draftIsPublished) approval += `. A newer draft${drafted} is waiting for approval`;
  } else if (v.withdrawn !== null) {
    approval = `Withdrawn ${formatWhen(v.withdrawn.at)} — guests see the neutral page`;
    if (v.draft !== null) approval += `. A draft${drafted} is waiting for approval`;
  } else if (v.draft !== null) {
    approval = `Nothing published. Draft waiting for approval${drafted}`;
  } else {
    approval = "Nothing submitted yet";
  }
  let live: string;
  if (v.published === null) live = "No: guests see the neutral DeskRally page";
  else if (v.live) live = "Yes: the live join page shows the published revision";
  else if (a === null) live = "No: guests see the neutral page until a hostname is assigned and activated";
  else live = "No: guests see the neutral page until the hostname is active";
  return { hostname, hostnameState, approval, live };
}

// ---- what the form starts from ---------------------------------------------------------------------------

export type PrefillSource = "draft" | "published" | "console";

export type LogoState =
  | { kind: "none" }
  /** The current draft's (or published revision's) logo, which the server keeps (keep_logo). The console never gets its bytes. */
  | { kind: "kept"; sha256: string }
  /** A downscaled PNG data URI to upload. */
  | { kind: "new"; dataUri: string }
  /** The console appearance's logo, still to be downscaled before it can be submitted. */
  | { kind: "console"; dataUri: string };

export interface BrandPrefill {
  values: BrandFormValues;
  logo: LogoState;
  source: PrefillSource;
  /** The sentence shown under the form's title; the console case must say it was copied and not submitted. */
  note: string;
}

const valuesOf = (r: BrandRevision): BrandFormValues => ({
  productName: r.productName,
  accent: r.accent,
  supportText: r.supportText,
  contactKind: r.contact.kind,
  contactValue: r.contact.value,
});

/** The current draft, else the published revision, else the console appearance values (labelled as not submitted). */
export function prefillBrandForm(view: BrandingRevisionsView, consoleBranding: TenantBranding | null): BrandPrefill {
  const rev = view.draft ?? view.published;
  if (rev !== null) {
    const fromDraft = view.draft !== null;
    return {
      values: valuesOf(rev),
      logo: rev.hasLogo ? { kind: "kept", sha256: rev.logoSha256 } : { kind: "none" },
      source: fromDraft ? "draft" : "published",
      note: fromDraft ? "Showing your current draft." : "Showing the published revision.",
    };
  }
  const c = consoleBranding;
  return {
    values: { productName: c?.product_name ?? "", accent: c?.accent_color ?? "", supportText: "", contactKind: "", contactValue: "" },
    logo: c !== null && c.logo_data_uri !== "" ? { kind: "console", dataUri: c.logo_data_uri } : { kind: "none" },
    source: "console",
    note: "Copied from your console appearance; not submitted yet.",
  };
}

/**
 * The request body for the form: each field's canonical value when it passed the inline check, else what was typed (the
 * server is the authority and says why it refuses). Null when a console logo still needs its downscale.
 */
export function buildRevisionInput(values: BrandFormValues, check: BrandFormCheck, logo: LogoState, logoUploadSupported: boolean): BrandRevisionInput | null {
  const n = check.normalized;
  const input: BrandRevisionInput = {
    product_name: n.productName ?? values.productName,
    accent_color: n.accent ?? values.accent,
    support_text: n.supportText ?? values.supportText,
    support_contact: n.contact ?? { kind: values.contactKind, value: values.contactValue },
  };
  // keep_logo needs no converter (only a new upload does): without it a revision has NO logo, so an unsupported server must
  // still be told to keep the draft's. The hidden field offers no new upload and no console copy.
  if (logo.kind === "kept") input.keep_logo = true;
  if (!logoUploadSupported) return input;
  if (logo.kind === "console") return null;
  if (logo.kind === "new") input.logo_data_uri = logo.dataUri;
  return input;
}

// ---- refusals in plain words -----------------------------------------------------------------------------

export interface SubmitProblem {
  /** The field the server named, when it did (`{field, error}`), else "". */
  field: string;
  message: string;
}

/**
 * A failed submit, in words an Owner can act on. A field refusal carries the SERVER's text (it is the authority); the two
 * 429s (the 20-per-hour revision budget, the per-minute logo budget) and the other statuses are explained.
 */
export function describeSubmitFailure(status: number, serverText: string, field: string): SubmitProblem {
  if (status === 429) {
    if (/busy/i.test(serverText)) return { field: "logo", message: "The logo converter is busy. Try again in a few seconds." };
    if (/logo/i.test(serverText)) return { field: "logo", message: "Too many logo uploads just now. Wait a minute and submit again." };
    return {
      field: "",
      message: "You have submitted the most revisions allowed (20 per hour). Nothing was lost: wait up to an hour and submit again.",
    };
  }
  if (status === 403) return { field: "", message: "Only an Owner can submit the public join page." };
  if (status === 501) return { field: "logo", message: "This server cannot process logo uploads. Submit without a new logo." };
  if (status === 503) return { field: "", message: "The server is busy. Try again in a few seconds." };
  if (status === 400 && field !== "") return { field, message: serverText };
  return { field, message: serverText || `The server refused the request (HTTP ${status}).` };
}

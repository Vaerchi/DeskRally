/**
 * The pure rules of the platform operator's hostname and branding-review screens (docs/66 2k): what a hostname's
 * state is called, which actions a row offers, what the review shows a guest, when Approve is allowed and what it
 * sends, and how the server's refusals read. No React, no network: vitest covers every function here.
 *
 * The server owns every decision (control-plane/http_brandrev.go, http_hostname.go); these helpers only keep the
 * screen from offering what the server will refuse and from sending what it did not show.
 */

import { ConsoleApiError } from "./console_api";
import type { BrandingApproveRequest, BrandingReviewResult, BrandingRevisionView, HostnameAssignment, PlatformFinding } from "./console_api";
import { validLogoRev, type HostBrand } from "./host_branding";

/** The one reason limit of the platform routes (Go: at most 500 bytes after trimming). */
export const REASON_MAX_BYTES = 500;

export function reasonOk(reason: string): boolean {
  const r = reason.trim();
  return r.length > 0 && new TextEncoder().encode(r).length <= REASON_MAX_BYTES;
}

// ---- hostnames -----------------------------------------------------------------------------------------

const utcDate = (iso: string) => new Date(iso).toISOString().slice(0, 10);

/** True while a released host is still held back from other tenants. */
export function isQuarantined(a: HostnameAssignment, now: Date): boolean {
  if (a.state !== "released" || !a.quarantined_until) return false;
  const t = Date.parse(a.quarantined_until);
  return Number.isFinite(t) && t > now.getTime();
}

/** The state in the operator's words: pending, active, released, or "quarantined until <UTC date>". */
export function hostnameStatusLabel(a: HostnameAssignment, now: Date): string {
  if (isQuarantined(a, now)) return `quarantined until ${utcDate(a.quarantined_until as string)}`;
  return a.state;
}

export type HostnameAction = "activate" | "release" | "reactivate";

/**
 * The actions a row offers. Pending: activate or release. Active: release. Released: reactivate, and only on the
 * NEWEST released row of its host while nothing else holds that host or that tenant (the server would answer 409).
 */
export function hostnameActions(row: HostnameAssignment, all: readonly HostnameAssignment[]): HostnameAction[] {
  if (row.state === "pending") return ["activate", "release"];
  if (row.state === "active") return ["release"];
  const held = all.some((r) => r.id !== row.id && r.state !== "released" && (r.host === row.host || r.tenant_id === row.tenant_id));
  const newer = all.some((r) => r.id !== row.id && r.host === row.host && r.state === "released" && Date.parse(r.released_at ?? "") > Date.parse(row.released_at ?? ""));
  return held || newer ? [] : ["reactivate"];
}

/** The plain-words consequence shown before a hostname action is confirmed. */
export function hostnameActionEffect(action: HostnameAction | "assign", host: string, tenantName: string): string {
  switch (action) {
    case "assign":
      return `Creates a PENDING assignment of ${host} to ${tenantName}. Guests are not affected until it is activated.`;
    case "activate":
      return `Makes ${host} live for ${tenantName}: join codes redeemed there become scoped to this tenant, and its approved branding is shown to guests on that address.`;
    case "release":
      return `Ends ${tenantName}'s use of ${host}. Guests there get the neutral DeskRally page and join codes stop working on that address. The host is held back (quarantined) for at least 30 days.`;
    case "reactivate":
      return `Creates a NEW assignment of ${host} to ${tenantName}. Any earlier branding approval no longer applies, so the branding must be approved again before guests see it.`;
  }
}

/** The look-alike warnings of a 409 on assign (`body.warnings`), or null when this is not that answer. */
export function assignWarnings(e: unknown): PlatformFinding[] | null {
  if (!(e instanceof ConsoleApiError) || e.status !== 409) return null;
  const list = findingList(e.body?.warnings);
  return list.length > 0 ? list : null;
}

// ---- branding review -----------------------------------------------------------------------------------

function findingList(v: unknown): PlatformFinding[] {
  if (!Array.isArray(v)) return [];
  const out: PlatformFinding[] = [];
  for (const f of v) {
    const o = f as { code?: unknown; message?: unknown } | null;
    if (o && typeof o.code === "string" && o.code !== "") out.push({ code: o.code, message: typeof o.message === "string" ? o.message : "" });
  }
  return out;
}

/** The draft as the join page's brand. The page itself re-validates every field; a draft the page refuses reads as neutral. */
export function draftBrand(d: BrandingRevisionView): HostBrand {
  const k = d.support_contact?.kind;
  return {
    name: d.product_name,
    accent: d.accent_color,
    logoRev: validLogoRev(d.logo_sha256) ? d.logo_sha256 : "",
    supportText: d.support_text,
    contact: k === "phone" || k === "email" || k === "url" ? { kind: k, value: d.support_contact.value } : null,
  };
}

/** The draft's logo as the page's own `data:` logo address, or undefined for none / not base64. */
export function draftLogoSrc(logoPngBase64: string): string | undefined {
  return /^[A-Za-z0-9+/]+={0,2}$/.test(logoPngBase64) ? `data:image/png;base64,${logoPngBase64}` : undefined;
}

/** The checklist: one entry per code (the server acknowledges by code and may repeat one), with every message under it. */
export function groupFindings(findings: readonly { code: string; message: string }[]): { code: string; messages: string[] }[] {
  const out: { code: string; messages: string[] }[] = [];
  for (const f of findings) {
    const g = out.find((x) => x.code === f.code);
    if (g) g.messages.push(f.message);
    else out.push({ code: f.code, messages: [f.message] });
  }
  return out;
}

export type ApproveBlock = "no_draft" | "no_hostname" | "already_published" | "unacknowledged" | "no_reason";

/** Why Approve is not allowed yet (null = allowed). Every finding needs its own acknowledgement and any finding needs a reason. */
export function approveBlock(r: BrandingReviewResult, acked: ReadonlySet<string>, reason: string): ApproveBlock | null {
  const rv = r.review;
  if (!rv.draft) return "no_draft";
  if (!rv.assignment) return "no_hostname";
  if (rv.published_revision_id === rv.draft.id && rv.published_assignment_id === rv.assignment.id) return "already_published";
  if (r.findings.some((f) => !acked.has(f.code))) return "unacknowledged";
  if (r.findings.length > 0 && !reasonOk(reason)) return "no_reason";
  return null;
}

export const APPROVE_BLOCK_TEXT: Record<ApproveBlock, string> = {
  no_draft: "The tenant has no draft to approve.",
  no_hostname: "The tenant has no hostname assignment: assign one first (Hostnames).",
  already_published: "This revision is already published for the current hostname.",
  unacknowledged: "Acknowledge every finding to approve.",
  no_reason: "Give the override reason (at most 500 bytes) to approve.",
};

/** The approval body: exactly the ids, hash and generation the review showed, with the findings acknowledged. Null when blocked. */
export function buildApproveRequest(r: BrandingReviewResult, acked: ReadonlySet<string>, reason: string): BrandingApproveRequest | null {
  if (approveBlock(r, acked, reason) !== null) return null;
  const { draft, assignment, review_generation } = r.review;
  const codes = groupFindings(r.findings).map((g) => g.code);
  return {
    revision_id: draft!.id,
    normalized_hash: draft!.normalized_hash,
    assignment_id: assignment!.id,
    review_generation,
    acknowledge: codes,
    override_reason: codes.length > 0 ? reason.trim() : "",
  };
}

export type ReviewFailure =
  | { kind: "stale"; message: string }
  | { kind: "findings"; message: string; findings: PlatformFinding[] }
  | { kind: "other"; message: string };

export const STALE_TEXT = "The tenant changed something since you opened this review: reload.";

/** How a refused approve or withdraw reads. 409 `stale` and 409 `findings` are the two the server uses for a moved target. */
export function reviewFailure(e: unknown): ReviewFailure {
  if (e instanceof ConsoleApiError && e.status === 409) {
    if (e.code === "stale") return { kind: "stale", message: STALE_TEXT };
    if (e.code === "not_published") return { kind: "stale", message: "Nothing is published for this tenant any more: reload." };
    if (e.code === "findings") {
      return { kind: "findings", message: "The review has findings that were not all acknowledged. They are listed below.", findings: findingList(e.body?.findings) };
    }
  }
  return { kind: "other", message: e instanceof Error ? e.message : String(e) };
}

/**
 * What the console's live preview of the join page is given (docs/66 2.7, 2j): the DRAFT form values as a `HostBrand`, the
 * logo address, and the sentence about the deployment's default origin. Pure; the component is `components/JoinPreview.tsx`.
 */

import { NEUTRAL_BRAND, type HostBrand } from "./host_branding";
import { defaultDocsLink } from "./default_docs";
import type { BrandFormCheck } from "./brand_text";
import type { LogoState } from "./brand_revisions";

/**
 * The draft as the join page would receive it. A field that would be refused is left out (blank) so the preview shows
 * the rest; a draft whose NAME is refused has no brand at all, which the page renders as the neutral page.
 */
export function draftToHostBrand(check: BrandFormCheck): HostBrand {
  const n = check.normalized;
  if (n.productName === undefined || n.productName === "") return NEUTRAL_BRAND;
  const contact = n.contact !== undefined && n.contact.kind !== "" ? { kind: n.contact.kind, value: n.contact.value } : null;
  return { name: n.productName, accent: n.accent ?? "", logoRev: "", supportText: n.supportText ?? "", contact };
}

/**
 * The preview's logo address: only a logo the browser holds can be shown. The server never returns a stored logo to the
 * console (the public route serves the PUBLISHED one to the tenant's own hostname only), so a kept logo has no preview.
 */
export function previewLogoSrc(logo: LogoState): string | undefined {
  return logo.kind === "new" ? logo.dataUri : undefined;
}

/** True when the deployment's default origin is usable, so a tenant brand can show on the live join page at all. */
export function previewOriginUsable(origin: string | undefined | null): boolean {
  return defaultDocsLink(origin) !== null;
}

/** The sentence shown when it is not: the preview (and the live join page) are neutral until the build sets it. */
export const PREVIEW_ORIGIN_NOTICE =
  "The live join page will be neutral until the deployment sets VITE_DEFAULT_ORIGIN (the default host's https origin). The preview below shows the neutral page for the same reason.";

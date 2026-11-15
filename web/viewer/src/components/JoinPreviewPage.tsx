/**
 * The ONE way the console previews the guest join page (docs/66 2j, 2k, 2l): the Owner's editor (`JoinPreview`) and the
 * operator's review (`PlatformBrandingReview`) both render `PreviewJoinPage` inside a `JoinBrandFrame` of the widths below, so the
 * two cannot show different layouts and neither differs from what `JoinPage` gives a guest: the same top-bar links, the same
 * welcome panel on a wide screen, the same neutral-page name and the same default origin.
 *
 * The three top-bar links are INERT here (plain text, not anchors): a preview must not navigate the console.
 */

import type { ReactNode } from "react";
import { JoinBrand } from "./JoinBrand";
import { RallyWelcome } from "./RallyIdentity";
import type { HostBrand } from "../lib/host_branding";

export type PreviewWidth = "phone" | "desktop";

/** The viewports the previews show, in CSS pixels. The only place these numbers are written. */
export const PREVIEW_WIDTHS = { phone: 390, desktop: 1100 } as const;

/** The accessible name of a preview frame (what an automated test addresses it by). */
export const previewFrameTitle = (width: PreviewWidth) => `Join page as a guest sees it, ${width} width`;

export interface PreviewJoinPageProps {
  brand: HostBrand;
  logoSrc?: string;
  /** `import.meta.env.VITE_DEFAULT_ORIGIN`, passed exactly as `JoinPage` passes it. */
  defaultOrigin?: string;
  /** `import.meta.env.VITE_PRODUCT_NAME`, the neutral page's name, as `JoinPage` passes it. */
  fallbackName?: string;
  width: PreviewWidth;
  children?: ReactNode;
}

export function PreviewJoinPage({ brand, logoSrc, defaultOrigin, fallbackName, width, children }: PreviewJoinPageProps) {
  return (
    <JoinBrand
      brand={brand}
      fallbackName={fallbackName}
      defaultOrigin={defaultOrigin}
      logoSrc={logoSrc}
      nav={
        <>
          <span className="join__downloads" data-testid="preview-nav-downloads">Downloads</span>
          <span className="join__downloads" data-testid="preview-nav-docs">Documentation</span>
          <span className="join__signin" data-testid="preview-nav-signin">Technician sign in</span>
        </>
      }
      welcome={width === "desktop" ? <RallyWelcome /> : undefined}
    >
      {children}
    </JoinBrand>
  );
}

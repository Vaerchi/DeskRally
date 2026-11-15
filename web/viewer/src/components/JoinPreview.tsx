/**
 * The console's preview of the guest join page (docs/66 2.7, 2j, 2l): the REAL `JoinBrand` component, fed the draft brand, at a
 * phone or a desktop width, optionally as the neutral default. Never a copy: what an Owner (and, in the Platform area, an
 * operator) reviews is the code path a guest gets. It renders through `PreviewJoinPage` inside a `JoinBrandFrame`, the same
 * pair the operator's review uses, so the page's viewport media queries fire at the stated width.
 * `JoinPreview.test.tsx` fails if this stops using them.
 *
 * JoinBrand shows a tenant brand ONLY with a valid default origin, so the caller passes the same value the join page does
 * (`import.meta.env.VITE_DEFAULT_ORIGIN`); when it is unset the frame renders the neutral page, exactly as production would.
 */

import { JoinBrandFrame } from "./JoinBrandFrame";
import { PREVIEW_WIDTHS, PreviewJoinPage, previewFrameTitle, type PreviewWidth } from "./JoinPreviewPage";
import { NEUTRAL_BRAND, type HostBrand } from "../lib/host_branding";
import "./JoinPreview.css";

export type { PreviewWidth };

export interface JoinPreviewProps {
  /** The brand to show (the draft). */
  brand: HostBrand;
  /** A logo the browser holds (a `data:` or `blob:` URL); see `previewLogoSrc`. */
  logoSrc?: string;
  /** The default host's origin, `import.meta.env.VITE_DEFAULT_ORIGIN`; absent or invalid renders the neutral page. */
  defaultOrigin?: string;
  width: PreviewWidth;
  /** Show the unbranded page instead (the "Show as neutral default" toggle). */
  neutral?: boolean;
  /** The deployment's own product name for the neutral page (`import.meta.env.VITE_PRODUCT_NAME`). */
  fallbackName?: string;
  testId?: string;
}

export function JoinPreview({ brand, logoSrc, defaultOrigin, width, neutral = false, fallbackName, testId = "join-preview" }: JoinPreviewProps) {
  return (
    <div className="join-preview" data-testid={testId} data-width={width} data-neutral={neutral ? "true" : "false"}>
      <JoinBrandFrame width={PREVIEW_WIDTHS[width]} title={previewFrameTitle(width)} testId={`${testId}-frame`}>
        <PreviewJoinPage
          brand={neutral ? NEUTRAL_BRAND : brand}
          fallbackName={fallbackName}
          logoSrc={neutral ? undefined : logoSrc}
          defaultOrigin={defaultOrigin}
          width={width}
        >
          <div className="join__download">
            <span className="join__downloadbtn join-preview__sample" data-testid={`${testId}-sample-button`}>
              Sample button
            </span>
          </div>
        </PreviewJoinPage>
      </JoinBrandFrame>
    </div>
  );
}

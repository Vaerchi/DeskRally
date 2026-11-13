/**
 * Platform operator: review and approve a tenant's public join-page branding (docs/66 2a.7, 2c.2, 2k).
 *
 * Binding rule (2a.7): the operator approves what a GUEST would see, so the draft is rendered in the real
 * `JoinBrand` (the component `JoinPage` uses, never a copy) at phone and at desktop width, beside the hostname it
 * would be served on and the contact destination shown literally. The automated findings each need their own
 * acknowledgement and, if there are any, one override reason. Approve sends the revision id, hash, assignment id and
 * review generation the review returned, so it can only publish what was on screen; a 409 `stale` means the tenant
 * changed something since and the review must be reloaded.
 *
 * Changes go through the Platform panel's single-flight operation (`start`): a recent second factor is checked
 * first, exactly like suspend and resume. Reads (the review itself) are plain requests.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { formatIsoUtc } from "../backstage/panels";
import type { BrandingReviewResult, ConsoleApi } from "../lib/console_api";
import { defaultDocsLink } from "../lib/default_docs";
import {
  APPROVE_BLOCK_TEXT,
  approveBlock,
  buildApproveRequest,
  draftBrand,
  draftLogoSrc,
  groupFindings,
  reasonOk,
  reviewFailure,
  type ReviewFailure,
} from "../lib/platform_branding";
import { JoinBrandFrame } from "./JoinBrandFrame";
import { PREVIEW_WIDTHS, PreviewJoinPage, previewFrameTitle } from "./JoinPreviewPage";

export interface PlatformBrandingReviewProps {
  api: ConsoleApi;
  tenant: { id: string; slug: string; name: string };
  /** A change is in flight in the Platform panel: nothing here may start another. */
  frozen: boolean;
  /** Start a change through the panel's step-up and single-flight machinery; false when it refused to start. */
  start: (run: (live: () => boolean) => Promise<void>, fail: (e: unknown) => void) => boolean;
  onClose: () => void;
}

export function PlatformBrandingReview({ api, tenant, frozen, start, onClose }: PlatformBrandingReviewProps) {
  const [result, setResult] = useState<BrandingReviewResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [acked, setAcked] = useState<ReadonlySet<string>>(new Set());
  const [reason, setReason] = useState("");
  const [failure, setFailure] = useState<ReviewFailure | null>(null);
  const [stale, setStale] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [withdrawing, setWithdrawing] = useState(false);
  const [withdrawReason, setWithdrawReason] = useState("");

  const mounted = useRef(true);
  const loadSeq = useRef(0);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    const seq = ++loadSeq.current;
    setLoading(true);
    setLoadError(null);
    try {
      const r = await api.getBrandingReview(tenant.id);
      if (!mounted.current || seq !== loadSeq.current) return;
      setResult(r);
      setAcked(new Set());
      setReason("");
      setFailure(null);
      setStale(false);
    } catch (e) {
      if (!mounted.current || seq !== loadSeq.current) return;
      setLoadError(e instanceof Error ? e.message : String(e));
    } finally {
      if (mounted.current && seq === loadSeq.current) setLoading(false);
    }
  }, [api, tenant.id]);

  useEffect(() => {
    void load();
  }, [load]);

  const block = result ? approveBlock(result, acked, reason) : null;
  const canApprove = result !== null && block === null && !stale && !frozen;

  const approve = () => {
    if (!result || stale || frozen) return;
    const req = buildApproveRequest(result, acked, reason); // enforced here, not only by the disabled button
    if (!req) return;
    setFailure(null);
    setNotice(null);
    start(
      async (live) => {
        await api.approveBranding(tenant.id, req);
        if (!live()) return;
        await load();
        setNotice("Approved. Guests on this hostname now see this branding.");
      },
      (e) => {
        if (!mounted.current) return;
        const f = reviewFailure(e);
        setFailure(f);
        if (f.kind === "stale") setStale(true);
        if (f.kind === "findings") {
          setAcked(new Set());
          if (f.findings.length > 0) setResult((cur) => (cur ? { ...cur, findings: f.findings } : cur));
        }
      },
    );
  };

  const withdraw = () => {
    if (!reasonOk(withdrawReason) || frozen) return;
    const why = withdrawReason.trim();
    setFailure(null);
    setNotice(null);
    start(
      async (live) => {
        await api.withdrawBranding(tenant.id, why);
        if (!live()) return;
        setWithdrawing(false);
        setWithdrawReason("");
        await load();
        setNotice("Withdrawn. Guests on this hostname see the neutral DeskRally page.");
      },
      (e) => {
        if (!mounted.current) return;
        const f = reviewFailure(e);
        setFailure(f);
        if (f.kind === "stale") setStale(true);
      },
    );
  };

  const rv = result?.review;
  const draft = rv?.draft ?? null;
  const published = rv !== undefined && rv.published_revision_id !== "";
  const origin = import.meta.env.VITE_DEFAULT_ORIGIN;
  const brand = draft ? draftBrand(draft) : null;
  const logoSrc = result ? draftLogoSrc(result.logo_png_base64) : undefined;

  return (
    <section className="panel__form platform-review" aria-label={`Branding review: ${tenant.name}`} data-testid="review-root">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">
          Public join page: {tenant.name} ({tenant.slug})
        </span>
        <button className="panel__action" onClick={() => void load()} disabled={loading || frozen} data-testid="review-reload">
          {loading ? "Loading…" : "Reload review"}
        </button>
        <button className="panel__action" onClick={onClose} disabled={frozen} data-testid="review-close">
          Close
        </button>
        {loadError && (
          <span className="panel__toolbar-error" role="alert" data-testid="review-load-error">
            {loadError}
          </span>
        )}
      </div>

      {result && !draft && (
        <p className="panel__empty" data-testid="review-no-draft">
          This tenant has not saved a public join-page revision yet. There is nothing to review.
        </p>
      )}

      {result && draft && rv && brand && (
        <>
          <dl className="platform-review__facts">
            <dt>Hostname</dt>
            <dd data-testid="review-hostname">
              {rv.assignment ? (
                <>
                  <code dir="ltr">{rv.assignment.host}</code> ({rv.assignment.state})
                </>
              ) : (
                "none assigned"
              )}
            </dd>
            <dt>Contact</dt>
            <dd data-testid="review-contact">
              {draft.support_contact.kind ? (
                <>
                  {draft.support_contact.kind}: <code dir="ltr">{draft.support_contact.value}</code>
                </>
              ) : (
                "none"
              )}
            </dd>
            <dt>Revision</dt>
            <dd className="panel__mono">
              #{draft.seq} saved {formatIsoUtc(draft.created_at)} by {draft.created_by || "unknown"}; hash {draft.normalized_hash.slice(0, 16)}…
            </dd>
            <dt>Published now</dt>
            <dd data-testid="review-published">
              {!published
                ? "nothing: guests see the neutral page"
                : rv.published_revision_id === draft.id && rv.assignment && rv.published_assignment_id === rv.assignment.id
                  ? "this revision, on the current hostname"
                  : "an earlier revision, or one approved for another hostname assignment"}
            </dd>
          </dl>

          {defaultDocsLink(origin) === null && (
            <p className="panel__toolbar-error" role="note" data-testid="review-no-origin">
              This viewer build has no valid default origin (VITE_DEFAULT_ORIGIN), so guests are shown the NEUTRAL page and not this
              branding. The previews below show exactly that.
            </p>
          )}

          <div className="platform-review__frames">
            {(["phone", "desktop"] as const).map((k) => (
              <figure key={k} className="platform-review__figure">
                <figcaption>
                  {k === "phone" ? "Phone" : "Desktop"} ({PREVIEW_WIDTHS[k]} px)
                </figcaption>
                <JoinBrandFrame width={PREVIEW_WIDTHS[k]} title={previewFrameTitle(k)} testId={`review-frame-${k}`}>
                  <PreviewJoinPage brand={brand} logoSrc={logoSrc} defaultOrigin={origin} fallbackName={import.meta.env.VITE_PRODUCT_NAME} width={k} />
                </JoinBrandFrame>
              </figure>
            ))}
          </div>

          {result.findings.length === 0 ? (
            <p data-testid="review-no-findings">The automated checks found nothing to acknowledge.</p>
          ) : (
            <fieldset className="platform-review__findings" data-testid="review-findings">
              <legend>Automated findings: acknowledge each one to approve</legend>
              {groupFindings(result.findings).map((f) => (
                <label key={f.code} className="platform-review__finding">
                  <input
                    type="checkbox"
                    checked={acked.has(f.code)}
                    disabled={frozen || stale}
                    onChange={(e) =>
                      setAcked((cur) => {
                        const next = new Set(cur);
                        if (e.target.checked) next.add(f.code);
                        else next.delete(f.code);
                        return next;
                      })
                    }
                    data-testid={`review-ack-${f.code}`}
                  />{" "}
                  <strong>{f.code}</strong>: {f.messages.join(" / ")}
                </label>
              ))}
              <label className="panel__toolbar-field">
                Override reason (recorded in the audit log)
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  maxLength={500}
                  disabled={frozen || stale}
                  data-testid="review-reason"
                />
              </label>
            </fieldset>
          )}

          <div className="panel__toolbar">
            <button className="panel__action" onClick={approve} disabled={!canApprove} data-testid="review-approve">
              Approve and publish
            </button>
            {published && (
              <button className="panel__action" onClick={() => setWithdrawing(true)} disabled={frozen || withdrawing} data-testid="review-withdraw-open">
                Withdraw published branding…
              </button>
            )}
            {block && !stale && (
              <span data-testid="review-block" className="panel__hint">
                {APPROVE_BLOCK_TEXT[block]}
              </span>
            )}
          </div>

          {withdrawing && (
            <form
              className="panel__form"
              aria-label="Withdraw branding"
              data-testid="review-withdraw"
              onSubmit={(e) => {
                e.preventDefault();
                withdraw();
              }}
            >
              <span>
                Guests on {rv.assignment ? <code dir="ltr">{rv.assignment.host}</code> : "this tenant's hostname"} will see the neutral
                DeskRally page again. The tenant can submit a new revision for review.
              </span>
              <label className="panel__toolbar-field">
                Reason
                <input value={withdrawReason} onChange={(e) => setWithdrawReason(e.target.value)} maxLength={500} disabled={frozen} data-testid="review-withdraw-reason" />
              </label>
              <button className="panel__action" type="submit" disabled={frozen || !reasonOk(withdrawReason)} data-testid="review-withdraw-submit">
                Withdraw
              </button>
              <button className="panel__action" type="button" onClick={() => setWithdrawing(false)} disabled={frozen}>
                Cancel
              </button>
            </form>
          )}
        </>
      )}

      {failure && (
        <div className="panel__toolbar-error" role="alert" data-testid="review-error" data-kind={failure.kind}>
          {failure.message}
          {failure.kind === "findings" && failure.findings.length > 0 && (
            <ul data-testid="review-error-findings">
              {failure.findings.map((f, i) => (
                <li key={`${f.code}-${i}`}>
                  <strong>{f.code}</strong>: {f.message}
                </li>
              ))}
            </ul>
          )}
          {stale && (
            <button className="panel__action" onClick={() => void load()} disabled={loading || frozen} data-testid="review-stale-reload">
              Reload review
            </button>
          )}
        </div>
      )}
      {notice && (
        <p role="status" data-testid="review-notice">
          {notice}
        </p>
      )}
    </section>
  );
}

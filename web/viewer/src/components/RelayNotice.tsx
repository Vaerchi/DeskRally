/**
 * The relay-limit notice (lib/relay_notice.ts): signaling brokered this session WITHOUT a relay credential
 * because the account is at its cap on outstanding ones, so only a direct connection can succeed, and on a
 * restrictive network that may fail. Says what happened, what it means and what to do, in plain words.
 *
 * Presentational on purpose, like IncomingDownloadPrompt: the notice arrives as a prop and the one gesture
 * leaves as a callback, so App owns when it exists and whether it has been dismissed.
 *
 * WHERE it goes matters, and it is not the session top bar. That bar is a Chrome-Remote-Desktop-style tab
 * (lib/session_chrome.ts): the whole row is hidden by default and nothing may be added to it. App renders
 * this as a strip in the session area, below the remote picture, where the other session banners live. At
 * the bottom rather than the top because the collapsed tab sits over the top-centre of the window, and
 * because the picture then keeps its top edge where it was.
 *
 * Non-blocking: it takes no focus, covers no remote pixels, and `role="status"` is a polite announcement,
 * not an alert. The server's own text (a string from the network) is shown ONLY as text, cleaned and
 * clipped by `relayNoticeDetail`, in a labelled aside inside a `<bdi>`: it is never interpolated into this
 * component's own wording and never becomes markup.
 */
import { RELAY_NOTICE_COPY, relayNoticeDetail } from "../lib/relay_notice";

export interface RelayNoticeProps {
  /** The server's own `relay_notice` text. Untrusted: shown as text, and only in the labelled aside. */
  notice: string;
  /** The technician dismissed it. App remembers that for this machine, through every reconnect to it, until the
   *  technician disconnects or connects to another machine. */
  onDismiss: () => void;
}

export function RelayNotice({ notice, onDismiss }: RelayNoticeProps) {
  const detail = relayNoticeDetail(notice);
  return (
    <section className="relay-notice" role="status" aria-label="Relay connection notice" data-testid="relay-notice">
      <div className="relay-notice__text">
        <p className="relay-notice__lead" data-testid="relay-notice-lead">
          <strong>{RELAY_NOTICE_COPY.headline}</strong> {RELAY_NOTICE_COPY.what} {RELAY_NOTICE_COPY.consequence}
        </p>
        <p className="relay-notice__action" data-testid="relay-notice-action">
          {RELAY_NOTICE_COPY.action}
        </p>
        {detail && (
          <p className="relay-notice__server" data-testid="relay-notice-server">
            Server message: <bdi>{detail}</bdi>
          </p>
        )}
      </div>
      <button
        type="button"
        className="relay-notice__dismiss"
        data-testid="relay-notice-dismiss"
        aria-label="Dismiss relay notice"
        onClick={onDismiss}
      >
        Dismiss
      </button>
    </section>
  );
}

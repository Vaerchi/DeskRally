import { useState } from "react";
import { machineInviteUrl } from "../lib/machine_url_params";

/**
 * "Invite a colleague" for the live session (docs/01 §7 P1): copies a console link to this machine.
 *
 * The link grants nothing by itself. The colleague signs in as themselves and the control plane
 * applies their own access, so a link forwarded to someone without access to this machine is refused
 * there. "Watch" joins view-only; "control" joins as a co-technician (a concurrent session).
 */
export function SessionInvite({ device, allowControl }: { device: string; allowControl: boolean }) {
  const [copied, setCopied] = useState<{ url: string; ok: boolean } | null>(null);

  const copy = async (observe: boolean) => {
    const url = machineInviteUrl(device, window.location.origin, observe);
    try {
      await navigator.clipboard.writeText(url);
      setCopied({ url, ok: true });
    } catch {
      // No clipboard permission (or an insecure origin): show the link so it can be copied by hand.
      setCopied({ url, ok: false });
    }
  };

  return (
    <div className="session-invite" data-testid="session-invite">
      <span>Invite a colleague:</span>
      <button type="button" className="panel__action" data-testid="session-invite-watch" onClick={() => void copy(true)}>
        Copy watch link
      </button>
      {allowControl && (
        <button type="button" className="panel__action" data-testid="session-invite-control" onClick={() => void copy(false)}>
          Copy control link
        </button>
      )}
      {copied?.ok && <span role="status" data-testid="session-invite-copied">Link copied. They sign in with their own account.</span>}
      {copied && !copied.ok && (
        <input readOnly aria-label="Invite link" data-testid="session-invite-link" value={copied.url}
          onFocus={(e) => e.currentTarget.select()} />
      )}
    </div>
  );
}

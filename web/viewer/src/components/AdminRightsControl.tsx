import { adminRightsView, type AdminRightsModel } from "../lib/admin_rights";

/**
 * docs/53: "Request admin rights" in the Session menu of an attended session. The rules (who sees
 * it, when it is enabled, what each state says) are `adminRightsView`'s; this only renders them.
 */
export function AdminRightsControl({
  model,
  observing,
  onRequest,
}: {
  model: AdminRightsModel;
  observing: boolean;
  onRequest: () => void;
}) {
  const v = adminRightsView(model, observing);
  if (!v.show) return null;
  return (
    <div className="admin-rights" data-testid="admin-rights">
      <button
        type="button"
        className="panel__action"
        data-testid="admin-rights-request"
        disabled={!v.canRequest}
        title={v.disabledReason ?? "Ask the guest for administrator rights so your input reaches admin windows"}
        onClick={onRequest}
      >
        Request admin rights
      </button>
      {v.status && <span role="status" data-testid="admin-rights-status">{v.status}</span>}
      {v.hint && <span className="admin-rights__hint" data-testid="admin-rights-hint">{v.hint}</span>}
    </div>
  );
}

import { MenuSection } from "./ToolbarMenu";

export type KeepAwakeModel = { on: boolean; pending: boolean };

type Action =
  | { type: "requested" }
  | { type: "confirmed"; on: boolean }
  | { type: "reset" };

export const KEEP_AWAKE_OFF: KeepAwakeModel = { on: false, pending: false };

export function keepAwakeReducer(model: KeepAwakeModel, action: Action): KeepAwakeModel {
  switch (action.type) {
    case "requested": return { ...model, pending: true };
    case "confirmed": return { on: action.on, pending: false };
    case "reset": return KEEP_AWAKE_OFF;
  }
}

export function KeepAwakeControl({ model, advertised, observing, viewOnly, onRequest }: {
  model: KeepAwakeModel;
  advertised: boolean;
  observing: boolean;
  viewOnly: boolean;
  onRequest: (on: boolean) => void;
}) {
  if (!advertised || observing || viewOnly) return null;
  return (
    <MenuSection title="Session" testId="session-menu-controls">
      <button type="button" className="panel__action" data-testid="keep-awake-toggle"
        aria-pressed={model.on} aria-busy={model.pending} disabled={model.pending}
        onClick={() => onRequest(!model.on)}>
        Keep awake{model.pending && "…"}
      </button>
    </MenuSection>
  );
}

export function KeepAwakeBadge({ model }: { model: KeepAwakeModel }) {
  return model.on ? <span className="app__input-control" role="status" data-testid="keep-awake-badge">Awake</span> : null;
}

export interface EpochScope {
  isCurrent(epoch: number): boolean;
}

/** Returns an onError handler that silently drops errors from a superseded transport epoch. */
export function guardedTransportError(
  scope: EpochScope,
  epoch: number,
  setError: (message: string) => void,
): (e: Error) => void {
  return (e) => {
    if (!scope.isCurrent(epoch)) return;
    setError(e.message);
  };
}

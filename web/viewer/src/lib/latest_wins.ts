/**
 * Latest-wins guard for async reads: a monotonic generation counter. begin() takes a token for a new
 * operation (making every earlier token stale); isCurrent(token) is true only for the newest token that
 * has not been invalidated since; invalidate() makes all outstanding tokens stale without starting one.
 * Pure and framework-free so the ordering rule is unit-testable on its own.
 */
export interface LatestWins {
  begin(): number;
  isCurrent(token: number): boolean;
  invalidate(): void;
}

export function createLatestWins(): LatestWins {
  let generation = 0;
  return {
    begin: () => ++generation,
    isCurrent: (token) => token === generation,
    invalidate: () => {
      generation += 1;
    },
  };
}

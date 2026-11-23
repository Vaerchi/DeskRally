/**
 * Strip trailing "/" characters. A plain loop rather than `s.replace(/\/+$/, "")`: that regex backtracks quadratically
 * on a long run of slashes that is NOT at the end (CodeQL js/polynomial-redos). The inputs are origins and base URLs,
 * so the risk was small, but the loop costs nothing and is linear.
 */
export function trimTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47 /* "/" */) end--;
  return end === s.length ? s : s.slice(0, end);
}

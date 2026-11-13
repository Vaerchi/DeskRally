/**
 * Platform "Reach" tab (docs/68 stage 5): per-artifact REQUEST counts from the Caddy access log, for the platform
 * operator only. It never says "downloads" for a raw count, never "users" and never "installs": the figures are
 * requests, an approximate completed count and a salted per-day unique-ish count, and the section 3 caveats are
 * printed under the table.
 *
 * Access is the server's (same gate as the tenant listing: an operator, with a second factor within 12 h). A 403
 * re-reads /platform/me: an operator whose factor lapsed is asked for an authenticator code here and the report is
 * read again; anyone else gets the plain refusal. Every read is audited server-side.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ConsoleApiError } from "../lib/console_api";
import type { ConsoleApi } from "../lib/console_api";
import { createLatestWins } from "../lib/latest_wins";
import {
  REACH_WINDOWS,
  caveatsToShow,
  completedText,
  fmtCount,
  reachRange,
  sparklinePoints,
  summarize,
  uniqueText,
  type ArtifactSummary,
  type ReachReport,
  type ReachWindow,
} from "../lib/reach";

const SPARK_W = 96;
const SPARK_H = 24;

export function Sparkline({ values, label }: { values: readonly number[]; label: string }) {
  return (
    <svg className="reach__spark" width={SPARK_W} height={SPARK_H} viewBox={`0 0 ${SPARK_W} ${SPARK_H}`} role="img" aria-label={label} data-testid="reach-spark">
      <polyline points={sparklinePoints(values, SPARK_W, SPARK_H)} fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

export function PlatformReach({ api }: { api: ConsoleApi }) {
  const [report, setReport] = useState<ReachReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [needCode, setNeedCode] = useState(false);
  const [code, setCode] = useState("");
  const [codeError, setCodeError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [windowDays, setWindowDays] = useState<ReachWindow>(30);
  const guard = useRef(createLatestWins());
  const to = useRef<string>(reachRange(new Date()).to);

  const load = useCallback(async () => {
    const token = guard.current.begin();
    const { from, to: end } = reachRange(new Date());
    to.current = end;
    setBusy(true);
    setError(null);
    try {
      const r = await api.getPlatformReach(from, end);
      if (!guard.current.isCurrent(token)) return;
      setReport(r);
      setNeedCode(false);
    } catch (e) {
      if (!guard.current.isCurrent(token)) return;
      setReport(null);
      if (e instanceof ConsoleApiError && e.status === 403) {
        // A lapsed second factor is the one 403 the operator can cure here.
        let lapsed = false;
        try {
          const w = await api.platformWhoami();
          lapsed = w.operator && !w.mfa_ok;
        } catch {
          /* fall through to the plain refusal */
        }
        if (!guard.current.isCurrent(token)) return;
        if (lapsed) {
          setNeedCode(true);
          return;
        }
        setError("The request report is for the platform operator, with a second factor from the last 12 hours.");
        return;
      }
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (guard.current.isCurrent(token)) setBusy(false);
    }
  }, [api]);

  useEffect(() => {
    const g = guard.current;
    void load();
    return () => g.invalidate();
  }, [load]);

  const verify = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (verifying) return;
      setVerifying(true);
      setCodeError(null);
      try {
        await api.stepUp(code.trim());
      } catch {
        setCodeError("That code was not accepted.");
        setVerifying(false);
        return;
      }
      setVerifying(false);
      setCode("");
      void load();
    },
    [api, code, load, verifying],
  );

  const rows = report?.rows;
  const human = useMemo(() => (rows ? summarize(rows, "human", to.current, windowDays) : []), [rows, windowDays]);
  const updates = useMemo(() => (rows ? summarize(rows, "update", to.current, windowDays) : []), [rows, windowDays]);

  return (
    <div className="reach" data-testid="platform-reach">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Request counts</span>
        <span role="group" aria-label="Window" className="reach__windows">
          {REACH_WINDOWS.map((n) => (
            <button
              key={n}
              type="button"
              className="panel__action"
              aria-pressed={windowDays === n}
              onClick={() => setWindowDays(n)}
              data-testid={`reach-window-${n}`}
            >
              {n} days
            </button>
          ))}
        </span>
        <button className="panel__action" type="button" onClick={() => void load()} disabled={busy}>
          {busy ? "Loading…" : "Refresh"}
        </button>
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="reach-error">
            {error}
          </span>
        )}
      </div>

      {needCode && (
        <form className="panel__form" onSubmit={(e) => void verify(e)} aria-label="Verify it's you" data-testid="reach-stepup">
          <span className="panel__toolbar-title">Verify it's you</span>
          <span>Viewing request counts needs an authenticator code from the last 12 hours.</span>
          <label className="panel__toolbar-field">
            Code
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" data-testid="reach-stepup-code" />
          </label>
          <button className="panel__action" type="submit" disabled={verifying || code.trim() === ""}>
            {verifying ? "Verifying…" : "Verify"}
          </button>
          {codeError && (
            <span className="panel__toolbar-error" role="alert" data-testid="reach-stepup-error">
              {codeError}
            </span>
          )}
        </form>
      )}

      {report && (
        <>
          <ReachTable
            title="Person-facing artifacts"
            testId="reach-human"
            rows={human}
            window={windowDays}
            empty="No requests for a person-facing artifact in this window."
            full
          />
          <ReachTable
            title="Updates (machine traffic, separate)"
            testId="reach-updates"
            rows={updates}
            window={windowDays}
            empty="No update requests in this window."
          />
        </>
      )}

      <div className="reach__caveats" data-testid="reach-caveats">
        <strong>How to read these figures</strong>
        <ul>
          {caveatsToShow(report).map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function ReachTable({ title, testId, rows, window, empty, full }: { title: string; testId: string; rows: ArtifactSummary[]; window: number; empty: string; full?: boolean }) {
  return (
    <section className="reach__section" data-testid={testId}>
      <h3 className="reach__title">{title}</h3>
      <div className="reach__scroll">
        <table className="panel__table">
          <thead>
            <tr>
              <th>Artifact</th>
              <th title="Counted GET requests. Includes bots, retries and previews.">{full ? "Download requests" : "Requests"}</th>
              {full && <th title="A 200 whose logged size matches the artifact's current size.">Completed (approx.)</th>}
              {full && <th title="Salted per-day count of (address, browser) pairs; the mean over days with a usable figure.">Unique-ish clients / day (mean)</th>}
              <th>{window} days</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td className="panel__empty" colSpan={full ? 5 : 3}>
                  {empty}
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr key={r.artifact} data-testid={`reach-row-${r.artifact}`}>
                <td className="panel__name">{r.artifact}</td>
                <td className="panel__mono" data-testid="reach-requests">
                  {fmtCount(r.requests)}
                </td>
                {full && (
                  <td className="panel__mono" data-testid="reach-completed">
                    {completedText(r)}
                  </td>
                )}
                {full && (
                  <td className="panel__mono" data-testid="reach-unique">
                    {uniqueText(r)}
                    {r.uniquePartial && (
                      <>
                        {" "}
                        <span className="panel__badge" data-tone="pending" data-testid="reach-partial" title="Some days carry a lower-bound or missing figure; those days are left out of the mean.">
                          partial
                        </span>
                      </>
                    )}
                  </td>
                )}
                <td>
                  <Sparkline values={r.daily} label={`Requests per day for ${r.artifact}, last ${window} days`} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

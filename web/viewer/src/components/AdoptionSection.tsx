/**
 * Tenant "Adoption" card (docs/68 stage 5), inside the Security panel beside the other Owner-only sections.
 *
 * It shows this tenant's OWN counts: new devices per week, devices online in the last 30 days (machine.last_seen, kept by the presence sweep, 0079), the attended-session
 * funnel and the agent-version spread. Counts only; no person or machine is named. GET /adoption needs manage_tenant, so a
 * 403 (or 404, a server without the route) renders nothing at all, like the recording policy section.
 */

import { useEffect, useRef, useState } from "react";
import { ConsoleApiError } from "../lib/console_api";
import type { ConsoleApi } from "../lib/console_api";
import { fmtCount, funnelSteps, shareText, versionLabel, type Adoption } from "../lib/reach";

export function AdoptionSection({ api }: { api: ConsoleApi }) {
  const [data, setData] = useState<Adoption | null>(null);
  const [hidden, setHidden] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);

  useEffect(() => {
    const id = ++seq.current;
    void (async () => {
      try {
        const a = await api.getAdoption();
        if (id === seq.current) setData(a);
      } catch (e) {
        if (id !== seq.current) return;
        if (e instanceof ConsoleApiError && (e.status === 403 || e.status === 404)) setHidden(true);
        else setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      seq.current++;
    };
  }, [api]);

  if (hidden) return null;
  const maxWeek = data ? Math.max(1, ...data.newDevicesPerWeek.map((w) => w.count)) : 1;

  return (
    <section className="adoption" data-testid="adoption" aria-label="Adoption">
      <div className="panel__toolbar">
        <span className="panel__toolbar-title">Adoption</span>
        {data && <span className="adoption__range">{data.from} to {data.to} (UTC)</span>}
        {error && (
          <span className="panel__toolbar-error" role="alert" data-testid="adoption-error">
            {error}
          </span>
        )}
      </div>
      {data && (
        <div className="adoption__grid">
          <div className="adoption__card">
            <div className="adoption__big" data-testid="adoption-active">{fmtCount(data.activeDevices30d)}</div>
            <div className="adoption__cap"
              title="The server records a device as online every few minutes while it is connected. Before November 2026 it was recorded only when a console listed it, so older days may undercount.">
              devices online in the last 30 days
            </div>
          </div>

          <div className="adoption__card" data-testid="adoption-weeks">
            <div className="adoption__cap">New devices per week</div>
            {data.newDevicesPerWeek.length === 0 ? (
              <div className="panel__empty">None enrolled in this range.</div>
            ) : (
              <ul className="adoption__bars">
                {data.newDevicesPerWeek.map((w) => (
                  <li key={w.week}>
                    <span className="panel__mono">{w.week}</span>
                    <span className="adoption__bar" aria-hidden="true">
                      <span style={{ width: `${(w.count / maxWeek) * 100}%` }} />
                    </span>
                    <span className="panel__mono">{fmtCount(w.count)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="adoption__card" data-testid="adoption-funnel">
            <div className="adoption__cap">Support sessions created in this range</div>
            <ul className="adoption__bars">
              {funnelSteps(data.funnel).map((s) => (
                <li key={s.label}>
                  <span>{s.label}</span>
                  <span className="panel__mono">{fmtCount(s.count)}</span>
                  <span className="panel__mono adoption__share">{shareText(s.share)}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="adoption__card" data-testid="adoption-versions">
            <div className="adoption__cap">Agent versions (enrolled devices)</div>
            {data.agentVersions.length === 0 ? (
              <div className="panel__empty">No devices.</div>
            ) : (
              <ul className="adoption__bars">
                {data.agentVersions.map((v) => (
                  <li key={v.version}>
                    <span className="panel__mono">{versionLabel(v.version)}</span>
                    <span className="panel__mono">{fmtCount(v.count)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

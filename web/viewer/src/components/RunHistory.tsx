import { useEffect, useState } from "react";
import { formatIsoUtc } from "../backstage/panels";
import type { ConsoleApi, RunHistoryEntry, RunHistoryPage } from "../lib/console_api";

export function RunHistoryRows({ runs }: { runs: RunHistoryEntry[] }) {
  if (runs.length === 0) return null;
  return (
    <table className="panel__table">
      <thead>
        <tr><th>When (UTC)</th><th>Technician</th><th>Item</th><th>Run as</th><th>Result</th></tr>
      </thead>
      <tbody>
        {runs.map((run) => (
          <tr key={run.request_id}>
            <td className="panel__mono">{formatIsoUtc(run.requested_at)}</td>
            <td>{run.technician_name}</td>
            <td>{run.item_name}{run.item_version != null && `@${run.item_version}`}{run.item_deleted && " (deleted)"}</td>
            <td>{run.run_as}</td>
            <td>{run.result}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function RunHistory({
  api, scope, id, showEmpty = false,
}: {
  api: Pick<ConsoleApi, "listRunHistory">;
  scope: "machines" | "toolbox";
  id: string;
  showEmpty?: boolean;
}) {
  const [page, setPage] = useState<RunHistoryPage>({ runs: [] });
  const [request, setRequest] = useState({ offset: 0 });
  const { offset } = request;
  const [pending, setPending] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    let current = true;
    void api.listRunHistory(scope, id, offset).then((next) => {
      if (!current) return;
      setPage((prev) => next ? { ...next, runs: offset === 0 ? next.runs : [...prev.runs, ...next.runs] } : { runs: [] });
    }, () => {
      if (current) setError(true);
    }).finally(() => {
      if (current) setPending(false);
    });
    return () => { current = false; };
  }, [api, scope, id, offset, request]);

  if (!page.runs.length && !error && !showEmpty) return null;
  const nextOffset = page.next_offset;
  return (
    <section className="panel" aria-label="Run history">
      <h3 className="panel__toolbar-title">Run history</h3>
      <RunHistoryRows runs={page.runs} />
      {error && <p role="alert">Could not load run history.</p>}
      {!page.runs.length && !error && <p>{pending ? "Loading…" : "No run history to display."}</p>}
      {nextOffset != null && (
        <button className="panel__action" disabled={pending} onClick={() => {
          setPending(true);
          setError(false);
          setRequest({ offset: nextOffset });
        }}>Load more</button>
      )}
    </section>
  );
}

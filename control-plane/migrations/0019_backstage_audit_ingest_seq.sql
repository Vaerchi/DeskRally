-- Backstage audit export: a per-tenant APPEND-ORDERED cursor column.
--
-- WHY THIS EXISTS. `GET /audit/backstage/export` originally paged on `(session_id, seq)`, which is
-- a total order over a SNAPSHOT but is not an append order: `session_id` is a random v4 uuid and
-- `seq` restarts at 0 for every chain (each grant install builds a fresh AuditChain in the agent).
-- A SIEM collector that stored the last returned pair and resumed from it therefore never saw
-- anything later appended under a lower-sorting session_id — roughly half of all subsequent
-- events, silently, with nothing in the response distinguishing "caught up" from "records
-- skipped". Since the console's AuditForwarder flushes every 10s and new sessions start
-- constantly, that is the normal case, not an edge case.
--
-- `ingest_seq` is the fix and mirrors what `audit_event` (the management trail, 0014) already
-- does: a dense, gapless, monotonic per-tenant counter assigned AT APPEND under the same
-- transaction-scoped advisory lock, so ordering by it is exactly ingest order and a resuming
-- collector cannot miss a row. It is deliberately NOT a sequence/identity default: sequence values
-- are handed out before commit, so two concurrent appends can commit out of order and a tailing
-- reader would skip the laggard. The lock + max()+1 makes the order the COMMIT order.
--
-- `ingest_seq` is control-plane metadata and is NOT part of the agent's SHA-256 preimage — it must
-- never be added to the exported event body, or a collector re-verifying the chain would hash
-- bytes the agent never hashed. The export carries it as a response header instead.

ALTER TABLE backstage_audit_event ADD COLUMN ingest_seq bigint;

-- Backfill deterministically for rows ingested before this migration. `ingested_at` is the
-- control-plane receipt clock, which is the best available approximation of append order; the
-- (session_id, seq) tiebreak makes the result stable when several rows share a timestamp (a whole
-- batch is inserted in one transaction and so shares one now()).
WITH numbered AS (
    SELECT tenant_id,
           session_id,
           seq,
           row_number() OVER (PARTITION BY tenant_id
                              ORDER BY ingested_at, session_id, seq) - 1 AS n
    FROM backstage_audit_event
)
UPDATE backstage_audit_event e
   SET ingest_seq = numbered.n
  FROM numbered
 WHERE e.tenant_id  = numbered.tenant_id
   AND e.session_id = numbered.session_id
   AND e.seq        = numbered.seq;

ALTER TABLE backstage_audit_event ALTER COLUMN ingest_seq SET NOT NULL;

-- Uniqueness is the backstop that keeps the counter dense: a second append that read the same
-- max() (i.e. one that skipped the advisory lock) collides here instead of silently duplicating a
-- cursor position and hiding a row from every collector that pages past it. The implicit btree
-- this creates on (tenant_id, ingest_seq) is also exactly the export's ORDER BY, so paging is an
-- index scan rather than a sort.
ALTER TABLE backstage_audit_event
    ADD CONSTRAINT uq_backstage_audit_tenant_ingest UNIQUE (tenant_id, ingest_seq);

-- 0014_mgmt_audit_chain.sql — hash-chain the management-plane audit trail.
--
-- audit_event (0001_core.sql) was FLAT: append-only for the app role (0006 revokes
-- UPDATE/DELETE), but a privileged writer — or anyone who obtains the owner role — could edit or
-- delete rows without detection. The BACKSTAGE audit (0004_audit.sql) has been hash-chained since
-- H2; this migration brings the management audit to the same tamper-evidence bar, per-TENANT
-- (the natural scope here — mgmt events have no session; mirrors "hash-chained, per-tenant,
-- exportable to SIEM" in docs/02-architecture.md).
--
-- Chain contract (canonical mgmt-audit v1, control-plane/mgmtaudit_canonical.go):
--   hash = lower-hex SHA-256 over "RMTMAUDITv1\x00" || lpStr(id) || u64be(seq)
--          || lpStr(tenant_id) || lpStr(actor_user_id|"") || lpStr(action) || lpStr(target_kind|"")
--          || lpStr(target_id|"") || i64be(occurred_at ms) || lpStr(canonical_metadata)
--          || lpStr(prev_hash)
--   seq starts at 0 per tenant; genesis prev_hash is the empty string (same convention as the
--   backstage chain). occurred_at is truncated to MILLISECONDS by the store before hashing and
--   inserting, so the timestamptz column (µs precision) round-trips the hashed value exactly.
--   Metadata is hashed over a canonical JSON re-encoding (sorted keys), not raw bytes, because
--   jsonb does not preserve key order or number spelling.
--
-- The store computes seq/prev_hash/hash in Go inside one transaction, serialized per tenant with
-- a pg_advisory_xact_lock (management audit has MANY concurrent writers, unlike the single-writer
-- backstage chain). The unique index below is the DB backstop that turns any race or replay into
-- a hard insert error, mirroring 0004's UNIQUE(session_id, seq).
--
-- Legacy rows (inserted before this migration) keep NULL seq/prev_hash/hash: their content
-- cannot be retro-hashed trustworthily (the chain would just attest "whatever was there when
-- 0014 ran"). The chain covers every event from this migration onward; GET /audit/verify reports
-- chained coverage. Note the inherent hash-chain limit: deleting the newest N rows (tail
-- truncation) is not detectable without an external anchor — the DB-level append-only REVOKE
-- (0006) is the guard against that for the app role.

ALTER TABLE audit_event
    ADD COLUMN seq       bigint,
    ADD COLUMN prev_hash text,
    ADD COLUMN hash      text;

-- Chained fields travel together: a row is either legacy (all NULL) or fully chained.
ALTER TABLE audit_event
    ADD CONSTRAINT audit_event_chain_all_or_none CHECK (
        (seq IS NULL AND prev_hash IS NULL AND hash IS NULL)
        OR (seq IS NOT NULL AND prev_hash IS NOT NULL AND hash IS NOT NULL)
    );

-- Per-tenant replay/duplicate backstop + the ascending scan the verifier/exporter walks.
-- NULL seq (legacy) rows never collide: NULLs are distinct in a unique index.
CREATE UNIQUE INDEX uq_audit_event_tenant_seq ON audit_event (tenant_id, seq);

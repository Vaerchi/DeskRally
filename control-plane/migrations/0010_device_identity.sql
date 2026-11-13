-- Device-identity lookup — the privileged, RLS-bypassing read the SIGNALING server needs in order
-- to authenticate `register_agent` (docs/11-agent-identity-contract.md §4).
--
-- WHY THE RLS BYPASS IS NECESSARY: signaling is not a tenant principal. A WebSocket client claims a
-- device id and then has to prove possession of that device's enrolled key; at that moment nothing
-- has established which tenant the connection belongs to, so app.current_tenant cannot be pinned
-- and an ordinary SELECT on `machine` would be filtered to nothing (or raise). This is exactly the
-- 0003/0007 bootstrap shape: a SECURITY DEFINER function keyed on an exact identifier that returns
-- the minimum needed to then run everything else scoped.
--
-- WHY IT IS SAFE: `machine.device_id` is GLOBALLY unique (0008), so at most one row matches and the
-- answer cannot be ambiguous across tenants. The function returns only (device_id, tenant_id,
-- pubkey) — a PUBLIC key and the ids that key is bound to; no hostname, group, session or audit
-- data. It performs no writes. Rows with no pinned key (the legacy authenticated POST /enroll path
-- leaves `pubkey` empty) are excluded rather than returned as "no key": a machine that cannot be
-- authenticated must fail closed, never fall back to being trusted. Enumeration is prevented ABOVE
-- this function, in Go: the HTTP route is mounted only behind a 32+ character service token
-- (control-plane/http.go handleDeviceIdentity), compared in constant time and throttled per source.
--
-- SECURITY DEFINER hardening as in 0003/0006/0007: apply as the RLS-bypassing owner role,
-- search_path pinned so the body cannot be hijacked.
CREATE FUNCTION cp_machine_identity_by_device_id(p_device_id text)
    RETURNS TABLE (device_id text, tenant_id uuid, pubkey bytea)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = public, pg_catalog
AS $$
    SELECT m.device_id, m.tenant_id, m.pubkey
    FROM machine m
    WHERE m.device_id = p_device_id
      AND m.pubkey IS NOT NULL
      AND length(m.pubkey) > 0
$$;

-- Same grant posture as the 0003/0006/0007 bootstrap functions: EXECUTE to PUBLIC (the app role
-- name is deployment-specific). The function is self-limiting — it keys on an exact device id and
-- returns a public key.
GRANT EXECUTE ON FUNCTION cp_machine_identity_by_device_id(text) TO PUBLIC;

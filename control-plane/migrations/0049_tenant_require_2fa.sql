-- Tenant-level 2FA enforcement policy (docs/01 §10 "TOTP 2FA — enforcement policy").
--
-- Adds require_2fa to the tenant row so a tenant Owner can require ALL members to have a
-- confirmed TOTP enrollment before they can sign in. The column lives on tenant (not a
-- separate table) because it is a small, single-boolean policy and because the existing
-- selectUser query already JOINs tenant — carrying require_2fa there costs nothing per
-- request and is read exactly once per login attempt, on the same row that carries
-- disabled_at (the TenantSuspended check). Both fields share the same fail-closed posture:
-- if the join somehow returned nothing, the query returns ErrNoUser, which is the right
-- direction.
--
-- DEFAULT FALSE: an upgrade that adds this column leaves every existing tenant's enforcement
-- OFF, so no user is locked out after a migration. Tenants that want to enforce 2FA opt in
-- explicitly via PUT /tenant/security-policy.
--
-- Anti-lockout invariant (enforced in the handler, not here): a caller can only set
-- require_2fa = true when they themselves have a confirmed TOTP enrollment, so they cannot
-- fence themselves out of the console with one request.

ALTER TABLE tenant ADD COLUMN require_2fa BOOLEAN NOT NULL DEFAULT FALSE;

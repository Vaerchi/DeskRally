-- 0040_group_allow_backstage_under_view_only.sql — make the "view only" label HONEST BY DEFAULT, and keep
-- the exception reachable (docs/01 §5; the trust-model arc, loops 79/80/99).
--
-- THE PROBLEM. 0035 gave an admin a per-group switch — enforce_view_only — that the AGENT enforces via a
-- control-plane-signed session policy the technician cannot decline. It covers what `AccessLevel::ViewOnly`
-- covers (agent/src/session_policy.rs): injected input is dropped, and reboot / tool-launch / command-run /
-- lock / log-off / shut-down are refused. It does NOT reach BACKSTAGE. The remote shell and the other
-- backstage tool panels ride a second, independent trust axis — a control-plane-signed grant gated on
-- CapBackstageShell / CapManageMachines — and nothing on the agent's backstage path consults the session's
-- access level. So a technician holding backstage capability could run commands as SYSTEM on a machine the
-- console labelled "view only". The separation of the two axes was deliberate and granted nobody a
-- capability they did not already hold; the LABEL was the defect, and an admin ticking a box called
-- "Force view-only" will not infer "except the remote shell".
--
-- WHAT THIS COLUMN DOES. From now on a group that enforces view-only also REFUSES backstage grants:
-- handleMintGrant (control-plane/http.go) answers 409 rather than minting, mirroring what handleMintElevation
-- (control-plane/http_elevation.go) already did for elevation grants against the same mandate — the two
-- privilege-ISSUING endpoints previously disagreed about the same admin decision, and now do not. This column
-- is the explicit per-group opt-out for the case that made the combination worth keeping: deliberate
-- unattended maintenance (a patch window, a scripted remediation) on machines that must otherwise stay
-- watch-only. Setting it says, in the audit trail, that somebody chose it.
--
-- WHY THE COLUMN IS NAMED FOR THE PERMISSION AND NOT THE PROTECTION — the part that must survive any later
-- "tidy-up". The safe state has to be the DEFAULT and the ZERO value, because three existing facts compose
-- into a fleet-wide off switch otherwise:
--
--   1. Go's zero value for a bool is false.
--   2. PUT /machine-groups/{id}/session-policy is a FULL OVERWRITE, not a patch (groupSessionPolicyRequest,
--      control-plane/http_group_session_policy.go): a field the client omits decodes to its zero value and is
--      WRITTEN as such. That semantic is itself deliberate — without it "turn view-only off" would be
--      inexpressible — so it is not going to change.
--   3. GroupSessionPolicy.IsDefault() drives row DELETION.
--
-- A column called `refuse_backstage_under_view_only DEFAULT true` would therefore be switched OFF by every
-- pre-0040 console build, operator script and hand-rolled curl that touched a group's policy without knowing
-- the field existed — a security control disabled by a client that never mentioned it, recorded in the audit
-- trail as an ordinary cap edit. Named `allow_… DEFAULT false`, that same stale caller writes false, which IS
-- the protected state. Fail-closed by construction rather than by every caller staying current (docs/14 §0.1;
-- docs/25 keeps finding this default-flip family).
--
-- NOTE FOR THE STORE, REPEATING 0035'S WARNING BECAUSE THIS IS THE SECOND TIME. Adding a column changes when
-- a row may be DELETED. GroupSessionPolicy.IsDefault() must test THIS setting too, or a group whose only
-- stored decision is the backstage opt-out has its row dropped on write and reads back as the default — the
-- console checkbox unticking itself after a save. That direction fails safe (the group ends up protected),
-- which is precisely what makes it a bug nobody's alarm catches. IsDefault() now reads
-- `cap == 0 && !enforce_view_only && !allow_backstage_under_view_only`, and the pg store carries the column
-- through all THREE of its SQL sites: Get's SELECT, Set's INSERT + ON CONFLICT DO UPDATE, and List's SELECT.
--
-- The value is DORMANT while enforce_view_only is false, and is deliberately stored rather than normalized
-- away: an admin composing "opt-out first, mandate second" must not lose half the edit to click order, and a
-- checkbox that unticks itself is the same class of lie as rendering an unread value as a safe one. Nothing
-- reads it outside the enforce_view_only branch, so the inert combination is safe by definition.
--
-- It lives on group_session_policy for the same reasons 0035 did: the same kind of decision, about the same
-- subject, set by the same capability (CapManageGroups) on the same screen, behind the composite FK to
-- machine_group(tenant_id, id) that already makes a cross-tenant write impossible. The table inherits its RLS
-- policy and rmt_app grant from 0034/0005, so no new policy and no new GRANT. Applied WITH the core in the
-- test harness (pgstore_test.go's always-on list) like 0034/0035, because PgGroupSessionPolicyStore's SELECT
-- projections read it on every group-policy read.
--
-- NOT A PRIVILEGE BOUNDARY ON AN UNATTENDED HOST, and the header of crates/agent-* says why: an agent running
-- as SYSTEM can already do anything on that box, so what this buys is ATTRIBUTION AND POLICY — no new signed,
-- audited backstage authorization is ISSUED against a group the operator declared watch-only, and the audit
-- trail therefore cannot show one being handed out. That is the same thing quarantine buys
-- (refuseOutOfServiceMachine) and it is worth exactly as much.

ALTER TABLE group_session_policy
    ADD COLUMN allow_backstage_under_view_only boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN group_session_policy.allow_backstage_under_view_only IS
    'Opt-out: when true, a group that enforces view-only may still be issued BACKSTAGE grants (the remote '
    'shell and tool panels), for deliberate unattended maintenance. False — the default and the zero value — '
    'means handleMintGrant refuses to mint a backstage grant for machines in this group, so the "view only" '
    'label means watch-only full stop. NAMED FOR THE PERMISSION ON PURPOSE: the PUT that writes this row is a '
    'full overwrite, so a client omitting the field writes false, and false must be the PROTECTED state. '
    'Dormant while enforce_view_only is false (docs/01 §5).';

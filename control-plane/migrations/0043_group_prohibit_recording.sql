-- 0043_group_prohibit_recording.sql — let an admin BAN session recording for a machine group
-- (docs/01 §5; "allow_recording / require_recording on group_session_policy" backlog item).
--
-- THE NEW FIELD. `prohibit_recording` lets an admin bar technicians from starting a session
-- recording on machines in a group. When set, the control plane mints a signed session policy
-- that carries `allow_recording: false`; the agent verifies the signature and refuses every
-- `StartRecording` message for the session's lifetime. This closes the gap docs/01 §5 notes:
-- "any technician with a session can record" — which undermines a group's view-only mandate when
-- the admin's intent is "watch only, nothing saved to disk on the customer's side".
--
-- WHY `prohibit_recording DEFAULT false` AND NOT `allow_recording DEFAULT true`.
-- The same three facts that drove 0040's naming decision apply here:
--
--   1. Go's zero value for a bool is false.
--   2. PUT /machine-groups/{id}/session-policy is a FULL OVERWRITE (groupSessionPolicyRequest):
--      an omitted field decodes to its zero value and is WRITTEN as that.
--   3. GroupSessionPolicy.IsDefault() drives row DELETION.
--
-- If the field were named `allow_recording` with the "safe" value being `true`, then every older
-- console build, operator script and hand-rolled curl that predates this migration would PUT a body
-- omitting the field and thereby PROHIBIT recording on whichever group it touched — recording
-- banned by a client that never mentioned it, leaving an audit entry that looks like a routine cap
-- edit. Named `prohibit_recording DEFAULT false`, that same stale caller writes false, which is
-- "recording is not prohibited", i.e. the current behaviour. Fail-closed by construction; fail-
-- OPEN (for backward compat) would mean fail-safe here: recording that was previously allowed
-- remains allowed. The RESTRICTION direction is the opt-in.
--
-- HOW IT REACHES THE AGENT. The column's value flows into the signed session policy the control
-- plane mints at session start (and re-mints on every lease renewal). The minting code converts:
-- `allow_recording = !group.ProhibitRecording`. The signed preimage now ends with a single byte
-- (0x00 or 0x01) for `allow_recording`, so a viewer cannot tamper the field without invalidating
-- the Ed25519 signature. A replay from another session is already impossible (session binding,
-- loop 86). See session_policy_mint.go and agent/src/session_policy.rs for the preimage layout.
--
-- GOLDEN VECTOR UPDATE. Adding the byte to the preimage changes every existing golden vector hex
-- constant (the signature changes with the preimage). Both the Go constants in
-- session_policy_mint_test.go and the Rust constants in agent/src/session_policy.rs are updated
-- in this commit; the cross-language interop test `verifies_go_minted_session_policy` is updated
-- with the new wire JSON.
--
-- IsDefault() NOTE. Like 0040, this column changes when a row may be deleted.
-- GroupSessionPolicy.IsDefault() is extended to `... && !ProhibitRecording`, so a group whose
-- ONLY stored decision is the recording ban is not silently deleted on write (the same class of
-- bug 0035→0040 already fixed once).
--
-- SCOPE NOTE. Enforcement lives at the AGENT, not the console. A console that predates this
-- migration simply shows the Record button regardless; the agent will refuse `StartRecording`
-- when the signed policy says so. The console update (hiding the button via the
-- `allow_recording` field in `SessionPolicyInstalled`) is handled in the Viewer/App changes in
-- this commit, not in SQL.
--
-- Applied WITH the core in the test harness (pgstore_test.go) like 0034–0040, because
-- PgGroupSessionPolicyStore's SELECT projections read it on every group-policy read.

ALTER TABLE group_session_policy
    ADD COLUMN prohibit_recording boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN group_session_policy.prohibit_recording IS
    'When true, technicians may not start a session recording on machines in this group. '
    'The control plane mints a signed session policy with allow_recording=false; the agent '
    'verifies and refuses StartRecording for the session lifetime. '
    'False — the default and the zero value — preserves the current behaviour (recording permitted). '
    'NAMED FOR THE RESTRICTION ON PURPOSE: the PUT that writes this row is a full overwrite, so a '
    'client omitting the field writes false, which must be the PERMISSIVE state (no ban). '
    'See migration 0043 header for the full naming argument (same shape as allow_backstage_under_view_only).';

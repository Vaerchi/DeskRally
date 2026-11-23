-- 0037_machine_require_session_policy.sql — close the UNATTENDED half of the view-only floor
-- (docs/01 §5; the trust-model arc, loops 79-86). The sibling of 0036, which closed the attended half.
--
-- `require_session_policy` is an OPERATOR CONFIG FLAG on an installed agent
-- (crates/agent-windows/src/config.rs). When it is set the agent opens EVERY session view-only and stays
-- there until a control-plane-signed access policy verifies — the anti-tamper measure that stops a
-- technician who controls their own console from simply not forwarding the policy frame.
--
-- But the control plane never knew the flag was set. handleStartSession mints a policy only when the
-- machine's GROUP has enforce_view_only, and the flag's own doc says "Set BOTH for an enforcing
-- deployment" with no mention of groups. So an agent shipped with the flag, in a group whose mandate an
-- admin later cleared — or never set — opens VIEW-ONLY FOREVER: no input, no reboot, no command bar, and
-- retrying never helps, with nothing on screen explaining why. That is 0036's own header text, verbatim,
-- on the sibling path.
--
-- The control plane has no memory to fix it with, because it never told that agent to floor: the flag is
-- the AGENT's, decided before it ever spoke to a server. So the agent must REPORT it, and the mint
-- condition becomes `EnforceViewOnly || machine.require_session_policy`, carrying the group's CURRENT
-- level — `view_only` while a mandate stands, `control` once it does not. `control` is exactly what the
-- agent's ratchet accepts to discharge a PROVISIONAL floor, and only a provisional one.
--
-- WHAT THIS COLUMN COSTS, stated plainly because it is the reason loop 86 is not a one-line change.
-- Before it, every `access=control` policy this system minted named an EPHEMERAL attended device id that
-- would never exist again, which is what made a captured policy unreplayable (see the argument at
-- control-plane/http_attended.go). This column makes `control` reachable for a PERMANENT machine, so that
-- containment is spent. It is replaced by SESSION BINDING: the agent now compares the policy's session_id
-- against the live session id it learns from the verified session ticket, so a policy captured in one
-- session is rejected — terminally — in any other. Do not enable one without the other.
--
-- REPORTED ON EVERY REGISTER, not only at enrollment. Enrollment happens once, from the config that was
-- already on disk, so an enroll-only report would miss precisely the population this fixes: agents already
-- in the field whose operator sets the flag afterwards. The steady-state channel is the same one
-- machine.os uses (migrations/0017) — register_agent -> signaling presence -> the control plane — so the
-- bit self-heals on the next reconnect.
--
-- NOT NULL DEFAULT false is the correct historical value AND the correct safety default: an agent that has
-- never reported is one that never asked to floor, so it behaves exactly as it did before this column
-- existed. No backfill. `machine` already carries tenant_id and its RLS policy (0001_core.sql), so this
-- inherits tenant isolation with no new policy, and 0001's table-level grant to rmt_app covers new columns.
-- The column IS part of PgMachineStore's SELECT projections (both of them — selectMachine and the separate
-- inline ListMachines SELECT), so this migration is applied WITH the core in the test harness, like
-- 0017/0018/0031/0032/0033, and never opt-in per test.

ALTER TABLE machine
    ADD COLUMN require_session_policy boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN machine.require_session_policy IS
    'True when this agent reported (at enrollment, and again on every register) that its local '
    'require_session_policy config flag is set, meaning it opens every session VIEW-ONLY until a signed '
    'access policy verifies. Read at POST /sessions: a machine flagged here is ALWAYS minted a policy, '
    'carrying the group''s current access level, so an agent in a non-enforcing group is discharged '
    'instead of stranded view-only forever. Agent-reported, so it is advisory about the AGENT''s state '
    'and never a grant of authority: it can only cause a policy to be minted, never suppress one.';

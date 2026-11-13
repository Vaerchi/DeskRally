-- 0039_machine_agent_version.sql — give the fleet a VERSION IDENTITY. Step 1 of docs/21 §8, and the
-- prerequisite for every later step of agent auto-update.
--
-- THE PROBLEM THIS SOLVES IS THAT THE QUESTION HAD NO ANSWER. Before this, the agent had no version
-- constant anywhere (no CARGO_PKG_VERSION use in crates/agent-windows or crates/agent-core, verified
-- by grep, not assumed) and `machine` carried device id, group, name, os and status but nothing about
-- the BUILD. So "what is actually deployed out there" was literally unanswerable — and a rollout that
-- cannot be observed cannot be staged, canaried, soaked or rolled back. docs/21 §8 puts this first for
-- exactly that reason: it is useful on its own, and nothing after it is safe without it.
--
-- WHERE THE VALUE COMES FROM. rmt_agent_core::version::AGENT_VERSION, shaped `<semver>+<short git sha>`
-- (e.g. `0.0.1+0594362`), stamped at build time by crates/agent-core/build.rs. It rides the SAME channel
-- machine.os uses (migrations/0017) and machine.require_session_policy uses (migrations/0037):
-- register_agent -> the signaling presence feed -> annotatePresence. Reported on EVERY register, not
-- only at enrollment, so an agent already in the field self-heals on its next reconnect rather than
-- reporting whatever it was built as years ago.
--
-- DELIBERATELY NOT the device-identity call, which is what docs/21 §2 proposed. That route is
-- `GET /internal/devices/{device_id}/identity`: it has NO request body, its data flows control-plane ->
-- signaling rather than the other way, it is cached 60s so a version change would be swallowed, it fires
-- ONLY in enforced mode (every Playwright e2e runs dev mode and would never exercise it), and its own doc
-- comment declares it a deliberately unaudited read on a hot path. The presence feed already has tenant
-- pinning, batching and cross-tenant safety, and already carries two fields of exactly this kind.
--
-- AGENT-ASSERTED, THEREFORE NEVER AUTHORIZATION. The value arrives from the peer BEFORE proof of
-- possession, so it is attacker-controlled on the unauthenticated edge. It is bounded at receipt in
-- signaling (boundAgentVersion, 64 bytes) and bounded again in the store, because the store holds its own
-- invariants. It is inventory for a human to read. Nothing may branch on it to decide what an agent is
-- allowed to do.
--
-- WHAT `agent_version_seen_at` MEANS, because the name invites the wrong reading: it is when the CURRENT
-- value was FIRST OBSERVED, not a heartbeat. The refresh is `IS DISTINCT FROM`, so the steady state
-- writes ZERO rows — which is what stops every console poll from rewriting every row in the fleet — and
-- the stamp therefore only moves when the version actually changes. That is the rollout question
-- ("did the new build land on this machine, and when"). LIVENESS is `machine.last_seen`, which
-- TouchLastSeen already maintains; this column is not a second copy of it.
--
-- '' NOT NULL is the correct historical value AND the correct safety default: a machine that has never
-- reported is one whose version is UNKNOWN, and empty reads as unknown everywhere. No backfill is
-- possible — nothing in the field has ever reported a version. Critically, the refresh must never let an
-- older agent's SILENCE blank a version already recorded, so the update path skips empty values rather
-- than writing them.
--
-- `machine` already carries tenant_id and its RLS policy (0001_core.sql `tenant_isolation`), so these
-- columns inherit tenant isolation with no new policy, and 0005's table-level grant to rmt_app covers new
-- columns with no new GRANT. Both columns ARE part of PgMachineStore's SELECT projections — BOTH of them,
-- selectMachine and the separate inline ListMachines SELECT — so this migration is applied WITH the core
-- in the test harness, like 0017/0018/0031/0032/0033/0037, and never opt-in per test.

ALTER TABLE machine
    ADD COLUMN agent_version text NOT NULL DEFAULT '',
    ADD COLUMN agent_version_seen_at timestamptz;

COMMENT ON COLUMN machine.agent_version IS
    'The agent''s self-reported build identity, shaped "<semver>+<short git sha>" (rmt_agent_core '
    'version::AGENT_VERSION). Reported on every register_agent and carried to here by the signaling '
    'presence feed, so it self-heals after an upgrade rather than being write-once at enrollment. '
    'Empty means this machine has never reported one (a pre-0039 agent, or one that has not reconnected). '
    'AGENT-ASSERTED AND ADVISORY: it arrives before proof of possession, is bounded at receipt and again '
    'in the store, and is display/inventory only — nothing may branch on it to grant authority.';

COMMENT ON COLUMN machine.agent_version_seen_at IS
    'When the CURRENT value of agent_version was FIRST observed on this machine — not a heartbeat. The '
    'refresh writes only when the reported version differs (IS DISTINCT FROM), so the steady state writes '
    'no rows and this stamp moves only on an actual version change; that is what answers "did the rollout '
    'land on this machine, and when". For liveness use machine.last_seen instead. NULL means no version '
    'has ever been reported.';

package controlplane

// The Postgres-only properties of session transfer (migrations/0060): the per-state CHECKs, the live-offer
// unique index, the tenant-qualified composite foreign keys, RLS, rollback of a failed finalize, and the
// lock order under concurrent load. The behavioural scenarios run on both backends in
// session_transfer_test.go.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgCode is the SQLSTATE of err ("" when it is not a Postgres error).
func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// suExec runs sql as the superuser (constraints are tested as the table owner; RLS as rmt_app).
func suExec(t *testing.T, h *transferHarness, sql string, args ...any) error {
	t.Helper()
	_, err := h.su.Exec(context.Background(), sql, args...)
	return err
}

func TestPgSessionTransferMigrationIsIdempotent(t *testing.T) {
	h := newPgTransferHarness(t)
	applyMigrationFile(t, h.su, "migrations/0060_session_transfer.sql")
	// Re-applied on a populated schema with live rows: nothing is lost.
	s1 := h.startVouched(h.alice)
	id := h.mustOffer(h.alice, s1, h.bob)
	applyMigrationFile(t, h.su, "migrations/0060_session_transfer.sql")
	if got := h.transfer(id).State; got != TransferPending {
		t.Fatalf("offer after re-applying the migration = %s", got)
	}
}

func TestPgSessionTransferStateConstraints(t *testing.T) {
	h := newPgTransferHarness(t)
	s1 := h.startVouched(h.alice)
	s2 := h.start(h.carol) // a real second session to use as new_session_id
	ins := func(state, cols, vals string) error {
		return suExec(t, h, `INSERT INTO session_transfer (tenant_id, session_id, machine_id, from_user_id, state, expires_at`+cols+`)
			VALUES ($1, $2, $3, $4, $5, now() + interval '5 minutes'`+vals+`)`, h.tenant, s1, h.machine, h.alice, state)
	}
	del := func() { _ = suExec(t, h, `DELETE FROM session_transfer`) }
	bob, s2id := "'"+h.bob+"'", "'"+s2+"'"
	cases := []struct {
		name, state, cols, vals string
		wantOK                  bool
	}{
		{"pending alone", "pending", "", "", true},
		{"pending with accepted_by", "pending", ", accepted_by", ", " + bob, false},
		{"pending with new_session_id", "pending", ", new_session_id", ", " + s2id, false},
		{"pending with failure_reason", "pending", ", failure_reason", ", 'x'", false},
		{"releasing complete", "releasing", ", accepted_by, releasing_at", ", " + bob + ", now()", true},
		{"releasing without releasing_at", "releasing", ", accepted_by", ", " + bob, false},
		{"releasing without accepted_by", "releasing", ", releasing_at", ", now()", false},
		{"releasing with new_session_id", "releasing", ", accepted_by, releasing_at, new_session_id", ", " + bob + ", now(), " + s2id, false},
		{"accepted complete", "accepted", ", accepted_by, new_session_id", ", " + bob + ", " + s2id, true},
		{"accepted without new_session_id", "accepted", ", accepted_by", ", " + bob, false},
		{"accepted without accepted_by", "accepted", ", new_session_id", ", " + s2id, false},
		{"failed with a reason", "failed", ", failure_reason", ", 'timed out'", true},
		{"failed without a reason", "failed", "", "", false},
		{"cancelled", "cancelled", "", "", true},
		{"cancelled with new_session_id", "cancelled", ", new_session_id", ", " + s2id, false},
		{"expired with new_session_id", "expired", ", new_session_id", ", " + s2id, false},
		{"superseded with new_session_id", "superseded", ", new_session_id", ", " + s2id, false},
		{"unknown state", "bogus", "", "", false},
	}
	for _, c := range cases {
		del()
		err := ins(c.state, c.cols, c.vals)
		if c.wantOK && err != nil {
			t.Errorf("%s: rejected: %v", c.name, err)
		}
		if !c.wantOK && pgCode(err) != "23514" {
			t.Errorf("%s: err = %v, want a CHECK violation (23514)", c.name, err)
		}
	}
	del()
	if err := suExec(t, h, `INSERT INTO session_transfer (tenant_id, session_id, machine_id, from_user_id, state, expires_at, note)
		VALUES ($1, $2, $3, $4, 'pending', now(), repeat('x', 501))`, h.tenant, s1, h.machine, h.alice); pgCode(err) != "23514" {
		t.Errorf("a 501-character note: %v, want 23514", err)
	}
}

func TestPgSessionTransferOneLiveOfferPerSession(t *testing.T) {
	h := newPgTransferHarness(t)
	s1 := h.startVouched(h.alice)
	ins := func(state, extraCols, extraVals string) error {
		return suExec(t, h, `INSERT INTO session_transfer (tenant_id, session_id, machine_id, from_user_id, state, expires_at`+extraCols+`)
			VALUES ($1, $2, $3, $4, $5, now() + interval '5 minutes'`+extraVals+`)`, h.tenant, s1, h.machine, h.alice, state)
	}
	if err := ins("pending", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := ins("pending", "", ""); pgCode(err) != "23505" {
		t.Fatalf("a second pending offer for one session: %v, want 23505", err)
	}
	// Terminal rows are not "live": any number may sit beside a live one.
	for _, st := range []string{"cancelled", "expired", "superseded"} {
		if err := ins(st, "", ""); err != nil {
			t.Fatalf("a %s row beside a live one: %v", st, err)
		}
	}
	// A releasing offer counts as live too: pending -> releasing frees nothing.
	if err := suExec(t, h, `DELETE FROM session_transfer`); err != nil {
		t.Fatal(err)
	}
	if err := ins("releasing", ", accepted_by, releasing_at", ", '"+h.bob+"', now()"); err != nil {
		t.Fatal(err)
	}
	if err := ins("pending", "", ""); pgCode(err) != "23505" {
		t.Fatalf("a pending offer beside a releasing one: %v, want 23505", err)
	}
}

func TestPgSessionTransferForeignKeysAreTenantQualified(t *testing.T) {
	h := newPgTransferHarness(t)
	ctx := context.Background()
	s1 := h.startVouched(h.alice)
	// A machine, group, session and user that exist ONLY in the other tenant.
	alienGroup, alienMachine := seedGroupMachine(t, h.su, h.alienTenant, "alien-dev")
	var alienSession string
	if err := h.su.QueryRow(ctx, `INSERT INTO session_record (tenant_id, machine_id, technician_id) VALUES ($1, $2, $3) RETURNING id::text`,
		h.alienTenant, alienMachine, h.erin).Scan(&alienSession); err != nil {
		t.Fatal(err)
	}
	const base = `INSERT INTO session_transfer (tenant_id, session_id, machine_id, group_id, from_user_id, to_user_id, state, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', now() + interval '5 minutes')`
	cases := []struct {
		name                                   string
		session, machine, group, from, to, ten string
	}{
		{"another tenant's session", alienSession, h.machine, h.group, h.alice, h.bob, h.tenant},
		{"another tenant's machine", s1, alienMachine, h.group, h.alice, h.bob, h.tenant},
		{"another tenant's group", s1, h.machine, alienGroup, h.alice, h.bob, h.tenant},
		{"another tenant's sender", s1, h.machine, h.group, h.erin, h.bob, h.tenant},
		{"another tenant's recipient", s1, h.machine, h.group, h.alice, h.erin, h.tenant},
	}
	for _, c := range cases {
		err := suExec(t, h, base, c.ten, c.session, c.machine, c.group, c.from, c.to)
		if pgCode(err) != "23503" {
			t.Errorf("%s: err = %v, want a foreign-key violation (23503)", c.name, err)
		}
	}
	// The same-tenant control row is accepted, so the failures above are the FK and nothing else.
	if err := suExec(t, h, base, h.tenant, s1, h.machine, h.group, h.alice, h.bob); err != nil {
		t.Fatalf("control insert: %v", err)
	}
	// accepted_by and new_session_id are tenant-qualified too.
	if err := suExec(t, h, `UPDATE session_transfer SET state = 'releasing', accepted_by = $1, releasing_at = now()`, h.erin); pgCode(err) != "23503" {
		t.Errorf("another tenant's acceptor: %v, want 23503", err)
	}
	if err := suExec(t, h, `UPDATE session_transfer SET state = 'accepted', accepted_by = $1, new_session_id = $2`, h.bob, alienSession); pgCode(err) != "23503" {
		t.Errorf("another tenant's new_session_id: %v, want 23503", err)
	}
	// session_record.transferred_from cannot point across tenants either.
	if err := suExec(t, h, `INSERT INTO session_record (tenant_id, machine_id, technician_id, transferred_from) VALUES ($1, $2, $3, $4)`,
		h.tenant, h.machine, h.alice, alienSession); pgCode(err) != "23503" {
		t.Errorf("transferred_from across tenants: %v, want 23503", err)
	}
	if err := suExec(t, h, `INSERT INTO session_record (tenant_id, machine_id, technician_id, transferred_from) VALUES ($1, $2, $3, $4)`,
		h.tenant, h.machine, h.bob, s1); err != nil {
		t.Errorf("transferred_from within a tenant: %v", err)
	}
}

func TestPgSessionTransferRowLevelSecurity(t *testing.T) {
	h := newPgTransferHarness(t)
	s1 := h.startVouched(h.alice)
	h.mustOffer(h.alice, s1, h.bob)
	count := func(tenant string) (n int) {
		t.Helper()
		if err := withTenant(context.Background(), h.app, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT count(*) FROM session_transfer`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(h.tenant) != 1 || count(h.alienTenant) != 0 {
		t.Fatalf("rows visible: own tenant %d (want 1), other tenant %d (want 0)", count(h.tenant), count(h.alienTenant))
	}
	// WITH CHECK: pinned to the other tenant, writing a row for this tenant is refused.
	err := withTenant(context.Background(), h.app, h.alienTenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO session_transfer (tenant_id, session_id, machine_id, from_user_id, state, expires_at)
			VALUES ($1, $2, $3, $4, 'cancelled', now())`, h.tenant, s1, h.machine, h.alice)
		return err
	})
	if pgCode(err) != "42501" {
		t.Fatalf("cross-tenant insert as rmt_app: %v, want an RLS violation (42501)", err)
	}
	// And an UPDATE pinned to the other tenant touches nothing.
	var touched int64
	if err := withTenant(context.Background(), h.app, h.alienTenant, func(tx pgx.Tx) error {
		ct, err := tx.Exec(context.Background(), `UPDATE session_transfer SET state = 'cancelled'`)
		touched = ct.RowsAffected()
		return err
	}); err != nil || touched != 0 {
		t.Fatalf("cross-tenant update touched %d rows (err %v)", touched, err)
	}
}

func TestPgAgentEndedAtFirstReportWinsAndIsTenantScoped(t *testing.T) {
	h := newPgTransferHarness(t)
	ctx := context.Background()
	s1 := h.startVouched(h.alice)
	t1 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, t1, nil); err != nil {
		t.Fatal(err)
	}
	// The stamp is DATABASE time (compared against releasing_at), not the caller's value; first wins.
	first := h.session(s1).AgentEndedAt
	if first == nil {
		t.Fatal("the first report did not stamp agent_ended_at")
	}
	time.Sleep(5 * time.Millisecond) // a second stamp, if one were written, would differ
	if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, t1.Add(time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if got := h.session(s1).AgentEndedAt; got == nil || !got.Equal(*first) {
		t.Fatalf("agent_ended_at = %v after a duplicate report, want the FIRST report's %v", got, *first)
	}
	// Another tenant's report cannot stamp this tenant's session; an unknown or malformed id is a no-op.
	s2 := h.start(h.carol)
	if err := h.transfers.RecordAgentEnded(ctx, h.alienTenant, s2, t1, nil); err != nil {
		t.Fatal(err)
	}
	if got := h.session(s2).AgentEndedAt; got != nil {
		t.Fatalf("a report from another tenant stamped agent_ended_at = %v", got)
	}
	for _, id := range []string{newUUID(), "not-a-uuid"} {
		if err := h.transfers.RecordAgentEnded(ctx, h.tenant, id, t1, nil); err != nil {
			t.Fatalf("report for %q: %v", id, err)
		}
	}
}

func TestPgFailedFinalizeRollsBackUntouched(t *testing.T) {
	h := newPgTransferHarness(t)
	ctx := context.Background()
	s1 := h.startVouched(h.alice)
	id := h.mustOffer(h.alice, s1, h.bob)
	h.mustAccept(h.bob, id)
	boom := errors.New("user store unavailable")
	err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, time.Now().UTC(),
		func(context.Context, *SessionTransfer) (*TransferAdmission, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the admitter's infrastructure error", err)
	}
	// The finalize work rolled back (still releasing, S1 open, no end_reason), but the agent's report IS
	// recorded: its first timestamp must survive a transient failure (Codex impl round 2), or an on-time
	// report would be judged late when the retry comes after the deadline.
	if tr := h.transfer(id); tr.State != TransferReleasing {
		t.Fatalf("offer = %+v", tr)
	}
	if rec := h.session(s1); rec.EndedAt != nil || rec.EndReason != "" {
		t.Fatalf("S1 changed by a rolled-back finalize: %+v", rec)
	}
	if rec := h.session(s1); rec.AgentEndedAt == nil {
		t.Fatal("the transient finalize failure erased the agent's first report")
	}
	// The retry completes it.
	if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, time.Now().UTC(), h.srv(h.bob).transferAdmitter(h.tenant)); err != nil {
		t.Fatal(err)
	}
	if tr := h.transfer(id); tr.State != TransferAccepted {
		t.Fatalf("after the retry: %+v", tr)
	}
}

func TestTransferExpireStale(t *testing.T) {
	forEachBackend(t, func(t *testing.T, h *transferHarness) {
		ctx := context.Background()
		pendingS := h.startVouched(h.alice)
		pending := h.mustOffer(h.alice, pendingS, h.bob)
		relS := h.startVouched(h.carol)
		releasing := h.mustOffer(h.carol, relS, h.bob)
		h.mustAccept(h.bob, releasing)
		freshS := h.startVouched(h.alice)
		fresh := h.mustOffer(h.alice, freshS, h.bob)

		h.advance(61 * time.Second)
		if n, err := h.transfers.ExpireStale(ctx, h.tenant); err != nil || n != 1 {
			t.Fatalf("after 61 s: swept %d (err %v), want 1 (the releasing offer fails; pending ones live 5 minutes)", n, err)
		}
		if h.transfer(releasing).State != TransferFailed || h.transfer(pending).State != TransferPending || h.transfer(fresh).State != TransferPending {
			t.Fatalf("states: releasing=%s pending=%s fresh=%s", h.transfer(releasing).State, h.transfer(pending).State, h.transfer(fresh).State)
		}
		h.advance(5 * time.Minute)
		if n, err := h.transfers.ExpireStale(ctx, h.tenant); err != nil || n != 2 {
			t.Fatalf("after 5 more minutes: swept %d (err %v), want 2", n, err)
		}
		for _, id := range []string{pending, fresh} {
			if h.transfer(id).State != TransferExpired {
				t.Fatalf("offer %s = %s, want expired", id, h.transfer(id).State)
			}
		}
		if n, _ := h.transfers.ExpireStale(ctx, h.tenant); n != 0 {
			t.Fatalf("a second sweep changed %d rows; terminal states are terminal", n)
		}
		if got := h.auditCount("session.transfer_expired"); got != 2 {
			t.Fatalf("expired audit rows = %d, want 2", got)
		}
		// A releasing offer whose agent already reported is NOT failed by the sweep: it is waiting for finalize.
		s := h.startVouched(h.alice)
		id := h.mustOffer(h.alice, s, h.bob)
		h.mustAccept(h.bob, id)
		if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s, time.Now().UTC(), nil); err != nil {
			t.Fatal(err)
		}
		h.advance(2 * time.Minute)
		if _, err := h.transfers.ExpireStale(ctx, h.tenant); err != nil {
			t.Fatal(err)
		}
		if got := h.transfer(id).State; got != TransferReleasing {
			t.Fatalf("a releasing offer with the agent's report recorded became %s by the sweep", got)
		}
		if _, out := h.get(h.bob, id); str(transferOf(out), "state") != "accepted" {
			t.Fatalf("the acceptor's poll must finalize it: %v", out)
		}
	})
}

// TestPgTransferLockOrderUnderLoad hammers the five writers that share the admission lock, the offer row
// and S1's row (offer, accept, cancel, the agent's end report, an ordinary start) concurrently. A lock-order
// inversion shows as a Postgres deadlock (40P01), which the handlers map to a 5xx, so any 5xx fails the test.
func TestPgTransferLockOrderUnderLoad(t *testing.T) {
	h := newPgTransferHarness(t)
	const rounds = 8
	var bad sync.Map
	record := func(what string, code int) {
		if code >= 500 {
			bad.Store(what, code)
		}
	}
	for round := 0; round < rounds; round++ {
		s1 := h.startVouched(h.alice)
		first := h.mustOffer(h.alice, s1, "")
		var wg sync.WaitGroup
		start := make(chan struct{})
		run := func(name string, f func() int) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				record(name, f())
			}()
		}
		run("offer", func() int { c, _ := h.offer(h.alice, s1, "", ""); return c })
		run("offer2", func() int { c, _ := h.offer(h.alice, s1, h.carol, ""); return c })
		run("accept-bob", func() int { c, _ := h.accept(h.bob, first); return c })
		run("accept-carol", func() int { c, _ := h.accept(h.carol, first); return c })
		run("cancel", func() int { c, _ := h.do(h.alice, "DELETE", "/session-transfers/"+first, ""); return c })
		run("end-report", func() int { return h.agentEnd(s1) })
		run("poll-bob", func() int { c, _ := h.get(h.bob, first); return c })
		run("start", func() int {
			c, _ := h.do(h.frank, "POST", "/sessions", `{"machine_id":"`+transferTestDevice+`"}`)
			return c
		})
		run("renew", func() int { c, _ := h.do(h.alice, "POST", "/sessions/"+s1+"/policy", ""); return c })
		close(start)
		wg.Wait()
		// Settle: deliver the end report, then poll every live offer to a terminal or accepted state.
		h.agentEnd(s1)
		rows, err := h.su.Query(context.Background(), `SELECT id::text, accepted_by::text FROM session_transfer WHERE state = 'releasing'`)
		if err != nil {
			t.Fatal(err)
		}
		type rel struct{ id, by string }
		var rels []rel
		for rows.Next() {
			var r rel
			var by *string
			if err := rows.Scan(&r.id, &by); err != nil {
				t.Fatal(err)
			}
			if by != nil {
				r.by = *by
			}
			rels = append(rels, r)
		}
		rows.Close()
		for _, r := range rels {
			if r.by == h.bob || r.by == h.carol {
				record("settle-poll", func() int { c, _ := h.get(r.by, r.id); return c }())
			}
		}
	}
	bad.Range(func(k, v any) bool {
		t.Errorf("%v answered %v: a 5xx under concurrent load (deadlock, lock timeout or an unhandled error)", k, v)
		return true
	})
	// Invariants, read straight from the tables.
	check := func(what, sql string) {
		var n int
		if err := h.su.QueryRow(context.Background(), sql).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s: %d violating rows", what, n)
		}
	}
	check("two live offers for one session", `SELECT count(*) FROM (SELECT 1 FROM session_transfer WHERE state IN ('pending','releasing') GROUP BY tenant_id, session_id HAVING count(*) > 1) x`)
	check("an accepted offer whose S2 is missing, mislinked or not the acceptor's", `
		SELECT count(*) FROM session_transfer t LEFT JOIN session_record s2 ON s2.id = t.new_session_id
		WHERE t.state = 'accepted' AND (s2.id IS NULL OR s2.transferred_from <> t.session_id OR s2.technician_id <> t.accepted_by)`)
	check("an S2 without an accepted offer", `
		SELECT count(*) FROM session_record s2 WHERE s2.transferred_from IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM session_transfer t WHERE t.new_session_id = s2.id AND t.state = 'accepted')`)
	check("two S2s for one offer", `SELECT count(*) FROM (SELECT transferred_from FROM session_record WHERE transferred_from IS NOT NULL GROUP BY transferred_from HAVING count(*) > 1) x`)
	check("an accepted offer whose S1 is still open", `
		SELECT count(*) FROM session_transfer t JOIN session_record s1 ON s1.id = t.session_id WHERE t.state = 'accepted' AND s1.ended_at IS NULL`)
	_ = http.StatusOK
}

// The durable "vouched" marker (0061): a redemption stamps session_record.redeemed_at, and WasRedeemed keeps
// answering after the ledger row is reaped. Before this, the ledger alone forgot a session about an hour
// after its ticket expired, so a session older than that could not be transferred, and a transferred
// session's ticket could be re-minted and redeemed again.
func TestPgRedemptionStampsTheSessionDurably(t *testing.T) {
	h := newPgTransferHarness(t)
	ctx := context.Background()
	unredeemed := h.start(h.alice)
	s1 := h.startVouched(h.alice) // redeemed through the real cp_session_ticket_redeem

	var stamped bool
	if err := h.su.QueryRow(ctx, `SELECT redeemed_at IS NOT NULL FROM session_record WHERE id = $1`, s1).Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	if !stamped {
		t.Fatal("redemption did not stamp session_record.redeemed_at (the definer must pin the tenant: FORCE RLS)")
	}
	store := NewPgTicketRedemptionStore(h.su)
	// The reap, as the ledger would do an hour after expiry.
	mustExec(t, h.su, `DELETE FROM session_ticket_redemption WHERE session_id = $1`, s1)
	if ok, err := store.WasRedeemed(ctx, h.tenant, s1); err != nil || !ok {
		t.Fatalf("after the ledger row is gone: WasRedeemed = %v, %v; want true from the durable marker", ok, err)
	}
	if ok, err := store.WasRedeemed(ctx, h.tenant, unredeemed); err != nil || ok {
		t.Fatalf("a never-redeemed session: WasRedeemed = %v, %v; want false", ok, err)
	}
	// Single use is unchanged by the redefinition: a replay of a live ticket is still refused.
	s2 := h.startVouched(h.bob)
	if _, err := store.RedeemTicket(ctx, h.tenant, s2, transferTestDevice, time.Now().Add(2*time.Minute)); err != ErrTicketAlreadyRedeemed {
		t.Fatalf("replay = %v, want ErrTicketAlreadyRedeemed", err)
	}
}

// Codex impl round 2: a TIMELY report whose finalize hits a transient error, retried AFTER the deadline,
// still finalizes on the original (on-time) stamp.
func TestPgTimelyReportSurvivesATransientFinalizeFailure(t *testing.T) {
	h := newPgTransferHarness(t)
	ctx := context.Background()
	s1 := h.startVouched(h.alice)
	id := h.mustOffer(h.alice, s1, h.bob)
	h.mustAccept(h.bob, id)
	h.advance(10 * time.Second)
	boom := errors.New("user store unavailable")
	if err := h.transfers.RecordAgentEnded(ctx, h.tenant, s1, time.Now().UTC(),
		func(context.Context, *SessionTransfer) (*TransferAdmission, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the transient failure", err)
	}
	h.advance(2 * time.Minute) // the retry comes long after the deadline
	if _, out := h.get(h.bob, id); str(transferOf(out), "state") != "accepted" {
		t.Fatalf("an on-time report judged late after a transient failure: %v", out)
	}
}

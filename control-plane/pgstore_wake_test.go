package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type pgWakeFixture struct {
	h             *dirHarness
	store         *PgWakeStore
	target, relay dirMachine
	issue         wakeIssuance
	principal     Principal
}

func newPgWakeFixture(t *testing.T) *pgWakeFixture {
	t.Helper()
	h := newPgDirHarness(t)
	ctx := context.Background()
	store := &PgWakeStore{Pool: h.app, Audit: h.audit.(*PgMgmtAuditStore)}
	target := h.addMachineFn(h.group, MachineStatusActive)
	relay := h.addMachineFn(h.otherGroup, MachineStatusActive)
	lan := h.machines.(LanStore)
	ref := WakeConnRef{Incarnation: newUUID(), Generation: 2}
	if ok, _, err := lan.ActivateSignalingIncarnation(ctx, ref.Incarnation, 0); err != nil || !ok {
		t.Fatalf("activate signaling: %v", err)
	}
	gateway := "02:00:00:00:00:01"
	var epoch int64
	for i, m := range []dirMachine{target, relay} {
		var outcome LanOutcome
		var err error
		epoch, outcome, err = lan.AllocateLanEpoch(ctx, m.Device, m.Pub, ref.Incarnation, ref.Generation)
		if err != nil || outcome != "" {
			t.Fatalf("allocate epoch: %q %v", outcome, err)
		}
		mac := []string{"02:00:00:00:00:ea", "02:00:00:00:00:02"}[i]
		digest := sha256.Sum256([]byte(mac))
		outcome, err = lan.IngestLanReport(ctx, m.Device, m.Pub, ref.Incarnation, ref.Generation, epoch, 1,
			digest[:], []LanEntry{{MAC: mac, IPv4Network: "192.0.2.0/24", GatewayMAC: &gateway}})
		if err != nil || outcome != LanApplied {
			t.Fatalf("ingest: %q %v", outcome, err)
		}
	}
	facts, err := store.wakeFacts(ctx, h.tenant, []string{target.ID, relay.ID})
	if err != nil || len(facts[target.ID]) != 1 || len(facts[relay.ID]) != 1 {
		t.Fatalf("read fixture LAN facts: %v", err)
	}
	load := func(m dirMachine) wakeCandidate {
		t.Helper()
		row, err := h.machines.GetMachineByID(ctx, h.tenant, m.ID)
		if err != nil {
			t.Fatal(err)
		}
		return wakeCandidate{Machine: *row, Facts: facts[m.ID]}
	}
	pub, err := hex.DecodeString(relay.Pub)
	if err != nil {
		t.Fatal(err)
	}
	return &pgWakeFixture{
		h: h, store: store, target: target, relay: relay,
		issue: wakeIssuance{Target: load(target), Relay: load(relay), RequestID: newUUID(),
			Dispatch: WakeContext{ConnRef: ref, Epoch: epoch, DeviceKeySHA256: sha256.Sum256(pub)}},
		principal: Principal{UserID: h.owner, TenantID: h.tenant},
	}
}

func TestPgWakeIssue(t *testing.T) {
	f := newPgWakeFixture(t)
	h := f.h
	ctx := context.Background()
	if facts, err := f.store.wakeFacts(ctx, h.alien, []string{f.target.ID, f.relay.ID}); err != nil || len(facts) != 0 {
		t.Fatalf("cross-tenant facts visible or lookup failed: %v", err)
	}
	// Simulate reports stored before MAC validation tightened. On the real LAN,
	// the zero and multicast target MACs sort before the usable target MAC.
	h.rawSQL(`INSERT INTO machine_lan (tenant_id, machine_id, mac, ipv4_network, gateway_mac, received_at)
		VALUES ($1, $2, '00:00:00:00:00:00', '192.0.2.0/24', '02:00:00:00:00:01', now()),
		       ($1, $2, '01:00:00:00:00:01', '192.0.2.0/24', '02:00:00:00:00:01', now()),
		       ($1, $2, '02:00:00:00:00:03', '192.0.2.0/24', '00:00:00:00:00:00', now()),
		       ($1, $3, '02:00:00:00:00:04', '192.0.2.0/24', '00:00:00:00:00:00', now()),
		       ($1, $3, '01:00:00:00:00:02', '192.0.2.0/24', '02:00:00:00:00:01', now()),
		       ($1, $3, '02:00:00:00:00:05', '192.0.2.0/24', '01:00:00:00:00:01', now())`,
		h.tenant, f.target.ID, f.relay.ID)
	facts, err := f.store.wakeFacts(ctx, h.tenant, []string{f.target.ID, f.relay.ID})
	if err != nil || len(facts[f.target.ID]) != 1 || len(facts[f.relay.ID]) != 1 {
		t.Fatalf("readiness facts should include only valid entries: %v", err)
	}
	applyAPITokenMigration(t, h.su)
	tokens := NewPgAPITokenStore(h.app)
	bearer, token, err := tokens.Mint(ctx, h.tenant, "wake client", []Capability{CapWakeMachine}, h.owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := h.newServer(&APITokenAuthenticator{Tokens: tokens})
	server.WakeOnLAN, server.WakeStore, server.WakeThrottle = true, f.store, fakeWakeThrottle(0)
	presence := onlineAt(time.Now(), f.relay.Device)
	presence.WakeCapableByDevice = map[string]bool{f.relay.Device: true}
	server.Presence = fixedPresence{p: presence}
	var claims WakeClaims
	server.WakeDispatcher = &fakeWakeDispatcher{
		onContext: func(string) (WakeContext, WakeOutcome) { return f.issue.Dispatch, WakeContextReady },
		onForward: func(_ string, artifact []byte) WakeOutcome {
			var order signedWake
			if err := json.Unmarshal(artifact, &order); err != nil {
				t.Fatal("invalid signed wake order")
			}
			claims = order.Claims
			return WakeWritten
		},
	}
	if got, body := h.doOn(server, http.MethodPost, "/machines/"+f.target.ID+"/wake", "", bearer); got != 202 || body["status"] != "requested" {
		t.Fatalf("token wake response = %d %v", got, body)
	}
	if claims.TargetMAC != f.issue.Target.Facts[0].MAC ||
		claims.IPv4Network != f.issue.Target.Facts[0].Network ||
		claims.GatewayMAC != f.issue.Target.Facts[0].Gateway {
		t.Fatal("wake did not use the target's asserted destination on a matching segment")
	}
	var actor, target, request, relay, tokenID string
	var fields int
	err = h.su.QueryRow(ctx, `
		SELECT actor_user_id::text, target_id::text, metadata->>'request_id', metadata->>'relay_machine_id',
		       metadata->>'api_token_id', (SELECT count(*) FROM jsonb_object_keys(metadata))
		FROM audit_event WHERE action = 'machine.wake_requested'`).
		Scan(&actor, &target, &request, &relay, &tokenID, &fields)
	if err != nil || actor != h.owner || target != f.target.ID || request != claims.RequestID ||
		relay != f.relay.ID || tokenID != token.ID || fields != 3 {
		t.Fatalf("unexpected audit metadata or actor: %v", err)
	}
}

func TestPgWakeChangesBeforeIssuance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*pgWakeFixture)
	}{
		{"target LAN replaced", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE machine_lan SET mac = '02:00:00:00:00:ff' WHERE machine_id = $1`, f.target.ID)
		}},
		{"relay LAN replaced", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE machine_lan SET gateway_mac = NULL WHERE machine_id = $1`, f.relay.ID)
		}},
		{"relay key changed", func(f *pgWakeFixture) {
			_, pub := newDirKey(f.h.t)
			f.h.setPubkey(f.relay.ID, pub)
		}},
		{"relay epoch changed", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE machine_lan_state SET epoch = epoch + 1 WHERE machine_id = $1`, f.relay.ID)
		}},
		{"relay generation changed", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE machine_lan_state SET epoch_generation = epoch_generation + 1 WHERE machine_id = $1`, f.relay.ID)
		}},
		{"signaling incarnation changed", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE signaling_incarnation SET id = gen_random_uuid()`)
		}},
		{"machine regrouped", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE machine SET group_id = $2 WHERE id = $1`, f.relay.ID, f.h.group)
		}},
		{"machine quarantined", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE machine SET status = 'quarantined' WHERE id = $1`, f.target.ID)
		}},
		{"capability revoked", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE membership SET role_id = (SELECT id FROM role WHERE key = 'readonly' AND tenant_id IS NULL)
				WHERE user_id = $1`, f.h.owner)
		}},
		{"membership scope changed", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE membership SET scoped_group_ids = ARRAY[$2::uuid] WHERE user_id = $1`,
				f.h.owner, f.h.group)
		}},
		{"account disabled", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE app_user SET disabled_at = clock_timestamp() WHERE id = $1`, f.h.owner)
		}},
		{"group reparented", func(f *pgWakeFixture) {
			f.h.rawSQL(`UPDATE machine_group SET parent_id = $2 WHERE id = $1`, f.h.otherGroup, f.h.group)
			f.h.rawSQL(`UPDATE membership SET scoped_group_ids = ARRAY[$2::uuid] WHERE user_id = $1`, f.h.owner, f.h.group)
			f.h.rawSQL(`UPDATE machine_group SET parent_id = NULL WHERE id = $1`, f.h.otherGroup)
		}},
		{"API token revoked", func(f *pgWakeFixture) {
			token := f.asToken(nil)
			if err := NewPgAPITokenStore(f.h.app).Revoke(context.Background(), f.h.tenant, token); err != nil {
				f.h.t.Fatal(err)
			}
		}},
		{"tenant suspended", func(f *pgWakeFixture) {
			f.h.setSuspended(true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPgWakeFixture(t)
			tc.change(f)
			if _, err := f.store.issueWake(context.Background(), &f.principal, f.issue); !errors.Is(err, errWakeChanged) {
				t.Fatalf("issuance = %v, want changed", err)
			}
			f.checkAuditCount(0)
		})
	}
}

func (f *pgWakeFixture) asToken(expiresAt *time.Time) string {
	f.h.t.Helper()
	applyAPITokenMigration(f.h.t, f.h.su)
	_, token, err := NewPgAPITokenStore(f.h.app).Mint(context.Background(), f.h.tenant, "wake client",
		[]Capability{CapWakeMachine}, f.h.owner, expiresAt)
	if err != nil {
		f.h.t.Fatal(err)
	}
	f.principal.APIToken = true
	f.principal.UserID = token.ID
	return token.ID
}

func (f *pgWakeFixture) checkAuditCount(want int) {
	f.h.t.Helper()
	var count int
	if err := f.h.su.QueryRow(context.Background(), `SELECT count(*) FROM audit_event WHERE action = 'machine.wake_requested'`).
		Scan(&count); err != nil || count != want {
		f.h.t.Fatalf("wake audit count = %d, %v; want %d", count, err, want)
	}
}

func TestPgWakeAuditFailureDoesNotForward(t *testing.T) {
	f := newPgWakeFixture(t)
	h := f.h
	s := h.srv(h.owner)
	s.WakeOnLAN, s.WakeStore, s.WakeThrottle = true, f.store, fakeWakeThrottle(0)
	s.Presence = fixedPresence{p: &Presence{
		Online:              map[string]time.Time{f.relay.Device: time.Now()},
		WakeCapableByDevice: map[string]bool{f.relay.Device: true},
	}}
	dispatch := &fakeWakeDispatcher{onContext: func(string) (WakeContext, WakeOutcome) {
		return f.issue.Dispatch, WakeContextReady
	}}
	s.WakeDispatcher = dispatch
	f.store.Audit = nil
	if got, body := h.doOn(s, http.MethodPost, "/machines/"+f.target.ID+"/wake", "", ""); got != 503 || body["error"] != "audit_unavailable" {
		t.Fatalf("missing audit response = %d %v", got, body)
	}
	f.store.Audit = h.audit.(*PgMgmtAuditStore)
	h.failAuditAction("machine.wake_requested")
	if got, _ := h.doOn(s, http.MethodPost, "/machines/"+f.target.ID+"/wake", "", ""); got != 500 {
		t.Fatalf("audit failure response = %d", got)
	}
	if len(dispatch.contexts) != 2 || len(dispatch.forwards) != 0 {
		t.Fatal("unexpected dispatch calls")
	}
	f.checkAuditCount(0)
}

func TestPgWakeThrottle(t *testing.T) {
	h := newPgDirHarness(t)
	applyThrottleMigration(t, h.su)
	store := NewPgThrottleStore(h.app)
	ctx := context.Background()
	check := func(tenant, id string, allowed bool) {
		t.Helper()
		wait, err := store.ReserveWake(ctx, tenant, id)
		if err != nil || (wait == 0) != allowed {
			t.Fatalf("wake throttle wait = %s, %v; allowed = %t", wait, err, allowed)
		}
	}
	first := newUUID()
	check(h.tenant, first, true)
	check(h.tenant, first, false)
	for range 29 {
		check(h.tenant, newUUID(), true)
	}
	check(h.tenant, newUUID(), false)
	check(h.alien, first, true)
}

func holdWakeAuditChain(t *testing.T, f *pgWakeFixture) (pgx.Tx, uint32) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.h.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('mgmt_audit_chain:' || $1, 0))`,
		f.h.tenant); err != nil {
		t.Fatal(err)
	}
	return tx, tx.Conn().PgConn().PID()
}

func waitForWakeBlock(t *testing.T, f *pgWakeFixture, blocker uint32) uint32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var pid int32
		err := f.h.su.QueryRow(ctx, `
			SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)) LIMIT 1`, int32(blocker)).Scan(&pid)
		if err == nil {
			return uint32(pid)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("transaction did not wait for the expected lock")
	return 0
}

func TestPgWakeMutationsWaitForIssuance(t *testing.T) {
	for _, kind := range []string{"grant", "membership", "disable", "reparent", "token", "suspend"} {
		t.Run(kind, func(t *testing.T) {
			f := newPgWakeFixture(t)
			h := f.h
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			var token string
			if kind == "token" {
				token = f.asToken(nil)
			}
			if kind == "reparent" {
				h.rawSQL(`UPDATE machine_group SET parent_id = $2 WHERE id = $1`, h.otherGroup, h.group)
				h.rawSQL(`UPDATE membership SET scoped_group_ids = ARRAY[$2::uuid] WHERE user_id = $1`, h.owner, h.group)
			}
			gate, gatePID := holdWakeAuditChain(t, f)
			issued := make(chan error, 1)
			go func() {
				_, err := f.store.issueWake(ctx, &f.principal, f.issue)
				issued <- err
			}()
			wakePID := waitForWakeBlock(t, f, gatePID)
			mutated := make(chan error, 1)
			go func() {
				mutated <- func() error {
					tx, err := h.su.Begin(ctx)
					if err != nil {
						return err
					}
					defer tx.Rollback(ctx)
					switch kind {
					case "grant":
						_, err = tx.Exec(ctx, `UPDATE membership SET role_id = (SELECT id FROM role WHERE key = 'readonly' AND tenant_id IS NULL)
							WHERE user_id = $1`, h.owner)
					case "membership":
						_, err = tx.Exec(ctx, `UPDATE membership SET scoped_group_ids = ARRAY[$2::uuid] WHERE user_id = $1`, h.owner, h.group)
					case "disable":
						_, err = tx.Exec(ctx, `SELECT m.id FROM membership m JOIN role r ON r.id = m.role_id
							WHERE m.tenant_id = $1 AND r.key = 'owner' AND r.tenant_id IS NULL ORDER BY m.id FOR UPDATE OF m`, h.tenant)
						if err == nil {
							_, err = tx.Exec(ctx, `UPDATE app_user SET disabled_at = clock_timestamp() WHERE id = $1`, h.owner)
						}
					case "reparent":
						_, err = tx.Exec(ctx, `UPDATE machine_group SET parent_id = NULL WHERE id = $1`, h.otherGroup)
					case "token":
						_, err = tx.Exec(ctx, `UPDATE api_token SET revoked_at = clock_timestamp() WHERE id = $1`, token)
					case "suspend":
						err = lockTenantIssuanceExclusive(ctx, tx, h.tenant)
						if err == nil {
							_, err = tx.Exec(ctx, `UPDATE tenant SET disabled_at = clock_timestamp() WHERE id = $1`, h.tenant)
						}
					}
					if err != nil {
						return err
					}
					return tx.Commit(ctx)
				}()
			}()
			waitForWakeBlock(t, f, wakePID)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-issued; err != nil {
				t.Fatalf("issuance failed while mutation waited: %v", err)
			}
			if err := <-mutated; err != nil {
				t.Fatalf("mutation failed after issuance: %v", err)
			}
			f.checkAuditCount(1)
			if _, err := f.store.issueWake(ctx, &f.principal, f.issue); !errors.Is(err, errWakeChanged) {
				t.Fatalf("issuance after mutation = %v, want changed", err)
			}
			f.checkAuditCount(1)
		})
	}
}

func TestPgWakeMachineAndCoverageChanges(t *testing.T) {
	scopeTo := func(f *pgWakeFixture, group string) {
		f.h.rawSQL(`UPDATE membership SET scoped_group_ids = ARRAY[$2::uuid] WHERE user_id = $1`, f.h.owner, group)
	}
	for _, tc := range []struct {
		name    string
		prepare func(*pgWakeFixture) (string, []any)
	}{
		{"target regrouped outside scope", func(f *pgWakeFixture) (string, []any) {
			h := f.h
			uncovered := newUUID()
			h.rawSQL(`INSERT INTO machine_group (id, tenant_id, name) VALUES ($1, $2, 'Uncovered')`, uncovered, h.tenant)
			h.rawSQL(`UPDATE machine_group SET parent_id = $2 WHERE id = $1`, h.otherGroup, h.group)
			scopeTo(f, h.group)
			return `UPDATE machine SET group_id = $2 WHERE id = $1`, []any{f.target.ID, uncovered}
		}},
		{"relay quarantined", func(f *pgWakeFixture) (string, []any) {
			return `UPDATE machine SET status = 'quarantined' WHERE id = $1`, []any{f.relay.ID}
		}},
		{"target retired", func(f *pgWakeFixture) (string, []any) {
			return `UPDATE machine SET status = 'retired' WHERE id = $1`, []any{f.target.ID}
		}},
		{"relay retired", func(f *pgWakeFixture) (string, []any) {
			return `UPDATE machine SET status = 'retired' WHERE id = $1`, []any{f.relay.ID}
		}},
		{"reparent removes target coverage", func(f *pgWakeFixture) (string, []any) {
			h := f.h
			h.rawSQL(`UPDATE machine_group SET parent_id = $2 WHERE id = $1`, h.group, h.otherGroup)
			scopeTo(f, h.otherGroup)
			return `UPDATE machine_group SET parent_id = NULL WHERE id = $1`, []any{h.group}
		}},
		{"reparent removes relay coverage", func(f *pgWakeFixture) (string, []any) {
			h := f.h
			h.rawSQL(`UPDATE machine_group SET parent_id = $2 WHERE id = $1`, h.otherGroup, h.group)
			scopeTo(f, h.group)
			return `UPDATE machine_group SET parent_id = NULL WHERE id = $1`, []any{h.otherGroup}
		}},
	} {
		t.Run(tc.name+"/mutation commits before authority read", func(t *testing.T) {
			f := newPgWakeFixture(t)
			sql, args := tc.prepare(f)
			h := f.h
			s := h.srv(h.owner)
			s.WakeOnLAN, s.WakeStore, s.WakeThrottle = true, f.store, fakeWakeThrottle(0)
			presence := onlineAt(time.Now(), f.relay.Device)
			presence.WakeCapableByDevice = map[string]bool{f.relay.Device: true}
			s.Presence = fixedPresence{p: presence}
			dispatcher := &fakeWakeDispatcher{
				onContext: func(string) (WakeContext, WakeOutcome) {
					// Candidate selection has finished and issuance has yet to read authority.
					h.rawSQL(sql, args...)
					return f.issue.Dispatch, WakeContextReady
				},
				onForward: func(string, []byte) WakeOutcome { return WakeWritten },
			}
			s.WakeDispatcher = dispatcher
			status, body := h.doOn(s, http.MethodPost, "/machines/"+f.target.ID+"/wake", "", "")
			if status != http.StatusConflict || body["error"] != "changed" ||
				len(dispatcher.contexts) != 1 || len(dispatcher.forwards) != 0 {
				t.Fatalf("Wake response = %d %v, context calls = %d, forwards = %d; want 409 changed after one context call without forwarding",
					status, body, len(dispatcher.contexts), len(dispatcher.forwards))
			}
			f.checkAuditCount(0)
		})
		t.Run(tc.name+"/Wake commits first", func(t *testing.T) {
			f := newPgWakeFixture(t)
			sql, args := tc.prepare(f)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			gate, gatePID := holdWakeAuditChain(t, f)
			issued := make(chan error, 1)
			go func() {
				_, err := f.store.issueWake(ctx, &f.principal, f.issue)
				issued <- err
			}()
			wakePID := waitForWakeBlock(t, f, gatePID)
			mutated := make(chan error, 1)
			go func() {
				// Exec commits the mutation in an implicit transaction.
				_, err := f.h.su.Exec(ctx, sql, args...)
				mutated <- err
			}()
			waitForWakeBlock(t, f, wakePID)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-issued; err != nil {
				t.Fatalf("issuance failed while mutation waited: %v", err)
			}
			if err := <-mutated; err != nil {
				t.Fatalf("mutation failed after issuance: %v", err)
			}
			f.checkAuditCount(1)
			if _, err := f.store.issueWake(ctx, &f.principal, f.issue); !errors.Is(err, errWakeChanged) {
				t.Fatalf("issuance after mutation = %v, want changed", err)
			}
			f.checkAuditCount(1)
		})
	}
}

func TestPgWakeRejectsMembershipReplacementWhileWaiting(t *testing.T) {
	f := newPgWakeFixture(t)
	h := f.h
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h.rawSQL(`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
		SELECT $1, $2, id, '{}'::uuid[] FROM role WHERE key = 'technician' AND tenant_id IS NULL`, h.tenant, h.owner)
	gate, err := h.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(ctx)
	// Pause SetUserAssignment in its DELETE by locking the other membership.
	// The assignment has already locked the Owner row when it reaches this wait.
	if _, err := gate.Exec(ctx, `SELECT m.id FROM membership m JOIN role r ON r.id = m.role_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND r.key = 'technician' AND r.tenant_id IS NULL
		FOR UPDATE OF m`, h.tenant, h.owner); err != nil {
		t.Fatal(err)
	}
	assigned := make(chan error, 1)
	go func() {
		assigned <- h.users.SetUserAssignment(ctx, h.tenant, h.owner, Assignment{Role: RoleOwner})
	}()
	assignmentPID := waitForWakeBlock(t, f, gate.Conn().PgConn().PID())

	s := h.srv(h.owner)
	s.WakeOnLAN, s.WakeStore, s.WakeThrottle = true, f.store, fakeWakeThrottle(0)
	presence := onlineAt(time.Now(), f.relay.Device)
	presence.WakeCapableByDevice = map[string]bool{f.relay.Device: true}
	s.Presence = fixedPresence{p: presence}
	dispatcher := &fakeWakeDispatcher{
		onContext: func(string) (WakeContext, WakeOutcome) { return f.issue.Dispatch, WakeContextReady },
		onForward: func(string, []byte) WakeOutcome { return WakeWritten },
	}
	s.WakeDispatcher = dispatcher
	path := "/machines/" + f.target.ID + "/wake"
	done := make(chan *httptest.ResponseRecorder, 1)
	handler := s.Handler()
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil).WithContext(ctx))
		done <- rec
	}()
	waitForWakeBlock(t, f, assignmentPID)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-assigned; err != nil {
		t.Fatalf("assignment failed after Wake waited: %v", err)
	}
	rec := <-done
	var body map[string]any
	if rec.Code != http.StatusConflict || json.Unmarshal(rec.Body.Bytes(), &body) != nil ||
		body["error"] != "changed" || len(dispatcher.forwards) != 0 {
		t.Fatalf("Wake response = %d %s, want 409 changed without forwarding", rec.Code, rec.Body)
	}
	f.checkAuditCount(0)
	if _, err := f.store.issueWake(ctx, &f.principal, f.issue); err != nil {
		t.Fatalf("fresh issuance with replacement authority: %v", err)
	}
}

func TestPgWakeAuthorityExpiresWhileWaitingForAudit(t *testing.T) {
	for _, kind := range []string{"membership", "token", "window"} {
		t.Run(kind, func(t *testing.T) {
			f := newPgWakeFixture(t)
			h := f.h
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			var token string
			if kind == "token" {
				token = f.asToken(nil)
			}
			gate, pid := holdWakeAuditChain(t, f)
			var dbNow time.Time
			if err := h.su.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
				t.Fatal(err)
			}
			deadline := dbNow.UTC().Truncate(time.Second).Add(2 * time.Second)
			switch kind {
			case "membership":
				h.rawSQL(`UPDATE membership SET expires_at = $2 WHERE user_id = $1`, h.owner, deadline)
			case "token":
				h.rawSQL(`UPDATE api_token SET expires_at = $2 WHERE id = $1`, token, deadline)
			case "window":
				// A fixed POSIX zone offset places a local minute boundary at the fixture deadline.
				minute := deadline.Truncate(time.Minute).Add(time.Minute)
				offset := int(minute.Sub(deadline).Seconds())
				zone := fmt.Sprintf("UTC-00:%02d:%02d", offset/60, offset%60)
				end := minute.Hour()*60 + minute.Minute()
				if end == 0 {
					end = 1440
				}
				h.rawSQL(`UPDATE membership SET window_days = 127, window_start = 0, window_end = $2,
					window_tz = $3 WHERE user_id = $1`, h.owner, end, zone)
				// At local midnight an all-days window would immediately reopen.
				if end == 1440 {
					h.rawSQL(`UPDATE membership SET window_start = 1 WHERE user_id = $1`, h.owner)
				}
			}
			issued := make(chan error, 1)
			go func() {
				_, err := f.store.issueWake(ctx, &f.principal, f.issue)
				issued <- err
			}()
			waitForWakeBlock(t, f, pid)
			if _, err := gate.Exec(ctx, `SELECT pg_sleep_until($1)`, deadline.Add(25*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-issued; !errors.Is(err, errWakeChanged) {
				t.Fatalf("issuance at expired boundary = %v, want changed", err)
			}
			f.checkAuditCount(0)
		})
	}
}

func TestPgWakeWaitsForOwnerDisable(t *testing.T) {
	f := newPgWakeFixture(t)
	h := f.h
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h.rawSQL(`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
		SELECT $1, $2, id, '{}'::uuid[] FROM role WHERE key = 'technician' AND tenant_id IS NULL`, h.tenant, h.owner)
	tx, err := h.app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant', $1, true)`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := lockOwnersAndCount(ctx, tx); err != nil {
		t.Fatal(err)
	}
	issued := make(chan error, 1)
	go func() {
		_, err := f.store.issueWake(ctx, &f.principal, f.issue)
		issued <- err
	}()
	waitForWakeBlock(t, f, tx.Conn().PgConn().PID())
	if _, err := tx.Exec(ctx, `UPDATE app_user SET disabled_at = clock_timestamp() WHERE id = $1`, h.owner); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-issued; !errors.Is(err, errWakeChanged) {
		t.Fatalf("issuance after Owner disable = %v, want changed", err)
	}
	f.checkAuditCount(0)
}

func TestPgWakeStillIssuesAfterDelayedPredecessorAllocation(t *testing.T) {
	f := newPgWakeFixture(t)
	h := f.h
	dispatch := f.issue.Dispatch
	lan := h.machines.(LanStore)
	// The fixture has already accepted the replacement's first report. A delayed
	// allocation for the previous socket must leave that report usable for Wake.
	epoch, outcome, err := lan.AllocateLanEpoch(context.Background(), f.relay.Device, f.relay.Pub,
		dispatch.ConnRef.Incarnation, dispatch.ConnRef.Generation-1)
	if err != nil || outcome != LanSuperseded || epoch != 0 {
		t.Fatalf("delayed allocation = (%d, %q, %v), want superseded", epoch, outcome, err)
	}

	s := h.srv(h.owner)
	s.WakeOnLAN, s.WakeStore, s.WakeThrottle = true, f.store, fakeWakeThrottle(0)
	presence := onlineAt(time.Now(), f.relay.Device)
	presence.WakeCapableByDevice = map[string]bool{f.relay.Device: true}
	s.Presence = fixedPresence{p: presence}
	dispatcher := &fakeWakeDispatcher{
		onContext: func(string) (WakeContext, WakeOutcome) { return dispatch, WakeContextReady },
		onForward: func(device string, _ []byte) WakeOutcome {
			if device != f.relay.Device {
				t.Fatalf("forward to %q, want acknowledged relay", device)
			}
			return WakeWritten
		},
	}
	s.WakeDispatcher = dispatcher
	if status, body := h.doOn(s, http.MethodPost, "/machines/"+f.target.ID+"/wake", "", ""); status != 202 || body["status"] != "requested" {
		t.Fatalf("wake after delayed allocation = %d %v", status, body)
	}
	if len(dispatcher.forwards) != 1 {
		t.Fatalf("got %d forwards, want 1", len(dispatcher.forwards))
	}
	f.checkAuditCount(1)
}

// Replace the CP Server and its Wake store on the same database, retaining the
// fake signaling handler's state and both ends of its relay socket. This exercises
// CP routes, HTTP dispatch, persistence and frame receipt in-process. The signaling
// HTTP handler and relay framing are test doubles for the production WebSocket path.
func TestPgWakeThroughAcknowledgedRelayAfterStaleActivationAndCPRestart(t *testing.T) {
	f := newPgWakeFixture(t)
	h := f.h
	first := h.srv(h.owner)
	first.LAN = NewPgMachineStore(h.app)
	const incarnationPath = "/internal/signaling/incarnation"
	call := func(s *Server, method, path string, payload any, want int) map[string]any {
		t.Helper()
		var raw []byte
		if payload != nil {
			var err error
			raw, err = json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
		}
		status, body := h.doOn(s, method, path, string(raw), deviceIdentityToken)
		if status != want {
			t.Fatalf("%s %s returned %d %v, want %d", method, path, status, body, want)
		}
		return body
	}
	revision := call(first, http.MethodGet, incarnationPath, nil, http.StatusOK)["revision"]
	delayed := map[string]any{"incarnation": newUUID(), "expected_revision": revision}
	dispatch := f.issue.Dispatch
	dispatch.ConnRef = WakeConnRef{Incarnation: newUUID(), Generation: 1}
	dispatch.Challenge[0] = 1
	call(first, http.MethodPost, incarnationPath,
		map[string]any{"incarnation": dispatch.ConnRef.Incarnation, "expected_revision": revision}, http.StatusOK)

	report := map[string]any{
		"device_id": f.relay.Device, "device_pubkey": f.relay.Pub,
		"incarnation": dispatch.ConnRef.Incarnation, "generation": dispatch.ConnRef.Generation,
	}
	epoch, ok := call(first, http.MethodPost, "/internal/devices/lan-epoch", report, http.StatusOK)["epoch"].(float64)
	if !ok || epoch <= float64(f.issue.Dispatch.Epoch) {
		t.Fatalf("replacement did not advance the relay epoch: %v", epoch)
	}
	dispatch.Epoch = int64(epoch)
	fact := f.issue.Relay.Facts[0]
	digest := sha256.Sum256([]byte("replacement relay snapshot"))
	report["epoch"], report["seq"], report["digest"] = dispatch.Epoch, 1, hex.EncodeToString(digest[:])
	report["entries"] = []LanEntry{{MAC: fact.MAC, IPv4Network: fact.Network, GatewayMAC: &fact.Gateway}}
	if body := call(first, http.MethodPost, "/internal/devices/lan", report, http.StatusOK); body["status"] != string(LanApplied) {
		t.Fatalf("relay report was not acknowledged: %v", body)
	}

	signalingSocket, relaySocket := net.Pipe()
	defer signalingSocket.Close()
	defer relaySocket.Close()
	challenge := hex.EncodeToString(dispatch.Challenge[:])
	keyHash := hex.EncodeToString(dispatch.DeviceKeySHA256[:])
	contexts := 0
	signaling := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+deviceIdentityToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/internal/devices/" + f.relay.Device + "/wake-context":
			contexts++
			writeJSON(w, http.StatusOK, map[string]any{
				"conn_ref": dispatch.ConnRef, "epoch": dispatch.Epoch,
				"challenge": challenge, "device_key_sha256": keyHash,
			})
		case "/internal/devices/" + f.relay.Device + "/wake":
			var order struct {
				ConnRef  WakeConnRef     `json:"conn_ref"`
				Artifact json.RawMessage `json:"artifact"`
			}
			if json.NewDecoder(r.Body).Decode(&order) != nil || order.ConnRef != dispatch.ConnRef {
				writeError(w, http.StatusConflict, "not_written")
				return
			}
			frame := map[string]any{"type": "wake", "artifact": order.Artifact}
			if json.NewEncoder(signalingSocket).Encode(frame) != nil {
				writeError(w, http.StatusBadGateway, "write_failed")
				return
			}
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	presence := onlineAt(time.Now(), f.relay.Device)
	presence.WakeCapableByDevice = map[string]bool{f.relay.Device: true}
	configure := func(s *Server) {
		s.WakeOnLAN = true
		s.WakeStore = &PgWakeStore{Pool: h.app, Audit: NewPgMgmtAuditStore(h.app)}
		s.WakeThrottle = fakeWakeThrottle(0)
		s.Presence = fixedPresence{p: presence}
		s.WakeDispatcher = &HTTPWakeDispatcher{
			BaseURL: "http://signaling.test", Token: deviceIdentityToken,
			Client: &http.Client{Transport: wakeRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Body != nil {
					defer r.Body.Close()
				}
				rec := httptest.NewRecorder()
				signaling.ServeHTTP(rec, r)
				return rec.Result(), nil
			})},
		}
	}
	relayDecoder := json.NewDecoder(relaySocket)
	pub := first.DirectiveIssuer.priv.Public().(ed25519.PublicKey)
	wake := func(s *Server) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		if err := signalingSocket.SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if err := relaySocket.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		type relayFrame struct {
			Type     string          `json:"type"`
			Artifact json.RawMessage `json:"artifact"`
		}
		received := make(chan relayFrame, 1)
		go func() {
			var frame relayFrame
			if relayDecoder.Decode(&frame) != nil {
				frame = relayFrame{}
			}
			received <- frame
		}()
		status, body := h.doOn(s, http.MethodPost, "/machines/"+f.target.ID+"/wake", "", "")
		if status != http.StatusAccepted || body["status"] != "requested" {
			t.Fatalf("Wake returned %d %v", status, body)
		}
		frame := <-received
		expect := wakeExpectation{TenantID: h.tenant, RelayDeviceID: f.relay.Device,
			RelayKeySHA256: keyHash, WakeChallenge: challenge, NowMs: time.Now().UnixMilli()}
		if got := verifyWake(pub, frame.Artifact, expect); frame.Type != "wake" || got != "ok" {
			t.Fatalf("relay frame type %q, verification %q", frame.Type, got)
		}
	}

	configure(first)
	if body := call(first, http.MethodPost, incarnationPath, delayed, http.StatusConflict); body["error"] != "revision_moved" {
		t.Fatalf("delayed predecessor activation returned %v", body)
	}
	wake(first)

	restarted := h.newServer(dirAuth{users: h.users, tenant: h.tenant, user: h.owner, sid: h.sessionFor(h.owner).ID})
	restarted.Machines = NewPgMachineStore(h.app)
	restarted.LAN = restarted.Machines.(LanStore)
	configure(restarted)
	wake(restarted)
	if contexts != 2 {
		t.Fatalf("signaling received %d context requests, want one per Wake", contexts)
	}
	var seq int64
	var storedDigest []byte
	if err := h.su.QueryRow(context.Background(),
		`SELECT last_seq, last_digest FROM machine_lan_state WHERE machine_id = $1`, f.relay.ID).
		Scan(&seq, &storedDigest); err != nil || seq != 1 || hex.EncodeToString(storedDigest) != hex.EncodeToString(digest[:]) {
		t.Fatalf("relay report watermark changed across the lifecycle: seq=%d err=%v", seq, err)
	}
	f.checkAuditCount(2)
}

func TestPgWakeTakesOwnerMembershipBeforeAssignment(t *testing.T) {
	f := newPgWakeFixture(t)
	h := f.h
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	h.rawSQL(`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
		SELECT $1, $2, id, '{}'::uuid[] FROM role WHERE key = 'technician' AND tenant_id IS NULL`, h.tenant, h.owner)

	// Hold the caller's second membership so Wake pauses during its ordered read.
	// Assignment can wait on Wake here only if Wake already took the Owner row.
	gate, err := h.su.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Rollback(ctx)
	var membershipID string
	if err := gate.QueryRow(ctx, `SELECT m.id::text FROM membership m JOIN role r ON r.id = m.role_id
		WHERE m.tenant_id = $1 AND m.user_id = $2 AND r.key = 'technician' AND r.tenant_id IS NULL
		FOR UPDATE OF m`, h.tenant, h.owner).Scan(&membershipID); err != nil {
		t.Fatal(err)
	}

	issued := make(chan error, 1)
	go func() {
		_, err := f.store.issueWake(ctx, &f.principal, f.issue)
		issued <- err
	}()
	wakePID := waitForWakeBlock(t, f, gate.Conn().PgConn().PID())
	assigned := make(chan error, 1)
	go func() {
		assigned <- h.users.SetUserAssignment(ctx, h.tenant, h.owner, Assignment{Role: RoleTechnician})
	}()
	waitForWakeBlock(t, f, wakePID)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-issued; err != nil {
		t.Fatalf("wake issuing first: %v", err)
	}
	if err := <-assigned; err != nil {
		t.Fatalf("assignment after wake: %v", err)
	}
	f.checkAuditCount(1)
}

package controlplane

// Proofs that REDUCING a technician's access interrupts their live remote-control session at the next
// lease renewal (external review: "live sessions outlast a permission change"). The renewal handler
// re-reads the holder's CURRENT grant on every call (SessionAuthenticator.GrantFor, then
// checkHeldSession). A definite denial now refuses the lease AND ends the session record with an
// audited `session.end` / reason `access_revoked`; a failed lookup refuses nothing and ends nothing.
//
// These drive the real authenticator and handler chain with a session cookie obtained BEFORE the
// change, which is the only thing that matters to a technician who is already connected.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func (f *leaseFixture) revokeAuditRows(t *testing.T) []MgmtAuditEvent {
	t.Helper()
	evs, err := f.srv.MgmtAudit.ListEventsFiltered(context.Background(), leaseTenant, 50, AuditFilter{Action: "session.end"})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var out []MgmtAuditEvent
	for _, e := range evs {
		if e.TargetID == f.rec.ID && strings.Contains(string(e.Metadata), "access_revoked") {
			out = append(out, e)
		}
	}
	return out
}

func (f *leaseFixture) requireOpen(t *testing.T) {
	t.Helper()
	st, err := f.srv.SessionRecords.GetSession(context.Background(), leaseTenant, f.rec.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if st.EndedAt != nil {
		t.Fatalf("session must still be open")
	}
}

func (f *leaseFixture) requireRevokedEnd(t *testing.T) {
	t.Helper()
	st, err := f.srv.SessionRecords.GetSession(context.Background(), leaseTenant, f.rec.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if st.EndedAt == nil {
		t.Fatalf("a revoked holder's session record must be ended")
	}
	if rows := f.revokeAuditRows(t); len(rows) != 1 {
		t.Fatalf("want exactly one session.end access_revoked audit row, got %d", len(rows))
	}
}

// mutateStoredSession edits the in-memory session record in place (the fake's map holds pointers).
func (f *leaseFixture) mutateStoredSession(t *testing.T, fn func(*SessionRecord)) {
	t.Helper()
	st := f.srv.SessionRecords.(*InMemorySessionRecordStore)
	st.mu.Lock()
	defer st.mu.Unlock()
	r, ok := st.records[leaseTenant+"\x00"+f.rec.ID]
	if !ok {
		t.Fatalf("stored session not found")
	}
	fn(r)
}

func TestRenewSucceedsWhileAuthorizedAndWritesNoRevokeAudit(t *testing.T) {
	f := newLeaseFixture(t)
	sess, cc, ct := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
	for i := 0; i < 2; i++ {
		if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusOK {
			t.Fatalf("renewal %d = %d %s", i, got.code, got.body)
		}
	}
	f.requireOpen(t)
	if n := len(f.revokeAuditRows(t)); n != 0 {
		t.Fatalf("no revocation audit while authorized, got %d", n)
	}
}

func TestRenewEndsAndAuditsAfterAccessIsReduced(t *testing.T) {
	cases := []struct {
		name   string
		reduce func(t *testing.T, f *leaseFixture)
	}{
		{"role downgraded to read-only", func(t *testing.T, f *leaseFixture) {
			if err := f.users.SetUserRole(context.Background(), leaseTenant, leaseTechID, RoleReadOnly, nil); err != nil {
				t.Fatal(err)
			}
		}},
		{"group scope narrowed away from the machine", func(t *testing.T, f *leaseFixture) {
			if err := f.users.SetUserRole(context.Background(), leaseTenant, leaseTechID, RoleTechnician, []string{"some-other-group"}); err != nil {
				t.Fatal(err)
			}
		}},
		{"machine moved out of the technician's scope", func(t *testing.T, f *leaseFixture) {
			if err := f.users.SetUserRole(context.Background(), leaseTenant, leaseTechID, RoleTechnician, []string{leaseGroup}); err != nil {
				t.Fatal(err)
			}
			f.mutateStoredSession(t, func(r *SessionRecord) { r.MachineGroupID = "elsewhere" })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLeaseFixture(t)
			sess, cc, ct := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
			if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusOK {
				t.Fatalf("renewal before the change = %d %s", got.code, got.body)
			}
			tc.reduce(t, f)
			got := f.renewWith(t, f.rec.ID, sess, cc, ct)
			if got.code != http.StatusForbidden {
				t.Fatalf("renewal after reduction = %d, want 403: %s", got.code, got.body)
			}
			f.requireRevokedEnd(t)
			// Retrying changes nothing: still refused, and no second audit row.
			if again := f.renewWith(t, f.rec.ID, sess, cc, ct); again.code != http.StatusForbidden {
				t.Fatalf("renewal after the end = %d, want 403 (the capability check precedes the ended check)", again.code)
			}
			if n := len(f.revokeAuditRows(t)); n != 1 {
				t.Fatalf("audit rows after retry = %d, want 1", n)
			}
		})
	}
}

// A disabled or removed user never reaches the handler: authentication refuses them (401). The lease
// is therefore refused and lapses at the agent; no record write happens on this path.
func TestRenewRefusedForDisabledAndRemovedUsers(t *testing.T) {
	for _, mode := range []string{"disabled", "removed"} {
		t.Run(mode, func(t *testing.T) {
			f := newLeaseFixture(t)
			sess, cc, ct := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
			if mode == "disabled" {
				if err := f.users.SetUserDisabled(context.Background(), leaseTenant, leaseTechID, true); err != nil {
					t.Fatal(err)
				}
			} else {
				f.users.mu.Lock()
				delete(f.users.users, userKey(leaseTenant, leaseTechID))
				f.users.mu.Unlock()
			}
			if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusUnauthorized {
				t.Fatalf("renewal as %s user = %d, want 401: %s", mode, got.code, got.body)
			}
		})
	}
}

// VIEW vs CONTROL: there is no separate "view" grant to fall back to. Every session needs
// start_session on the machine's group (observers additionally need observe_session), so losing
// start_session ends the session whatever its access. What CAN be downgraded is the group's
// view-only mandate, which the next lease carries (TestRenewCarriesTheGroupsCurrentMandate). An
// observer who loses observe_session while keeping start_session ends too.
func TestRenewEndsObserverThatLostObserveSession(t *testing.T) {
	f := newLeaseFixture(t)
	f.mutateStoredSession(t, func(r *SessionRecord) { r.Access = "view_only" })
	sess, cc, ct := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
	if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusOK {
		t.Fatalf("observer renewal while permitted = %d %s", got.code, got.body)
	}
	custom := Membership{Role: "custom", Scope: AllGroups(),
		caps: newCapabilitySet([]Capability{CapViewMachines, CapStartSession, CapViewSessions})}
	f.users.mu.Lock()
	f.users.grants[userKey(leaseTenant, leaseTechID)] = NewGrant(leaseTechID, leaseTenant, custom)
	f.users.mu.Unlock()
	if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusForbidden {
		t.Fatalf("observer renewal after losing observe_session = %d, want 403: %s", got.code, got.body)
	}
	f.requireRevokedEnd(t)
}

// Someone ELSE's denied call must never end the holder's session.
func TestDeniedRenewalByAnotherUserDoesNotEndTheSession(t *testing.T) {
	f := newLeaseFixture(t)
	const strangerID = "44444444-4444-4444-4444-444444444444"
	f.addUserWithGrant(t, leaseTenant, strangerID, "ro@acme.test", leasePw,
		NewGrant(strangerID, leaseTenant, NewMembership(RoleReadOnly, Groups(leaseGroup))))
	sess, cc, ct := loginFor(t, f.authFixture, "ro@acme.test", leasePw)
	if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusForbidden {
		t.Fatalf("stranger renewal = %d, want 403", got.code)
	}
	f.requireOpen(t)
	if n := len(f.revokeAuditRows(t)); n != 0 {
		t.Fatalf("stranger must not cause an audit row")
	}
}

// flakySessionRecords / flakyMachines inject a transient store failure into the lookups a renewal makes.
type flakySessionRecords struct {
	SessionRecordStore
	failGet bool
	ended   int
}

func (s *flakySessionRecords) GetSession(ctx context.Context, tenantID, id string) (*SessionRecord, error) {
	if s.failGet {
		return nil, errors.New("connection reset by peer")
	}
	return s.SessionRecordStore.GetSession(ctx, tenantID, id)
}

func (s *flakySessionRecords) EndSession(ctx context.Context, tenantID, id string, at time.Time) (*SessionRecord, error) {
	s.ended++
	return s.SessionRecordStore.EndSession(ctx, tenantID, id, at)
}

type flakyMachines struct {
	MachineStore
	fail bool
}

func (m *flakyMachines) GetMachine(ctx context.Context, tenantID, deviceID string) (*Machine, error) {
	if m.fail {
		return nil, errors.New("deadline exceeded")
	}
	return m.MachineStore.GetMachine(ctx, tenantID, deviceID)
}

// A transient database error during renewal is a 5xx: no lease, but NOTHING is ended and no
// revocation is audited. Only a definite "not authorized" ends a session.
func TestTransientStoreErrorDuringRenewalDoesNotEndTheSession(t *testing.T) {
	f := newLeaseFixture(t)
	recs := &flakySessionRecords{SessionRecordStore: f.srv.SessionRecords}
	f.srv.SessionRecords = recs
	ms := &flakyMachines{MachineStore: f.srv.Machines}
	f.srv.Machines = ms
	sess, cc, ct := loginFor(t, f.authFixture, "tech@acme.test", leasePw)

	recs.failGet = true
	if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusInternalServerError {
		t.Fatalf("session lookup failure = %d, want 500: %s", got.code, got.body)
	}
	recs.failGet = false
	ms.fail = true
	if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusInternalServerError {
		t.Fatalf("machine lookup failure = %d, want 500: %s", got.code, got.body)
	}
	ms.fail = false
	if recs.ended != 0 {
		t.Fatalf("a transient error ended the session %d times", recs.ended)
	}
	f.requireOpen(t)
	if n := len(f.revokeAuditRows(t)); n != 0 {
		t.Fatalf("transient error wrote %d revocation audit rows", n)
	}
	if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusOK {
		t.Fatalf("renewal after recovery = %d %s", got.code, got.body)
	}
}

func (s *flakySessionRecords) EndOpenSessionWithAudit(ctx context.Context, tenantID, id string, at time.Time, audit MgmtAuditStore, ev *MgmtAuditEvent) (bool, error) {
	s.ended++
	return s.SessionRecordStore.(SessionEndAuditor).EndOpenSessionWithAudit(ctx, tenantID, id, at, audit, ev)
}

type revokeFailingAudit struct {
	MgmtAuditStore
	fail bool
}

func (a *revokeFailingAudit) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	if a.fail {
		return errors.New("audit unavailable")
	}
	return a.MgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

// In-memory mirror of the PG rollback proof, and the "next renewal retries" half through the full chain.
func TestRevokedEndRollsBackWhenAuditFailsAndNextRenewalRetries(t *testing.T) {
	f := newLeaseFixture(t)
	fa := &revokeFailingAudit{MgmtAuditStore: f.srv.MgmtAudit, fail: true}
	f.srv.MgmtAudit = fa
	sess, cc, ct := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
	if err := f.users.SetUserRole(context.Background(), leaseTenant, leaseTechID, RoleReadOnly, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusInternalServerError {
		t.Fatalf("renewal with failing audit = %d, want 500: %s", got.code, got.body)
	}
	f.requireOpen(t)
	fa.fail = false
	if got := f.renewWith(t, f.rec.ID, sess, cc, ct); got.code != http.StatusForbidden {
		t.Fatalf("retry = %d, want 403", got.code)
	}
	f.requireRevokedEnd(t)
}

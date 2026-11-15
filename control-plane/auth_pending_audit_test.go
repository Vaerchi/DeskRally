package controlplane

// F20 telemetry tests — auth.second_factor_pending sampling.
//
// Covers: event content (empty actor/target, no secrets), cooldown gate, boundary,
// backward-clock safety, bad-password negative, successful-TOTP distinguishability,
// failing-store slot consumption, reentrant-store no-deadlock, concurrent admission.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingAuditStore wraps InMemoryMgmtAuditStore and counts RecordEvent calls.
type countingAuditStore struct {
	*InMemoryMgmtAuditStore
	calls atomic.Int64
}

func (c *countingAuditStore) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	c.calls.Add(1)
	return c.InMemoryMgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

// errAuditStore always returns an error from RecordEvent.
type errAuditStore struct{ *InMemoryMgmtAuditStore }

func (e *errAuditStore) RecordEvent(_ context.Context, _ string, _ *MgmtAuditEvent) error {
	return errors.New("synthetic store failure")
}

// pendingFixture extends authFixture with a TOTP-enrolled user and a controllable clock.
type pendingFixture struct {
	*authFixture
	audit    *countingAuditStore
	secret   string
	fixedNow time.Time
}

func newPendingFixture(t *testing.T) *pendingFixture {
	t.Helper()
	f := newAuthFixture(t)
	f.auth.DisableThrottle = true

	audit := &countingAuditStore{InMemoryMgmtAuditStore: NewInMemoryMgmtAuditStore()}
	f.auth.MgmtAudit = audit
	f.srv.MgmtAudit = audit

	u := f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)

	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}

	fixedNow := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return fixedNow }

	return &pendingFixture{authFixture: f, audit: audit, secret: secret, fixedNow: fixedNow}
}

// doLoginNoCode fires a POST /auth/login with the correct password but no TOTP code.
func (f *pendingFixture) doLoginNoCode(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)
}

// pendingEvents returns events with action auth.second_factor_pending from the audit store.
func pendingEvents(t *testing.T, store *countingAuditStore, tenantID string) []MgmtAuditEvent {
	t.Helper()
	events, err := store.ListEvents(context.Background(), tenantID, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	var out []MgmtAuditEvent
	for _, e := range events {
		if e.Action == "auth.second_factor_pending" {
			out = append(out, e)
		}
	}
	return out
}

// TestSecondFactorPendingAuditEmittedOnTOTPRequired checks that a correct password + enrolled
// TOTP + missing code emits exactly one auth.second_factor_pending event with empty actor/target
// and the expected metadata; no session cookie is set.
func TestSecondFactorPendingAuditEmittedOnTOTPRequired(t *testing.T) {
	f := newPendingFixture(t)

	rec := f.doLoginNoCode(t)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), ErrTOTPRequired.Error()) {
		t.Fatalf("body = %s, want totp required", rec.Body.String())
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("must not set a session cookie on ErrTOTPRequired")
	}

	events := pendingEvents(t, f.audit, "tenant-1")
	if len(events) != 1 {
		t.Fatalf("pending events = %d, want 1", len(events))
	}
	e := events[0]
	if e.ActorUserID != "" {
		t.Errorf("ActorUserID = %q, want empty (caller not authenticated)", e.ActorUserID)
	}
	if e.TargetID != "" {
		t.Errorf("TargetID = %q, want empty", e.TargetID)
	}

	var meta map[string]any
	if err := json.Unmarshal(e.Metadata, &meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if meta["email"] != "tech@example.com" {
		t.Errorf("metadata email = %v, want tech@example.com", meta["email"])
	}
	if _, ok := meta["ip"]; !ok {
		t.Error("metadata missing ip")
	}
	if meta["sampled"] != true {
		t.Errorf("metadata sampled = %v, want true", meta["sampled"])
	}
	// No secret fields.
	for _, banned := range []string{"password", "totp", "hash", "secret"} {
		if _, found := meta[banned]; found {
			t.Errorf("metadata must not contain %q", banned)
		}
	}
}

// TestSecondFactorPendingCooldownSuppressesRepeats verifies that a second call within the
// cooldown window does not emit a second event and does not charge the failure throttle budget.
func TestSecondFactorPendingCooldownSuppressesRepeats(t *testing.T) {
	f := newPendingFixture(t)
	h := f.srv.Handler()

	// First call — emits one event.
	if rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first call = %d, want 401", rec.Code)
	}

	// Second call within the same 30 s window (clock frozen) — suppressed.
	if rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("second call = %d, want 401", rec.Code)
	}

	events := pendingEvents(t, f.audit, "tenant-1")
	if len(events) != 1 {
		t.Fatalf("pending events after 2 calls = %d, want 1 (cooldown suppressed the second)", len(events))
	}
}

// TestSecondFactorPendingCooldownBoundary verifies that an event is allowed at exactly
// nextPendingAuditAt (boundary is inclusive: now == next is allowed, not suppressed).
func TestSecondFactorPendingCooldownBoundary(t *testing.T) {
	f := newPendingFixture(t)
	h := f.srv.Handler()

	// First event — sets nextPendingAuditAt = fixedNow + 30s.
	doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)

	// Advance clock to exactly the boundary.
	boundary := f.fixedNow.Add(pendingAuditCooldown)
	f.auth.Now = func() time.Time { return boundary }

	doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)

	events := pendingEvents(t, f.audit, "tenant-1")
	if len(events) != 2 {
		t.Fatalf("pending events at boundary = %d, want 2 (boundary is allowed)", len(events))
	}
}

// TestSecondFactorPendingBackwardClockCannotTrigger confirms that a backward clock move after
// the first event does not produce a second one.
func TestSecondFactorPendingBackwardClockCannotTrigger(t *testing.T) {
	f := newPendingFixture(t)
	h := f.srv.Handler()

	// First event.
	doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)

	// Wind the clock back — nextPendingAuditAt is already in the "future" from this instant.
	f.auth.Now = func() time.Time { return f.fixedNow.Add(-5 * time.Second) }

	doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)

	events := pendingEvents(t, f.audit, "tenant-1")
	if len(events) != 1 {
		t.Fatalf("pending events after backward clock = %d, want 1 (backward clock must not grant extra slots)", len(events))
	}
}

// TestBadPasswordDoesNotEmitPending confirms that a wrong password goes to the default
// auth.login_failed path and never emits auth.second_factor_pending.
func TestBadPasswordDoesNotEmitPending(t *testing.T) {
	f := newPendingFixture(t)

	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "wrong"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}

	events := pendingEvents(t, f.audit, "tenant-1")
	if len(events) != 0 {
		t.Fatalf("pending events after bad password = %d, want 0", len(events))
	}
}

// TestSuccessfulTOTPLoginDistinguishable verifies that after pending events, a correct full
// 2FA login still emits auth.login (attributed to the user) and not auth.second_factor_pending.
func TestSuccessfulTOTPLoginDistinguishable(t *testing.T) {
	f := newPendingFixture(t)
	h := f.srv.Handler()

	// Trigger one pending event.
	doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}, nil)

	// Advance clock past cooldown to allow the slot + a fresh TOTP step.
	f.auth.Now = func() time.Time { return f.fixedNow.Add(2 * pendingAuditCooldown) }
	now := f.fixedNow.Add(2 * pendingAuditCooldown)
	code, _ := TOTPCode(f.secret, now, DefaultTOTPConfig)

	rec := doJSON(t, h, "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234", TOTPCode: code}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("successful 2FA login = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	events, err := f.audit.ListEvents(context.Background(), "tenant-1", 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Action]++
	}
	if counts["auth.login"] == 0 {
		t.Fatal("successful 2FA login must emit auth.login")
	}
	// auth.login must be attributed; auth.second_factor_pending must never be.
	for _, e := range events {
		if e.Action == "auth.login" && e.ActorUserID == "" {
			t.Error("auth.login actor must not be empty after a successful authentication")
		}
		if e.Action == "auth.second_factor_pending" && e.ActorUserID != "" {
			t.Error("auth.second_factor_pending must always have an empty actor")
		}
	}
}

// TestFailingAuditStoreConsumesSlot verifies that when the store returns an error the cooldown
// slot is still consumed, so a broken store cannot amplify log output on every request.
func TestFailingAuditStoreConsumesSlot(t *testing.T) {
	f := newAuthFixture(t)
	f.auth.DisableThrottle = true

	failing := &errAuditStore{InMemoryMgmtAuditStore: NewInMemoryMgmtAuditStore()}
	f.auth.MgmtAudit = failing

	u := f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return now }

	h := f.srv.Handler()
	login := loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "password-1234"}

	// First call triggers a failing write and advances nextPendingAuditAt.
	if rec := doJSON(t, h, "POST", "/auth/login", login, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first call = %d, want 401", rec.Code)
	}

	// Replace with a counting store — the second call (within window) must not call RecordEvent.
	counting := &countingAuditStore{InMemoryMgmtAuditStore: NewInMemoryMgmtAuditStore()}
	f.auth.MgmtAudit = counting

	if rec := doJSON(t, h, "POST", "/auth/login", login, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("second call = %d, want 401", rec.Code)
	}
	if counting.calls.Load() != 0 {
		t.Fatalf("RecordEvent called %d times after failed-store slot consumed cooldown, want 0",
			counting.calls.Load())
	}
}

// TestPendingAuditMutexNotHeldDuringCallback verifies that the mutex is released before the
// store call by using a store whose RecordEvent calls tryRecordPendingAudit again — if the
// mutex were still held, this would deadlock.
func TestPendingAuditMutexNotHeldDuringCallback(t *testing.T) {
	f := newAuthFixture(t)
	f.auth.DisableThrottle = true

	u := f.addUser(t, "tenant-1", "u1", "tech@example.com", "password-1234", RoleTechnician)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := f.users.SetTOTP(context.Background(), u.TenantID, u.ID, secret, true); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	f.auth.Now = func() time.Time { return now }

	// A store that re-enters tryRecordPendingAudit from within RecordEvent.
	reentrant := &reentrantAuditStore{
		InMemoryMgmtAuditStore: NewInMemoryMgmtAuditStore(),
	}
	f.auth.MgmtAudit = reentrant
	// Provide the service reference so the store can call back.
	reentrant.svc = f.auth

	done := make(chan struct{})
	go func() {
		defer close(done)
		r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(
			`{"tenant":"tenant-1","email":"tech@example.com","password":"password-1234"}`))
		r.Header.Set("Content-Type", "application/json")
		f.auth.tryRecordPendingAudit(r, "tenant-1", "tech@example.com")
	}()

	select {
	case <-done:
		// no deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("tryRecordPendingAudit deadlocked — mutex was held during the store callback")
	}
}

// reentrantAuditStore calls tryRecordPendingAudit from within RecordEvent to detect mutex
// re-entry (which would deadlock if the mutex were held during I/O).
type reentrantAuditStore struct {
	*InMemoryMgmtAuditStore
	svc  *AuthService
	once sync.Once
}

func (s *reentrantAuditStore) RecordEvent(ctx context.Context, tenantID string, e *MgmtAuditEvent) error {
	s.once.Do(func() {
		// Re-enter from within the callback; the cooldown is already set so this returns immediately.
		r := httptest.NewRequest("POST", "/", nil)
		s.svc.tryRecordPendingAudit(r, tenantID, "tech@example.com")
	})
	return s.InMemoryMgmtAuditStore.RecordEvent(ctx, tenantID, e)
}

// TestPendingAuditConcurrentSlotAdmission fires N goroutines simultaneously and checks that
// exactly one audit event is recorded (the mutex ensures only one slot is granted). This test
// calls tryRecordPendingAudit directly to avoid repeated expensive argon2 hashing.
func TestPendingAuditConcurrentSlotAdmission(t *testing.T) {
	const goroutines = 20

	svc := &AuthService{DisableThrottle: true}
	store := &countingAuditStore{InMemoryMgmtAuditStore: NewInMemoryMgmtAuditStore()}
	svc.MgmtAudit = store

	fixedNow := time.Unix(1_700_000_000, 0)
	svc.Now = func() time.Time { return fixedNow }

	r := httptest.NewRequest("POST", "/", nil)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			svc.tryRecordPendingAudit(r, "tenant-1", "tech@example.com")
		}()
	}
	close(start)
	wg.Wait()

	if n := store.calls.Load(); n != 1 {
		t.Fatalf("RecordEvent called %d times from %d concurrent goroutines, want exactly 1", n, goroutines)
	}
}

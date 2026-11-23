package controlplane

// A store fault while authenticating is a 503, never the 401 the console reads as "signed out".
// See auth_outcome.go.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// faultSessions fails GetByTokenHash with the stored error while it is non-nil.
type faultSessions struct {
	SessionStore
	err atomic.Pointer[error]
}

func (f *faultSessions) set(e error) { f.err.Store(&e) }
func (f *faultSessions) GetByTokenHash(ctx context.Context, h []byte) (*Session, error) {
	if p := f.err.Load(); p != nil && *p != nil {
		return nil, *p
	}
	return f.SessionStore.GetByTokenHash(ctx, h)
}

// faultUsers fails FindUserByID and/or GrantFor.
type faultUsers struct {
	UserStore
	findErr, grantErr error
}

func (f *faultUsers) FindUserByID(ctx context.Context, t, u string) (*AuthUser, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.UserStore.FindUserByID(ctx, t, u)
}
func (f *faultUsers) GrantFor(ctx context.Context, t, u string) (*Grant, error) {
	if f.grantErr != nil {
		return nil, f.grantErr
	}
	return f.UserStore.GrantFor(ctx, t, u)
}

// countingBinder counts BindTenant calls: it is reached only by a request that authenticated.
type countingBinder struct{ n atomic.Int32 }

func (b *countingBinder) BindTenant(ctx context.Context, _ string) (context.Context, func(), error) {
	b.n.Add(1)
	return ctx, nil, nil
}

type authOutcomeRig struct {
	h      http.Handler
	cookie *http.Cookie
	bind   *countingBinder
}

// newAuthOutcomeRig logs a user in on the in-memory stores, then fronts them with the fault wrappers.
func newAuthOutcomeRig(t *testing.T, sess *faultSessions, users *faultUsers) *authOutcomeRig {
	t.Helper()
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "hunter2-long-enough", RoleTechnician)
	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "hunter2-long-enough"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d", rec.Code)
	}
	cookie := sessionCookieFrom(rec)
	sess.SessionStore = f.sessions.Store
	users.UserStore = f.users
	bind := &countingBinder{}
	srv := NewServer(&SessionAuthenticator{Sessions: NewSessionManager(sess), Users: users}, bind)
	srv.AuthAPI = &AuthService{Users: users, Sessions: NewSessionManager(sess), Issuer: "RMT"}
	srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
	return &authOutcomeRig{h: srv.Handler(), cookie: cookie, bind: bind}
}

func (r *authOutcomeRig) get(t *testing.T, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, r.h, "GET", path, nil, cookie)
}

func requireUnavailable(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%s = %d, want 503 (body %s)", what, rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "2" {
		t.Fatalf("%s Retry-After = %q, want 2", what, rec.Header().Get("Retry-After"))
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"temporarily unavailable"}` {
		t.Fatalf("%s body = %s, want the fixed generic error", what, got)
	}
}

func TestAuthStoreFault_Is503NeverTheSignOut401_AndNoHandlerRuns(t *testing.T) {
	pgFault := &pgconn.PgError{Code: "08006", Message: "connection failure with secret detail"}
	cases := []struct {
		name string
		sess error
		find error
		gran error
	}{
		{"session lookup: connection error", pgFault, nil, nil},
		{"session lookup: context deadline", fmt.Errorf("query: %w", context.DeadlineExceeded), nil, nil},
		{"session lookup: net error", &net.OpError{Op: "read", Err: errors.New("reset")}, nil, nil},
		{"session lookup: serialization failure", &pgconn.PgError{Code: "40001"}, nil, nil},
		{"session lookup: pool closed", errors.New("closed pool"), nil, nil},
		{"user lookup: too many connections", nil, &pgconn.PgError{Code: "53300"}, nil},
		{"user lookup: admin shutdown", nil, &pgconn.PgError{Code: "57P01"}, nil},
		{"grant lookup: deadlock", nil, nil, &pgconn.PgError{Code: "40P01"}},
		{"grant lookup: unclassified error", nil, nil, errors.New("something nobody has heard of")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, users := &faultSessions{}, &faultUsers{}
			rig := newAuthOutcomeRig(t, sess, users)
			if tc.sess != nil {
				sess.set(tc.sess)
			}
			users.findErr, users.grantErr = tc.find, tc.gran
			rec := rig.get(t, "/machines", rig.cookie)
			requireUnavailable(t, rec, "GET /machines")
			if strings.Contains(rec.Body.String(), "secret detail") {
				t.Fatal("the underlying error leaked into the response")
			}
			if n := rig.bind.n.Load(); n != 0 {
				t.Fatalf("the tenant binder ran %d times after a failed authentication: a handler chain was entered", n)
			}
			// And it is recoverable: the same cookie works once the store answers.
			sess.set(nil)
			users.findErr, users.grantErr = nil, nil
			if rec := rig.get(t, "/machines", rig.cookie); rec.Code != http.StatusOK {
				t.Fatalf("after recovery = %d, want 200", rec.Code)
			}
		})
	}
}

func TestAuthDefiniteVerdicts_Stay401Or403(t *testing.T) {
	cases := []struct {
		name string
		sess error
		find error
		want int
	}{
		{"session not found", ErrSessionNotFound, nil, 401},
		{"session expired", ErrSessionExpired, nil, 401},
		{"session idle", ErrSessionIdle, nil, 401},
		{"session revoked", ErrSessionRevoked, nil, 401},
		{"credential stale", ErrSessionCredentialStale, nil, 401},
		{"no rows from a lookup that did not map it", fmt.Errorf("scan: %w", pgx.ErrNoRows), nil, 401},
		{"user gone", nil, ErrNoUser, 401},
		{"user disabled", nil, ErrUserDisabled, 401},
		{"tenant suspended", nil, ErrTenantSuspended, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, users := &faultSessions{}, &faultUsers{}
			rig := newAuthOutcomeRig(t, sess, users)
			if tc.sess != nil {
				sess.set(tc.sess)
			}
			users.findErr = tc.find
			rec := rig.get(t, "/machines", rig.cookie)
			if rec.Code != tc.want {
				t.Fatalf("= %d, want %d", rec.Code, tc.want)
			}
			if rec.Header().Get("Retry-After") != "" {
				t.Fatal("a definite verdict must not carry Retry-After")
			}
			if rig.bind.n.Load() != 0 {
				t.Fatal("handler chain entered")
			}
		})
	}
	// No credential and a garbage cookie are 401 too (no store fault involved).
	rig := newAuthOutcomeRig(t, &faultSessions{}, &faultUsers{})
	if rec := rig.get(t, "/machines", nil); rec.Code != 401 {
		t.Fatalf("no credential = %d, want 401", rec.Code)
	}
	if rec := rig.get(t, "/machines", &http.Cookie{Name: DefaultSessionCookie, Value: "nope"}); rec.Code != 401 {
		t.Fatalf("unknown cookie = %d, want 401", rec.Code)
	}
}

type countFaultUsers struct {
	UserStore
	n        int
	failFrom int
	err      error
}

func (c *countFaultUsers) FindUserByID(ctx context.Context, t, u string) (*AuthUser, error) {
	c.n++
	if c.n >= c.failFrom {
		return nil, c.err
	}
	return c.UserStore.FindUserByID(ctx, t, u)
}

// /me and /auth/step-up re-read the user: a blip there must not sign the operator out either, while a user who is
// really gone stays 401.
func TestAuthStoreFault_MeAndStepUp(t *testing.T) {
	f := newAuthFixture(t)
	f.addUser(t, "tenant-1", "u1", "tech@example.com", "hunter2-long-enough", RoleTechnician)
	rec := doJSON(t, f.srv.Handler(), "POST", "/auth/login",
		loginRequest{Tenant: "tenant-1", Email: "tech@example.com", Password: "hunter2-long-enough"}, nil)
	cookie := sessionCookieFrom(rec)
	csrfCookie, csrf := csrfFrom(t, rec)

	build := func(err error) http.Handler {
		// The authenticator's FindUserByID (call 1) succeeds; the handler's own (call 2) fails.
		fu := &countFaultUsers{UserStore: f.users, failFrom: 2, err: err}
		srv := NewServer(&SessionAuthenticator{Sessions: f.sessions, Users: fu}, NoopBinder{})
		srv.AuthAPI = &AuthService{Users: fu, Sessions: f.sessions, Issuer: "RMT"}
		return srv.Handler()
	}
	for _, tc := range []struct {
		err  error
		want int
	}{{&pgconn.PgError{Code: "08000"}, 503}, {ErrNoUser, 401}} {
		got := doJSONWith(t, build(tc.err), "GET", "/me", nil, "", cookie)
		if got.Code != tc.want {
			t.Fatalf("/me with %v = %d, want %d", tc.err, got.Code, tc.want)
		}
		if tc.want == 503 {
			requireUnavailable(t, got, "/me")
		}
		got = doJSONWith(t, build(tc.err), "POST", "/auth/step-up", map[string]string{"code": "123456"}, csrf, cookie, csrfCookie)
		if got.Code != tc.want {
			t.Fatalf("/auth/step-up with %v = %d, want %d (%s)", tc.err, got.Code, tc.want, got.Body.String())
		}
	}
}

// API tokens: a store fault is 503; a token the store says is unknown is 401.
type faultTokens struct {
	APITokenStore
	err error
}

func (f faultTokens) Resolve(context.Context, string) (*APIToken, error) { return nil, f.err }

func TestAuthStoreFault_APIToken(t *testing.T) {
	tok := APITokenPrefix + strings.Repeat("a", 40)
	for _, tc := range []struct {
		err  error
		want int
	}{
		{&pgconn.PgError{Code: "57P01"}, 503},
		{context.DeadlineExceeded, 503},
		{ErrAPITokenNotFound, 401},
	} {
		bind := &countingBinder{}
		srv := NewServer(&APITokenAuthenticator{Tokens: faultTokens{err: tc.err}, Next: StubAuthenticator{}}, bind)
		srv.Machines = NewPermissiveMachineStore(DevDefaultMachineGroupID)
		r := httptest.NewRequest("GET", "/machines", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("token resolve %v = %d, want %d", tc.err, w.Code, tc.want)
		}
		if tc.want == 503 {
			requireUnavailable(t, w, "api token")
		}
		if bind.n.Load() != 0 {
			t.Fatal("handler chain entered")
		}
	}
}

// The credential guard's own refusals keep their semantics: 429 for the budget, 503 "temporarily busy" for the
// global cap. The new 503 must not shadow them (the middleware answers a refusal before classifying).
func TestAuthStoreFault_GuardRefusalKeepsItsOwnAnswer(t *testing.T) {
	busy := &credentialRefusal{err: ErrCredentialBusy, retryAfter: credentialBusyRetryAfter}
	srv := NewServer(refusingAuth{err: busy}, &countingBinder{})
	rec := doJSON(t, srv.Handler(), "GET", "/machines", nil, nil)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "temporarily busy") {
		t.Fatalf("busy refusal = %d %s, want the guard's own 503", rec.Code, rec.Body.String())
	}
	budget := &credentialRefusal{err: ErrCredentialBudget, retryAfter: credentialBusyRetryAfter}
	srv = NewServer(refusingAuth{err: budget}, &countingBinder{})
	if rec := doJSON(t, srv.Handler(), "GET", "/machines", nil, nil); rec.Code != 429 {
		t.Fatalf("budget refusal = %d, want 429", rec.Code)
	}
}

type refusingAuth struct{ err error }

func (a refusingAuth) Authenticate(*http.Request) (*Principal, error) { return nil, a.err }

func TestClassifyAuthError_Table(t *testing.T) {
	for _, tc := range []struct {
		err       error
		want      authOutcome
		transient bool
	}{
		{ErrInvalidCredentials, authDefiniteNo, false},
		{fmt.Errorf("w: %w", ErrNoUser), authDefiniteNo, false},
		{pgx.ErrNoRows, authDefiniteNo, false},
		{ErrTenantSuspended, authForbidden, false},
		{&pgconn.PgError{Code: "08006"}, authUnavailable, true},
		{&pgconn.PgError{Code: "53300"}, authUnavailable, true},
		{&pgconn.PgError{Code: "57P01"}, authUnavailable, true},
		{&pgconn.PgError{Code: "57014"}, authUnavailable, true},
		{&pgconn.PgError{Code: "40001"}, authUnavailable, true},
		{&pgconn.PgError{Code: "40P01"}, authUnavailable, true},
		{&pgconn.PgError{Code: "42501"}, authUnavailable, false}, // permission denied: 503 + loud log, never a 401
		{context.DeadlineExceeded, authUnavailable, true},
		{errors.New("unknown"), authUnavailable, false},
	} {
		if got := classifyAuthError(tc.err); got != tc.want {
			t.Errorf("classifyAuthError(%v) = %v, want %v", tc.err, got, tc.want)
		}
		if got := isTransientStoreError(tc.err); got != tc.transient {
			t.Errorf("isTransientStoreError(%v) = %v, want %v", tc.err, got, tc.transient)
		}
	}
}

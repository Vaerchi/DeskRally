package controlplane

// auth_outcome.go — what an authentication-time lookup FAILURE means to the caller.
//
// The console treats a 401 on a protected route as "you are signed out" (web/viewer/src/lib/
// auth_session.ts). So a 401 must mean exactly one thing: the credential was looked up and is not
// good. A database that blinked while we looked is NOT that — it says nothing about the credential,
// and answering 401 signed a technician out mid-work over a connection reset. The fail-closed answer
// is still "not authenticated, nothing ran"; it just must not LOOK like the condition it isn't
// (project lesson: fail-closed must say WHICH failure).
//
//	definite verdict (the store answered; the credential is not good)  -> 401
//	suspended tenant (credential good, tenancy not)                    -> 403
//	anything else (the store could not answer)                         -> 503 + Retry-After
//
// The classification is an ALLOW-list of definite verdicts, deliberately not a list of transient
// errors. A transient-error list has to be complete to be safe (miss one driver error and it becomes
// a sign-out again); an allow-list of verdicts fails the other way: an error nobody has heard of is
// "could not decide", which is a 503 the console retries, never a 401 that ends the session and never
// an authentication. Every definite verdict arrives as one of the sentinels below (they are the same
// set credential_guard.go's credentialFailure already treats as "this credential is not valid"), or as
// pgx.ErrNoRows from a lookup that did not map it. isTransientStoreError exists only to LABEL the log
// line (a connection fault reads differently from an unclassified one); it does not decide the status.

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// authUnavailableRetryAfter is the Retry-After (seconds) of the transient answer: short, because a
// blip clears in about that long and the console retries by itself.
const authUnavailableRetryAfter = "2"

// authUnavailableMessage is the one fixed body of the transient answer. The console matches it
// (web/viewer/src/lib/console_api.ts TRANSIENT_UNAVAILABLE); it never carries the underlying error.
const authUnavailableMessage = "temporarily unavailable"

type authOutcome int

const (
	authDefiniteNo  authOutcome = iota // 401
	authForbidden                      // 403 (suspended tenant)
	authUnavailable                    // 503
)

// classifyAuthError maps a non-nil error from an authentication lookup to its outcome.
func classifyAuthError(err error) authOutcome {
	switch {
	case errors.Is(err, ErrTenantSuspended):
		return authForbidden
	case errors.Is(err, ErrInvalidCredentials),
		errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrSessionExpired), errors.Is(err, ErrSessionIdle),
		errors.Is(err, ErrSessionRevoked), errors.Is(err, ErrSessionCredentialStale),
		errors.Is(err, ErrUserDisabled), errors.Is(err, ErrNoUser),
		errors.Is(err, ErrAPITokenNotFound), errors.Is(err, ErrMachineNotFound),
		errors.Is(err, pgx.ErrNoRows):
		return authDefiniteNo
	}
	return authUnavailable
}

// isTransientStoreError reports whether err is recognisably an infrastructure fault: connection
// class (08*), insufficient resources (53*), operator shutdown / cancel (57P0*, 57014), serialization
// and deadlock (40001, 40P01), a context deadline or cancel, a net error, or a pool that is closed or
// out of connections. Used for logging only (see the file comment).
func isTransientStoreError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		c := pgErr.Code
		switch {
		case len(c) >= 2 && (c[:2] == "08" || c[:2] == "53"):
			return true
		case len(c) >= 3 && c[:3] == "57P":
			return true
		case c == "57014", c == "40001", c == "40P01":
			return true
		}
		return false
	}
	var connErr *pgconn.ConnectError
	if errors.As(err, &connErr) {
		return true
	}
	return pgconn.Timeout(err) || pgconn.SafeToRetry(err)
}

// authFaultLog rate-limits the fault log line: an outage must not let request volume (including
// unauthenticated volume) become log volume. At most one line per interval; the next line says how many
// were suppressed.
var authFaultLog struct {
	sync.Mutex
	next       time.Time
	suppressed int
}

const authFaultLogInterval = 10 * time.Second

// logAuthStoreFault records the real error server-side (method and path only; never the credential).
func logAuthStoreFault(r *http.Request, kind string, err error) {
	now := time.Now()
	authFaultLog.Lock()
	if now.Before(authFaultLog.next) {
		authFaultLog.suppressed++
		authFaultLog.Unlock()
		return
	}
	suppressed := authFaultLog.suppressed
	authFaultLog.suppressed = 0
	authFaultLog.next = now.Add(authFaultLogInterval)
	authFaultLog.Unlock()
	log.Printf("authentication unavailable (%s store fault) on %s %s: %v (%d similar suppressed)", kind, r.Method, r.URL.Path, err, suppressed)
}

// writeAuthUnavailable answers a request that could not be authenticated because the store could not
// answer: 503, a short Retry-After, a fixed body. The real error is logged server-side only.
func writeAuthUnavailable(w http.ResponseWriter, r *http.Request, err error) {
	kind := "unclassified"
	if isTransientStoreError(err) {
		kind = "transient"
	}
	logAuthStoreFault(r, kind, err)
	w.Header().Set("Retry-After", authUnavailableRetryAfter)
	w.Header().Set("Cache-Control", "no-store")
	writeError(w, http.StatusServiceUnavailable, authUnavailableMessage)
}

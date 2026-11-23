package controlplane

// Bounded concurrency for argon2id, closing F01 of docs/25 (the external Codex review):
// "login admits unbounded concurrent Argon2 work".
//
// THE DEFECT. HandleLogin calls Throttle.Allow and only records a failure AFTERWARDS, so Allow
// reserves nothing: N simultaneous requests all see zero past failures and all proceed. Each then
// runs a verification that allocates DefaultArgon2Params.Memory — 64 MiB — so the control plane's
// peak memory is set by how many requests an anonymous client chooses to send. Knowing a password
// is unnecessary, and an unknown user costs the same because the dummy-hash path (auth.go,
// authenticateLocal) deliberately spends comparable work to blunt enumeration. Varying the email
// and source address defeats the per-account and per-IP counters entirely, because those are
// per-KEY and this is a shared, process-wide resource.
//
// WHERE THE GATE SITS, AND WHY. The bound is applied inside VerifyPassword / HashPasswordWith —
// at the point the memory is actually allocated — and not at the handlers. A gate on a shared
// budget has to sit where the budget is SPENT, or it protects only the call sites someone
// remembered to change; there are eleven argon2 call sites today across login, password change,
// reset minting, reset redemption, TOTP step-up and bootstrap, and the next one added would
// silently be unprotected. Sitting here, every present and future caller is bounded.
//
// A BUSY ANSWER IS NOT A CREDENTIAL FAILURE. This is the trap that makes a limiter dangerous, and
// it is why the two entry points below differ:
//
//   - VerifyPassword/HashPassword (no context) WAIT. They keep their existing contract exactly —
//     an error still means "malformed hash" and nothing else. Had they instead returned a "busy"
//     error, every caller's `if verr != nil || !ok` would read it as a WRONG PASSWORD, call
//     th.Fail(keys...), and lock out the account. An attacker who can saturate the semaphore could
//     then lock out any account they can name, turning a memory bound into a remote off switch for
//     other people's logins. The rate limiter that becomes the off switch is a mistake this
//     project has already paid for once.
//   - VerifyPasswordCtx/HashPasswordCtx may return ErrHashBusy, and the handlers that call them
//     map it to 503 + Retry-After and return WITHOUT spending throttle budget or writing a
//     credential-failure audit event. Nothing an attacker does to capacity may be recorded as a
//     failed guess by the victim.
//
// RESIDUAL LIMITATION, stated plainly. This bounds MEMORY and CPU, not availability. A client with
// enough concurrency can still fill the semaphore and its queue, and legitimate logins then get
// 503 for as long as that lasts. That is a strictly better failure than the current one — the
// process stays alive, other endpoints keep serving, and the answer is a retryable status rather
// than an OOM kill — but it is not a defence against a determined flood, which needs admission
// control at the edge (docs/25 F09) as well.

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// ErrHashBusy is returned by the context-aware hashing entry points when the process is already
// running its configured maximum of concurrent argon2 operations and the wait queue is full or the
// wait deadline elapsed. It means "no capacity right now", never "wrong password" — see
// WriteHashBusy for the response, and the file header for why the distinction is load-bearing.
var ErrHashBusy = errors.New("password verification capacity exhausted")

// HashLimiterConfig bounds concurrent argon2 work.
type HashLimiterConfig struct {
	// MaxConcurrent is the number of argon2 operations that may run at once. Peak argon2 memory
	// is approximately MaxConcurrent * Argon2Params.Memory, so this is the memory knob: at the
	// 64 MiB default parameters, 4 concurrent is ~256 MiB.
	MaxConcurrent int
	// MaxQueue is how many context-aware callers may WAIT for a slot. Beyond it, callers are
	// rejected immediately with ErrHashBusy, having allocated nothing.
	MaxQueue int
	// MaxWait bounds how long a queued context-aware caller waits before giving up with
	// ErrHashBusy. It exists so a saturated process answers rather than hangs.
	MaxWait time.Duration
}

// DefaultHashLimiterConfig is deliberately small. Each slot costs 64 MiB of live allocation and
// Argon2Params.Threads (4) lanes of CPU, so the default caps argon2 at ~256 MiB and keeps a modest
// VPS responsive; the queue absorbs an ordinary login burst without turning it into 503s, and
// MaxWait keeps a saturated process answering.
var DefaultHashLimiterConfig = HashLimiterConfig{
	MaxConcurrent: defaultHashConcurrency(),
	MaxQueue:      64,
	MaxWait:       2 * time.Second,
}

// defaultHashConcurrency clamps to [2,4]. Two so a single stuck verification cannot serialize the
// whole login path; four because beyond that the memory (4 * 64 MiB) matters more than the
// throughput on the small hosts this deploys to.
func defaultHashConcurrency() int {
	n := runtime.NumCPU()
	if n < 2 {
		return 2
	}
	if n > 4 {
		return 4
	}
	return n
}

// hashLimiter is a counting semaphore with a bounded wait queue.
type hashLimiter struct {
	cfg HashLimiterConfig
	sem chan struct{}

	waiting atomic.Int64
	// rejected counts ErrHashBusy answers, for the regression test and for operators reading a
	// saturation report rather than guessing from latency.
	rejected atomic.Int64
}

// -------------------------------------------------------------------------------------
// Concurrency instrumentation — deliberately NOT part of the limiter
// -------------------------------------------------------------------------------------
//
// argon2InFlight/argon2Peak are maintained by enterArgon2/leaveArgon2, which password.go wraps
// around the argon2.IDKey call ITSELF, not around the semaphore. That separation is the whole
// point: a test that asked the limiter how many slots it had handed out would be asking the
// component under test to grade its own work, and would report a tidy 0 if someone deleted the
// acquire() call entirely. Measured at the allocation instead, the number is the real one — remove
// the bound and the peak rises, which is what makes TestArgon2ConcurrencyIsBounded a control
// rather than a constant.
var (
	argon2InFlight atomic.Int64
	argon2Peak     atomic.Int64
)

func enterArgon2() {
	n := argon2InFlight.Add(1)
	for {
		p := argon2Peak.Load()
		if n <= p || argon2Peak.CompareAndSwap(p, n) {
			return
		}
	}
}

func leaveArgon2() { argon2InFlight.Add(-1) }

func newHashLimiter(cfg HashLimiterConfig) *hashLimiter {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = DefaultHashLimiterConfig.MaxConcurrent
	}
	if cfg.MaxQueue < 0 {
		cfg.MaxQueue = DefaultHashLimiterConfig.MaxQueue
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = DefaultHashLimiterConfig.MaxWait
	}
	return &hashLimiter{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrent)}
}

func (l *hashLimiter) release() { <-l.sem }

// acquire takes a slot. When bounded is false it waits indefinitely (honouring ctx) and never
// returns ErrHashBusy — that is the contract the non-context entry points keep. When bounded is
// true it refuses immediately once MaxQueue callers are already waiting, and gives up after
// MaxWait.
func (l *hashLimiter) acquire(ctx context.Context, bounded bool) (func(), error) {
	// Uncontended fast path: no timer, no queue bookkeeping.
	select {
	case l.sem <- struct{}{}:
		return l.release, nil
	default:
	}

	if bounded {
		// Count this waiter BEFORE looking at the limit, so concurrent arrivals cannot all
		// observe a queue below the cap and enter together.
		if l.waiting.Add(1) > int64(l.cfg.MaxQueue) {
			l.waiting.Add(-1)
			l.rejected.Add(1)
			return nil, ErrHashBusy
		}
		defer l.waiting.Add(-1)

		timer := time.NewTimer(l.cfg.MaxWait)
		defer timer.Stop()
		select {
		case l.sem <- struct{}{}:
			return l.release, nil
		case <-ctx.Done():
			// The client hung up or the request deadline passed. No argon2 memory was
			// allocated; the slot goes to whoever is still waiting.
			return nil, ctx.Err()
		case <-timer.C:
			l.rejected.Add(1)
			return nil, ErrHashBusy
		}
	}

	l.waiting.Add(1)
	defer l.waiting.Add(-1)
	select {
	case l.sem <- struct{}{}:
		return l.release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// -------------------------------------------------------------------------------------
// Process-wide instance
// -------------------------------------------------------------------------------------

var (
	hashLimiterMu sync.Mutex
	hashLimiterP  atomic.Pointer[hashLimiter]
)

func passwordLimiter() *hashLimiter {
	if l := hashLimiterP.Load(); l != nil {
		return l
	}
	hashLimiterMu.Lock()
	defer hashLimiterMu.Unlock()
	if l := hashLimiterP.Load(); l != nil {
		return l
	}
	l := newHashLimiter(DefaultHashLimiterConfig)
	hashLimiterP.Store(l)
	return l
}

// ConfigurePasswordHashing installs the process-wide argon2 concurrency bound and returns a
// function restoring the previous one. Call it once at startup (main wires it from
// CP_PASSWORD_HASH_CONCURRENCY / CP_PASSWORD_HASH_QUEUE); tests use the restore function.
//
// Replacing the limiter does not disturb operations already running under the old one: each holds
// its own release closure over the limiter it acquired from.
func ConfigurePasswordHashing(cfg HashLimiterConfig) func() {
	hashLimiterMu.Lock()
	defer hashLimiterMu.Unlock()
	prev := hashLimiterP.Load()
	hashLimiterP.Store(newHashLimiter(cfg))
	return func() {
		hashLimiterMu.Lock()
		defer hashLimiterMu.Unlock()
		hashLimiterP.Store(prev)
	}
}

// PasswordHashingStats reports the limiter's high-water mark and refusal count. Exported for the
// regression test (docs/25 F01 asks for exactly this assertion) and useful in an operator report.
func PasswordHashingStats() (peakConcurrent int, rejected int64, maxConcurrent int) {
	l := passwordLimiter()
	// peakConcurrent comes from the argon2 call site, NOT from the semaphore — see the
	// instrumentation note above for why that separation is what makes the assertion meaningful.
	return int(argon2Peak.Load()), l.rejected.Load(), l.cfg.MaxConcurrent
}

// ResetPasswordHashingStats zeroes the high-water mark so a test can measure one burst.
func ResetPasswordHashingStats() {
	argon2Peak.Store(0)
	passwordLimiter().rejected.Store(0)
}

// IsHashCapacityError reports whether err means "the process had no argon2 capacity for this
// request" rather than "this credential is wrong". Callers MUST branch on it before their usual
// `err != nil || !ok` credential-failure handling: a saturation answer that is charged to the
// throttle, audited as a failed guess, or answered 401 hands an attacker a way to lock other
// people's accounts out by generating load. Context cancellation counts — the client went away
// while queued, so no credential was ever examined.
func IsHashCapacityError(err error) bool {
	return errors.Is(err, ErrHashBusy) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// WriteHashBusy answers a caller that could not get argon2 capacity. 503 with Retry-After, because
// the credential was never examined: answering 401 would tell the client its password was wrong,
// and answering 429 would suggest the client's own budget was spent when it was not.
func WriteHashBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusServiceUnavailable, "server busy verifying credentials; retry shortly")
}

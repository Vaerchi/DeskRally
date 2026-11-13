package controlplane

// Online-guessing defense for the credential-verifying endpoints: POST /auth/login,
// POST /auth/totp/enroll, POST /auth/totp/confirm and the public POST /enroll/redeem.
//
// Why this exists: a 6-digit TOTP has 10^6 codes and VerifyTOTP accepts the whole ±Skew window, so
// an attacker who already holds the password (credential stuffing, phishing, a leaked hash) expects
// to hit a valid code within a few hundred thousand tries — hours against an unmetered endpoint.
// Throttling, not the code space, is what makes the second factor hold. The same counter blunts
// password spraying and enrollment-token guessing.
//
// Shape: counters are keyed per ACCOUNT and per CLIENT IP, and a request is rejected when EITHER is
// locked out, so one attacker cannot hide behind many accounts nor one account be locked out by a
// single noisy source alone. After FreeAttempts consecutive failures each further failure doubles a
// lockout window (BaseDelay → MaxDelay); a success clears the account's counters, and an idle key
// decays after Reset.
//
// STORAGE: the counters live behind the ThrottleStore seam. Without one (`NewThrottle`, the
// DEV/test default) they are per-process and in-memory — sufficient for a single instance but a
// multi-replica deployment divides the effective limit by the replica count. Production wires
// the Postgres-backed store (`NewStoreThrottle(cfg, NewPgThrottleStore(pool))`,
// pgstore_throttle.go + migrations/0015_throttle.sql) so every replica shares ONE budget; the
// method set is unchanged, so nothing outside this file knows how the counters are stored.
//
// FAILURE POLICY (store-backed): FAIL CLOSED. If the store errors, Allow denies with a short
// fixed Retry-After rather than waving the request through — an attacker must not be able to
// turn a DB blip (or induced load) into an unmetered window. In practice a Postgres outage
// already fails production logins at the credential lookup, so closing here costs legitimate
// users nothing extra. Fail/Reset errors are logged and dropped (nothing sensible to do
// mid-request); the counter simply under-counts that one event.

import (
	"context"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ThrottleConfig tunes the backoff curve.
type ThrottleConfig struct {
	// FreeAttempts is how many consecutive failures are tolerated before any delay applies.
	FreeAttempts int
	// BaseDelay is the lockout after the first failure beyond FreeAttempts; it doubles per
	// further failure up to MaxDelay.
	BaseDelay time.Duration
	MaxDelay  time.Duration
	// Reset is the idle period after which a key's failure count is forgotten.
	Reset time.Duration
}

// DefaultThrottleConfig is the profile wired when a service does not configure one: five free
// attempts, then 2s, 4s, 8s … capped at 15 minutes, with counters decaying after 15 idle minutes.
// Generous enough that a fumbling human never notices, harsh enough that 10^6 codes are
// unreachable.
var DefaultThrottleConfig = ThrottleConfig{
	FreeAttempts: 5,
	BaseDelay:    2 * time.Second,
	MaxDelay:     15 * time.Minute,
	Reset:        15 * time.Minute,
}

type throttleEntry struct {
	failures    int
	lockedUntil time.Time
	lastFailure time.Time
}

// ThrottleStore is the shared-counter storage seam behind a store-backed Throttle. The Throttle
// keeps the policy (free attempts, backoff curve); the store keeps only key → (failures,
// last_failure, locked_until) with the atomicity a multi-writer deployment needs. Implemented by
// PgThrottleStore (pgstore_throttle.go); the in-memory default bypasses this seam entirely.
type ThrottleStore interface {
	// Bump records one failure for key at now and returns the NEW consecutive-failure count.
	// An entry idle since before staleBefore with no live lock restarts at 1 (the idle decay
	// gcLocked performs for the in-memory map). Must be atomic under concurrent writers.
	Bump(ctx context.Context, key string, now, staleBefore time.Time) (int, error)
	// SetLock stores key's lockout deadline (the zero time meaning "no lock").
	SetLock(ctx context.Context, key string, until time.Time) error
	// MaxLockedUntil returns the latest lockout among keys still in the future at now, or the
	// zero time when none is live.
	MaxLockedUntil(ctx context.Context, keys []string, now time.Time) (time.Time, error)
	// Clear forgets keys entirely (successful verification).
	Clear(ctx context.Context, keys []string) error
	// Reserve is the ATOMIC check-and-charge behind Throttle.Reserve: in ONE statement it
	// refuses (admitted=false, retryAfter>0) when key is locked at now, and otherwise records a
	// failure (applying the idle-decay restart), stores the lockout that failure earns under
	// the (free, base, max) policy, and admits. Two replicas reserving the same key serialize
	// on the row lock, so N parallel callers can never all pass a check made before any of
	// them is charged.
	Reserve(ctx context.Context, key string, now, staleBefore time.Time, free int, base, max time.Duration) (admitted bool, retryAfter time.Duration, err error)
	// Unbump refunds one failure charged by Reserve (floor 0) and drops the lock when the
	// remaining count no longer exceeds free.
	Unbump(ctx context.Context, key string, free int) error
	// Cleanup drops entries idle since before staleBefore with no lock live at now, bounding
	// table growth under a distributed attack (the map's gcLocked equivalent).
	Cleanup(ctx context.Context, staleBefore, now time.Time) error
}

// storeThrottleOpTimeout bounds each store round trip. The Throttle methods carry no context
// (their promise is the in-memory method set), so store calls run under their own deadline.
const storeThrottleOpTimeout = 5 * time.Second

// storeFailClosedRetryAfter is the Retry-After Allow answers with when the STORE errors — fail
// closed (see the failure-policy note in the file header), briefly.
const storeFailClosedRetryAfter = 30 * time.Second

// Throttle counts failures per key and converts them into lockout windows. All methods are safe on
// a nil receiver (throttling simply disabled) and safe for concurrent use.
type Throttle struct {
	cfg ThrottleConfig
	// Now is injectable for deterministic tests; defaults to time.Now.
	Now func() time.Time

	// store, when set, replaces the in-memory map (NewStoreThrottle). nil → mu/entries below.
	store ThrottleStore

	mu      sync.Mutex
	entries map[string]*throttleEntry
}

// NewThrottle constructs a Throttle. Zero-valued config fields fall back to
// DefaultThrottleConfig's, so NewThrottle(ThrottleConfig{}) is the default profile.
func NewThrottle(cfg ThrottleConfig) *Throttle {
	if cfg.FreeAttempts <= 0 {
		cfg.FreeAttempts = DefaultThrottleConfig.FreeAttempts
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = DefaultThrottleConfig.BaseDelay
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = DefaultThrottleConfig.MaxDelay
	}
	if cfg.Reset <= 0 {
		cfg.Reset = DefaultThrottleConfig.Reset
	}
	return &Throttle{cfg: cfg, entries: make(map[string]*throttleEntry)}
}

// NewStoreThrottle constructs a Throttle whose counters live in store — the multi-replica
// deployment shape (every replica shares one budget). Same method set and backoff policy as the
// in-memory default.
func NewStoreThrottle(cfg ThrottleConfig, store ThrottleStore) *Throttle {
	t := NewThrottle(cfg)
	t.store = store
	return t
}

func (t *Throttle) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Allow reports whether a request touching all of keys may proceed. When it may not, it returns the
// longest remaining lockout so the caller can send Retry-After.
func (t *Throttle) Allow(keys ...string) (retryAfter time.Duration, ok bool) {
	if t == nil {
		return 0, true
	}
	now := t.now()
	if t.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), storeThrottleOpTimeout)
		defer cancel()
		until, err := t.store.MaxLockedUntil(ctx, keys, now)
		if err != nil {
			log.Printf("throttle store Allow failed (FAILING CLOSED for %ds): %v",
				int(storeFailClosedRetryAfter.Seconds()), err)
			return storeFailClosedRetryAfter, false
		}
		retryAfter = until.Sub(now)
		if until.IsZero() {
			retryAfter = 0
		}
		return retryAfter, retryAfter <= 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked(now)
	for _, k := range keys {
		e, exists := t.entries[k]
		if !exists {
			continue
		}
		if wait := e.lockedUntil.Sub(now); wait > retryAfter {
			retryAfter = wait
		}
	}
	return retryAfter, retryAfter <= 0
}

// Fail records one failed verification against every key, extending the lockout window.
func (t *Throttle) Fail(keys ...string) {
	if t == nil {
		return
	}
	now := t.now()
	if t.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), storeThrottleOpTimeout)
		defer cancel()
		staleBefore := now.Add(-t.cfg.Reset)
		for _, k := range keys {
			failures, err := t.store.Bump(ctx, k, now, staleBefore)
			if err != nil {
				log.Printf("throttle store Bump(%q) failed (failure not counted): %v", k, err)
				continue
			}
			until := time.Time{}
			if over := failures - t.cfg.FreeAttempts; over > 0 {
				until = now.Add(t.delayFor(over))
			}
			if err := t.store.SetLock(ctx, k, until); err != nil {
				log.Printf("throttle store SetLock(%q) failed: %v", k, err)
			}
		}
		// Opportunistic idle decay, the map's gcLocked equivalent — bounded by the index on
		// last_failure and the (already-throttled) failure rate.
		if err := t.store.Cleanup(ctx, staleBefore, now); err != nil {
			log.Printf("throttle store Cleanup failed: %v", err)
		}
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked(now)
	for _, k := range keys {
		e := t.entries[k]
		if e == nil {
			e = &throttleEntry{}
			t.entries[k] = e
		}
		e.failures++
		e.lastFailure = now
		if over := e.failures - t.cfg.FreeAttempts; over > 0 {
			e.lockedUntil = now.Add(t.delayFor(over))
		}
	}
}

// throttleSpec names one key of an atomic Reserve together with its own backoff policy. Zero
// fields fall back to the Throttle's configured profile.
type throttleSpec struct {
	Key  string
	Free int
	Base time.Duration
	Max  time.Duration
}

func (t *Throttle) specPolicy(sp throttleSpec) (int, time.Duration, time.Duration) {
	free, base, max := sp.Free, sp.Base, sp.Max
	if free <= 0 {
		free = t.cfg.FreeAttempts
	}
	if base <= 0 {
		base = t.cfg.BaseDelay
	}
	if max <= 0 {
		max = t.cfg.MaxDelay
	}
	return free, base, max
}

func backoffFor(over int, base, max time.Duration) time.Duration {
	d := float64(base) * math.Pow(2, float64(over-1))
	if d > float64(max) || math.IsInf(d, 1) {
		return max
	}
	return time.Duration(d)
}

// Reserve is the ATOMIC form of Allow followed by Fail, for an endpoint that verifies a secret.
// It refuses when any spec's key is locked (returning the longest remaining lockout, charging
// nothing); otherwise it charges ONE failure to every key up front and admits the caller. The
// caller then calls Release for each key when the verification turns out not to be a credential
// failure (success, or the secret was never examined), and does nothing on a genuine failure:
// the charge already stands.
//
// Why: Allow-then-Fail lets N parallel requests all pass Allow before any Fail lands, so a burst
// bought ~60 guesses against a nominal 5. Here the charge is taken inside the same critical
// section (mutex in memory, one row-locked statement in Postgres) as the check, so at most
// FreeAttempts+1 requests of a burst are admitted before the lock the last of them earns turns
// the rest away.
func (t *Throttle) Reserve(specs ...throttleSpec) (retryAfter time.Duration, ok bool) {
	if t == nil {
		return 0, true
	}
	now := t.now()
	if t.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), storeThrottleOpTimeout)
		defer cancel()
		staleBefore := now.Add(-t.cfg.Reset)
		for i, sp := range specs {
			free, base, max := t.specPolicy(sp)
			admitted, wait, err := t.store.Reserve(ctx, sp.Key, now, staleBefore, free, base, max)
			if err != nil || !admitted {
				for _, done := range specs[:i] {
					f, _, _ := t.specPolicy(done)
					if uerr := t.store.Unbump(ctx, done.Key, f); uerr != nil {
						log.Printf("throttle store Unbump(%q) failed: %v", done.Key, uerr)
					}
				}
				if err != nil {
					log.Printf("throttle store Reserve failed (FAILING CLOSED for %ds): %v",
						int(storeFailClosedRetryAfter.Seconds()), err)
					return storeFailClosedRetryAfter, false
				}
				return wait, false
			}
		}
		return 0, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked(now)
	for _, sp := range specs {
		if e, exists := t.entries[sp.Key]; exists {
			if wait := e.lockedUntil.Sub(now); wait > retryAfter {
				retryAfter = wait
			}
		}
	}
	if retryAfter > 0 {
		return retryAfter, false
	}
	for _, sp := range specs {
		free, base, max := t.specPolicy(sp)
		e := t.entries[sp.Key]
		if e == nil {
			e = &throttleEntry{}
			t.entries[sp.Key] = e
		}
		e.failures++
		e.lastFailure = now
		if over := e.failures - free; over > 0 {
			e.lockedUntil = now.Add(backoffFor(over, base, max))
		}
	}
	return 0, true
}

// Release refunds the charge Reserve took for specs (one failure each, floor zero), dropping a
// lock the refunded count no longer justifies.
func (t *Throttle) Release(specs ...throttleSpec) {
	if t == nil {
		return
	}
	if t.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), storeThrottleOpTimeout)
		defer cancel()
		for _, sp := range specs {
			free, _, _ := t.specPolicy(sp)
			if err := t.store.Unbump(ctx, sp.Key, free); err != nil {
				log.Printf("throttle store Unbump(%q) failed: %v", sp.Key, err)
			}
		}
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, sp := range specs {
		e := t.entries[sp.Key]
		if e == nil {
			continue
		}
		free, _, _ := t.specPolicy(sp)
		e.failures--
		if e.failures <= 0 {
			delete(t.entries, sp.Key)
			continue
		}
		if e.failures <= free {
			e.lockedUntil = time.Time{}
		}
	}
}

// Reset clears the keys' counters — called on a successful verification so a legitimate user who
// mistyped a few times is not left throttled.
func (t *Throttle) Reset(keys ...string) {
	if t == nil {
		return
	}
	if t.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), storeThrottleOpTimeout)
		defer cancel()
		if err := t.store.Clear(ctx, keys); err != nil {
			log.Printf("throttle store Clear failed: %v", err)
		}
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		delete(t.entries, k)
	}
}

// delayFor is BaseDelay doubled per failure beyond the free allowance, capped at MaxDelay. The
// shift is computed in float to avoid overflowing on a long-running attack.
func (t *Throttle) delayFor(over int) time.Duration {
	return backoffFor(over, t.cfg.BaseDelay, t.cfg.MaxDelay)
}

// gcLocked drops keys idle for longer than Reset, so the map cannot grow without bound under a
// distributed attack. Caller holds t.mu.
func (t *Throttle) gcLocked(now time.Time) {
	for k, e := range t.entries {
		if now.Sub(e.lastFailure) > t.cfg.Reset && now.After(e.lockedUntil) {
			delete(t.entries, k)
		}
	}
}

// -------------------------------------------------------------------------------------
// Keys + HTTP helpers
// -------------------------------------------------------------------------------------

// trustProxyForClientIP makes [clientIP] read the rightmost X-Forwarded-For hop instead of
// RemoteAddr. Set ONCE at startup from CP_TRUST_PROXY_IP, before any request is served.
//
// A package-level flag rather than a threaded parameter, deliberately: `clientIP` has 24 call sites
// across auth.go, auth_password_reset.go, auth_user_admin.go, http.go and http_attended.go, spanning
// `AuthService`, `Server` and free functions. Threading a receiver through all of them would be a
// wide refactor of authentication-critical code to carry one deployment-wide boolean that is
// constant for the process's lifetime.
var trustProxyForClientIP atomic.Bool

// trustedProxyNetsForClientIP is the F14-secure companion to trustProxyForClientIP: when non-nil,
// XFF is only honoured for TCP peers whose address is in one of these networks. Nil falls back to
// the old trustProxyForClientIP bool (warn at startup). Same package-level-state rationale as above.
var trustedProxyNetsForClientIP atomic.Pointer[[]*net.IPNet]

// SetTrustProxyForClientIP configures [clientIP] for a deployment behind exactly ONE trusted reverse
// proxy. Call it once, at startup, before serving.
//
// PREFER [Server.SetTrustProxy], which calls this AND sets the allow-list's copy together. This one
// is exported only for tests and for a caller that has no *Server.
func SetTrustProxyForClientIP(trust bool) { trustProxyForClientIP.Store(trust) }

// SetTrustedProxyNets configures the F14-secure proxy restriction for [clientIP]. When nets is
// non-empty, XFF is only honoured from peers in the listed networks; trustProxyForClientIP is also
// set to true so the resolution path is active. Call it once, at startup, before serving.
//
// PREFER [Server.SetTrustedProxies], which calls this AND keeps the allow-list's copy in sync.
func SetTrustedProxyNets(nets []*net.IPNet) {
	if len(nets) == 0 {
		trustedProxyNetsForClientIP.Store(nil)
	} else {
		cp := append([]*net.IPNet(nil), nets...)
		trustedProxyNetsForClientIP.Store(&cp)
		trustProxyForClientIP.Store(true)
	}
}

// SetTrustProxy configures the whole process for a deployment behind exactly ONE trusted reverse
// proxy: the per-tenant IP allow-list AND the per-IP throttles both read the client address from the
// rightmost X-Forwarded-For hop. Call it once, at startup, before serving.
//
// THIS IS WHY THE FIELD IS UNEXPORTED. The two settings must never disagree, and while they were two
// independent assignments they did: `srv.TrustProxyIP = true` was wired at startup and the throttle's
// copy was not, so a deployment behind Caddy allow-listed on the real client while metering every
// login attempt against the proxy's container address. All per-IP buckets collapsed into one, and
// per-source brute-force protection was gone with nothing to show it.
//
// A setter is not merely tidier here — it removes the failure mode. There is now no way to arm one
// half from outside this package, and forgetting the call entirely leaves BOTH off, which is the
// safe direction (RemoteAddr, no header trust) rather than a silent asymmetry.
//
// PREFER [Server.SetTrustedProxies] when deploying the F14-secure path with CP_TRUSTED_PROXIES.
func (s *Server) SetTrustProxy(trust bool) {
	s.trustProxyIP = trust
	SetTrustProxyForClientIP(trust)
}

// SetTrustedProxies enables the F14-secure XFF path: XFF is honoured only from TCP peers whose
// address falls in one of the given networks. It sets the per-IP throttle nets, arms the allow-list's
// copy, and implies trustProxyIP=true (the proxy-aware path must be active for any of this to work).
// Call once, at startup, before serving. PREFER this over SetTrustProxy for new deployments.
func (s *Server) SetTrustedProxies(nets []*net.IPNet) {
	s.trustedProxyNets = nets
	s.trustProxyIP = len(nets) > 0
	SetTrustedProxyNets(nets)
	SetTrustProxyForClientIP(len(nets) > 0)
	if s.IPAllowlist != nil {
		s.IPAllowlist.trustedProxyNets = nets
		s.IPAllowlist.trustProxy = len(nets) > 0
	}
}

// clientIP is the throttling identity of a request's source.
//
// By default it is the RemoteAddr host ONLY. X-Forwarded-For is not trusted, because it is
// attacker-settable and honouring it blindly would let one client mint an unlimited number of
// throttle identities.
//
// BEHIND A REVERSE PROXY that default inverts into a different failure, which is why
// CP_TRUST_PROXY_IP exists: every request arrives with the proxy's address, so every per-IP bucket
// collapses into ONE. The login throttle then meters all users together — one attacker hammering
// `/auth/login` locks out the entire deployment, and per-source brute-force protection is gone.
// That is not hypothetical for this product: docs/18's topology puts Caddy in front of everything.
//
// The header is safe to read in that mode because [resolveClientIP] takes the RIGHTMOST hop — the
// one the trusted proxy appended. Values an attacker injects appear to its left and are ignored. Use
// CP_TRUSTED_PROXIES (F14) to further restrict which peers may set the header.
func clientIP(r *http.Request) string {
	if trustProxyForClientIP.Load() {
		var nets []*net.IPNet
		if p := trustedProxyNetsForClientIP.Load(); p != nil {
			nets = *p
		}
		if ip := resolveClientIP(r, true, nets); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// accountSeparator delimits the tenant from the account inside a per-account key. It must be a
// character that cannot appear in either component (so "a" + "b|c" and "a|b" + "c" stay distinct)
// AND that PostgreSQL can store.
//
// It used to be U+0000, which satisfied only the first requirement. PostgreSQL `text` cannot
// represent a NUL at all — a key carrying one fails the insert with
// `invalid byte sequence for encoding "UTF8": 0x00` (SQLSTATE 22021) — so against the PG-backed
// store (the production posture; the in-memory map used by most tests accepts NUL happily) EVERY
// per-account Bump errored, and because the throttle fails CLOSED that surfaced as a permanent 429
// on the metered endpoints. U+001F (UNIT SEPARATOR) is the same kind of delimiter, is equally
// absent from emails, tenant ids and uuids, and is storable.
//
// Changing it invalidates any counter rows written under the old form. That is harmless: throttle
// counters are ephemeral rate-limit state, and the old rows could never have been written anyway.
const accountSeparator = "\x1f"

// accountKey builds a per-account throttle key. Emails are lowercased so case variations do not
// buy an attacker a fresh budget.
//
// CONTRACT: no component may itself contain accountSeparator. Nothing enforces it, and violating it
// makes the key ambiguous — ("t1", "x\x1fy") and ("t1\x1fx", "y") would collide, sharing a budget
// between two accounts. Every real component is a uuid, an email or a base64url session id, none of
// which can contain U+001F; a caller that needs to key on TWO identifiers must put the extra one in
// `kind` (see passwordThrottleKey) rather than concatenating it into `account`.
func accountKey(kind, tenant, account string) string {
	return kind + ":acct:" + tenant + accountSeparator + strings.ToLower(account)
}

// ipKey builds a per-source throttle key.
//
// An IPv6 source is keyed by its /64 (the smallest block a subscriber or hosting customer is
// handed, so one /64 holds 2^64 addresses an attacker can rotate through for free); an IPv4
// source, and anything that does not parse as an IP, is keyed by the whole string.
func ipKey(kind, ip string) string { return kind + ":ip:" + throttleSource(ip) }

// throttleSource is the throttling identity of a client address: the /64 prefix for IPv6, the
// address itself otherwise (IPv4-mapped IPv6 counts as IPv4).
func throttleSource(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ip
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is6() {
		if p, perr := addr.Prefix(64); perr == nil {
			return p.String()
		}
	}
	return addr.String()
}

// writeThrottled answers a rate-limited request: 429 with Retry-After (seconds) and the same
// opaque message for every endpoint, so a prober learns nothing beyond "wait".
func writeThrottled(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(math.Ceil(retryAfter.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, ErrTooManyAttempts.Error())
}

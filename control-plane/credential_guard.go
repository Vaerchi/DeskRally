package controlplane

// Bounding the database work an ANONYMOUS client can cause with INVALID credentials (docs/26, the
// residual of docs/25 F09/F18; audit-2026-09-07 "POST /auth/logout").
//
// THE PROBLEM. Two routes resolve a presented bearer secret against the database before they know it is
// worth anything, and neither was metered:
//
//   - the protected chain: a GET carrying `Cookie: cp_session=<garbage>` (or `Authorization: Bearer
//     <garbage>`) is CSRF-exempt, reaches authMiddleware and costs one SECURITY DEFINER lookup
//     (cp_session_by_token) per request; an `rmt_api_…` bearer costs cp_api_token_resolve instead;
//   - POST /auth/logout with an Authorization header (no cookie, so CSRF is skipped) costs Validate +
//     Revoke per request.
//
// A flood of these needs no account, no password and no valid anything, and it lands on the same
// connection pool every legitimate request shares.
//
// THE DEFENCE has three layers, cheapest first, none of which touches the database:
//
//  1. SHAPE. Every secret this process mints has a fixed shape: a session token (plain, remembered or
//     OIDC-issued) is 32 random bytes as 43 base64url characters; an API token is "rmt_api_" plus the same
//     43. Anything else cannot be a credential and is refused before any store call.
//  2. A PER-SOURCE BUDGET of FAILED lookups. Each lookup of an unproven token RESERVES one unit of its
//     source's budget before it runs and refunds it if the credential turns out to be good, so successes
//     never consume it and a burst of concurrent requests cannot all pass a check made before any of them
//     is charged. Once the budget is gone the source gets 429 + Retry-After with NO store call until the
//     window rolls over. In memory on purpose: the DB-backed Throttle would itself be a database write per
//     failure — the very cost being bounded.
//  3. A GLOBAL CAP on concurrent unproven lookups (small waiting room, then 503), so many sources together
//     cannot exhaust the pool either; the per-source budget bounds one source, this bounds the sum.
//
// THE NAT TRADE-OFF. The budget is per source address, and a source can be shared by an attacker and a
// legitimate user (an office NAT, a carrier-grade NAT). So the gates apply only to a token that has NOT
// recently authenticated: a token that validated within validTTL is let through to its (normal) lookup
// even when its source is over budget or the global cap is full. That exemption is not a bypass of the
// authenticator — the lookup still runs, so a revoked session is still refused — it only means "do not
// meter a credential whose holder already proved it". What it costs: a holder of one VALID token can keep
// that token's lookups unmetered (they are authenticated work, bounded by whatever bounds an
// authenticated caller, and were unmetered before this change too). What remains degraded during an
// attack from a shared address: a legitimate user's FIRST request with a token this process has not seen
// succeed (a session started on another replica, or one idle past validTTL) waits out the window — a login
// on this replica registers its token (NoteValid), which covers the common case.

import (
	"container/list"
	"context"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults of the guard. The failure budget is generous for a human (an expired tab polling a handful of
// times is a handful of failures) and negligible for a database (60 indexed lookups a minute).
const (
	DefaultCredentialMaxFailures = 60
	DefaultCredentialWindow      = time.Minute
	// DefaultCredentialMaxSources bounds the tracked sources. 20 000 entries is ~2 MB; an attacker with
	// more addresses than that evicts the oldest windows, and is then bounded by the global cap instead.
	DefaultCredentialMaxSources = 20000
	DefaultCredentialQueueWait  = 500 * time.Millisecond
	DefaultCredentialValidTTL   = 10 * time.Minute
	DefaultCredentialValidMax   = 8192
	// credentialBusyRetryAfter is the Retry-After of the 503: the waiting room already waited
	// DefaultCredentialQueueWait, so a second is an honest "try again shortly".
	credentialBusyRetryAfter = time.Second
)

// ErrCredentialBudget / ErrCredentialBusy are the guard's two refusals. They are returned wrapped in a
// credentialRefusal that carries the Retry-After.
var (
	ErrCredentialBudget = errors.New("too many invalid credentials from this source")
	ErrCredentialBusy   = errors.New("credential lookups are busy")
)

// credentialRefusal is a refusal to look a credential up at all (as opposed to a lookup that said no).
type credentialRefusal struct {
	err        error
	retryAfter time.Duration
}

func (c *credentialRefusal) Error() string { return c.err.Error() }
func (c *credentialRefusal) Unwrap() error { return c.err }

// credentialRefusalOf returns the refusal inside err, or nil.
func credentialRefusalOf(err error) *credentialRefusal {
	var c *credentialRefusal
	if errors.As(err, &c) {
		return c
	}
	return nil
}

// writeCredentialRefusal answers a refusal: 429 for the budget (the same body and header as every other
// throttle), 503 for the global cap. Neither names which credential was presented.
func writeCredentialRefusal(w http.ResponseWriter, c *credentialRefusal) {
	if errors.Is(c.err, ErrCredentialBusy) {
		secs := int((c.retryAfter + time.Second - 1) / time.Second)
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusServiceUnavailable, "temporarily busy")
		return
	}
	writeThrottled(w, c.retryAfter)
}

// CredentialGuardConfig tunes the guard. Zero fields take the defaults above.
type CredentialGuardConfig struct {
	MaxFailures int
	Window      time.Duration
	MaxSources  int
	// MaxLookups is the global cap on concurrent unproven lookups; MaxQueue how many more may wait for a
	// slot (at most QueueWait each) before the 503. A negative MaxQueue means no waiting room at all.
	MaxLookups int
	MaxQueue   int
	QueueWait  time.Duration
	ValidTTL   time.Duration
	ValidMax   int
	// Now and Logf are injectable for tests (Logf defaults to log.Printf).
	Now  func() time.Time
	Logf func(format string, args ...any)
}

// CredentialGuard is the shape check, per-source failure budget, global lookup cap and recently-valid cache
// described above. A nil *CredentialGuard disables all of it (every method is nil-safe), the same idiom as
// Throttle.
type CredentialGuard struct {
	cfg CredentialGuardConfig

	mu      sync.Mutex
	sources map[string]*list.Element // source key -> element holding *budgetEntry
	order   *list.List               // oldest window first: eviction takes the front
	valid   map[[32]byte]*list.Element
	validLL *list.List // oldest insertion first

	slots  chan struct{}
	queued atomic.Int64

	// inflight: token hashes whose FIRST lookup has an elected leader now (capped at MaxLookups+MaxQueue
	// entries, see beginFirstLookup), so concurrent requests with the same unseen token wait for it, each in a seat of
	// the waiting room, instead of each taking a slot and a budget unit.
	inflight map[[32]byte]chan struct{}
}

type budgetEntry struct {
	key         string
	windowStart time.Time
	count       int
	// warned: this window's exhaustion was already logged (one line per source per window).
	warned bool
}

type validEntry struct {
	hash    [32]byte
	expires time.Time
}

// DefaultCredentialLookups sizes the global cap from the database pool: a quarter of it (min 2), so
// anonymous garbage can never hold more than a quarter of the connections every other request needs.
func DefaultCredentialLookups(poolMax int) int {
	n := poolMax / 4
	if n < 2 {
		n = 2
	}
	return n
}

// NewCredentialGuard builds a guard; see CredentialGuardConfig.
func NewCredentialGuard(cfg CredentialGuardConfig) *CredentialGuard {
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = DefaultCredentialMaxFailures
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultCredentialWindow
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = DefaultCredentialMaxSources
	}
	if cfg.MaxLookups <= 0 {
		cfg.MaxLookups = DefaultCredentialLookups(16)
	}
	if cfg.MaxQueue == 0 {
		cfg.MaxQueue = 2 * cfg.MaxLookups
	}
	if cfg.MaxQueue < 0 {
		cfg.MaxQueue = 0
	}
	if cfg.QueueWait <= 0 {
		cfg.QueueWait = DefaultCredentialQueueWait
	}
	if cfg.ValidTTL <= 0 {
		cfg.ValidTTL = DefaultCredentialValidTTL
	}
	if cfg.ValidMax <= 0 {
		cfg.ValidMax = DefaultCredentialValidMax
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &CredentialGuard{
		cfg:      cfg,
		sources:  make(map[string]*list.Element),
		order:    list.New(),
		valid:    make(map[[32]byte]*list.Element),
		validLL:  list.New(),
		slots:    make(chan struct{}, cfg.MaxLookups),
		inflight: make(map[[32]byte]chan struct{}),
	}
}

// -------------------------------------------------------------------------------------
// Shape
// -------------------------------------------------------------------------------------

// sessionTokenLen is len(base64.RawURLEncoding of 32 bytes): newSessionToken, which mints plain,
// remembered and OIDC sessions alike (IssueOIDCSession calls it too). The trailing-bits constraint of the
// last character is deliberately NOT enforced: Go's decoder does not require it and a check stricter than
// the minting code is a way to reject a good token for no gain.
const sessionTokenLen = 43

func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// validSessionTokenShape reports whether tok could be something newSessionToken minted.
func validSessionTokenShape(tok string) bool {
	return len(tok) == sessionTokenLen && isBase64URL(tok)
}

// validAPITokenShape reports whether tok could be something newAPITokenSecret minted:
// APITokenPrefix + newEnrollmentSecret (the same 43-character encoding).
func validAPITokenShape(tok string) bool {
	rest, ok := strings.CutPrefix(tok, APITokenPrefix)
	return ok && len(rest) == sessionTokenLen && isBase64URL(rest)
}

// presentedCredential names the secret the authenticators would look up for r, mirroring them exactly:
// an Authorization bearer carrying the API prefix is an API token (headerBearerToken, header only, wins
// even when a cookie is present); anything else is a session token (bearerToken: cookie first, then the
// header). "" = no credential, which costs no lookup.
func presentedCredential(r *http.Request, cookieName string) (tok string, api bool) {
	if h := headerBearerToken(r); strings.HasPrefix(h, APITokenPrefix) {
		return h, true
	}
	return bearerToken(r, cookieName), false
}

// -------------------------------------------------------------------------------------
// Source
// -------------------------------------------------------------------------------------

// credentialSource is the budget key of r: the trusted source address (sourceIPMiddleware, i.e.
// resolveClientIP under the configured proxy trust; clientIP as the fallback outside that middleware) —
// never a header the client picked. IPv6 sources collapse to their /64, since a single subscriber owns at
// least that and per-address keys would give one attacker 2^64 budgets AND flood the table.
func credentialSource(r *http.Request) string {
	ip := sourceIPFrom(r.Context())
	if ip == "" {
		ip = clientIP(r)
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "unknown"
	}
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.Masked().String()
		}
	}
	return a.String()
}

// -------------------------------------------------------------------------------------
// Lookup
// -------------------------------------------------------------------------------------

// credentialFailure reports whether err from a lookup counts against the source. It is an ALLOW-list of the
// errors that mean "this credential is not valid" — and nothing else: a suspended tenant or disabled user
// (the credential WAS good), a caller that went away, and above all any INFRASTRUCTURE error (connection
// refused, pool exhausted, protocol error, a failed profile read) are not the presenter's fault. A deny-list
// would charge those too, and a database blip of a few seconds would then burn the budget of every
// legitimate source — and, for a known token, forget it — turning an outage into a 429 lockout that outlasts
// it. An error this function has never heard of is therefore treated as infrastructure (refund, keep the
// token known): the fail-safe direction for availability, and it costs nothing in protection, because a
// credential verdict always arrives as one of the sentinels below.
func credentialFailure(err error) bool {
	switch {
	case errors.Is(err, ErrInvalidCredentials),
		errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrSessionExpired), errors.Is(err, ErrSessionIdle),
		errors.Is(err, ErrSessionRevoked), errors.Is(err, ErrSessionCredentialStale),
		errors.Is(err, ErrAPITokenNotFound), errors.Is(err, ErrNoUser):
		return true
	}
	return false
}

// Lookup runs do — the store work that resolves tok — under the guard. api selects the shape tok must
// have. It returns ErrInvalidCredentials without calling do when tok cannot be a credential, a
// credentialRefusal without calling do when the source is over budget or the global cap is full, and
// otherwise do's own error after charging or refunding the budget.
func (g *CredentialGuard) Lookup(r *http.Request, tok string, api bool, do func() error) error {
	if g == nil {
		return do()
	}
	if (api && !validAPITokenShape(tok)) || (!api && !validSessionTokenShape(tok)) {
		return ErrInvalidCredentials
	}
	h := HashToken(tok)
	var hash [32]byte
	copy(hash[:], h)
	src := credentialSource(r)

	known := g.isValid(hash)
	if !known {
		// Election is atomic: of N simultaneous first requests with one token, exactly one leads.
		end, leading, leader := g.beginFirstLookup(hash)
		if leader {
			// end runs on every exit (refusals included), waking the followers.
			defer end()
		} else if leading != nil && g.awaitFirstLookup(r.Context(), leading) {
			// Another request is already resolving this very token (a page load fires ~10 parallel XHRs
			// with one session): it paid for the lookup, and if the token is good it is now known, so this
			// request costs a slot and a budget unit of nobody's. If not, it goes through the gates below.
			known = g.isValid(hash)
		}
	}
	var resv budgetReservation
	if !known {
		var retry time.Duration
		var ok bool
		resv, retry, ok = g.reserve(src)
		if !ok {
			return &credentialRefusal{err: ErrCredentialBudget, retryAfter: retry}
		}
		release, ok := g.acquire(r.Context())
		if !ok {
			g.refund(resv)
			return &credentialRefusal{err: ErrCredentialBusy, retryAfter: credentialBusyRetryAfter}
		}
		defer release()
	}

	err := do()
	switch {
	case err == nil:
		g.markValid(hash)
		g.refund(resv)
	case !credentialFailure(err):
		g.refund(resv)
	case known:
		// A token that WAS good no longer is (revoked, expired, idle). It was let past the gates, so it
		// reserved nothing; charge the failure now and stop exempting it.
		g.forget(hash)
		g.charge(src)
	}
	return err
}

// NoteValid registers a token the server has just minted (login) as recently valid, so its holder keeps
// working from a source that is over budget. Nil-safe.
func (g *CredentialGuard) NoteValid(tok string) {
	if g == nil || !validSessionTokenShape(tok) {
		return
	}
	var hash [32]byte
	copy(hash[:], HashToken(tok))
	g.markValid(hash)
}

// Forget drops a token from the recently-valid set (logout). Nil-safe.
func (g *CredentialGuard) Forget(tok string) {
	if g == nil {
		return
	}
	var hash [32]byte
	copy(hash[:], HashToken(tok))
	g.forget(hash)
}

// -------------------------------------------------------------------------------------
// Budget
// -------------------------------------------------------------------------------------

// budgetReservation names the unit a lookup reserved so a success can give back exactly that unit, and
// not one from a later window.
type budgetReservation struct {
	key         string
	windowStart time.Time
	held        bool
}

// entryLocked returns key's entry for the window containing now, starting a fresh window (and evicting
// the oldest sources at the cap) when there is none or it has lapsed. g.mu must be held.
func (g *CredentialGuard) entryLocked(key string, now time.Time) *budgetEntry {
	if el, ok := g.sources[key]; ok {
		e := el.Value.(*budgetEntry)
		if now.Sub(e.windowStart) < g.cfg.Window {
			return e
		}
		e.windowStart, e.count, e.warned = now, 0, false
		g.order.MoveToBack(el)
		return e
	}
	for len(g.sources) >= g.cfg.MaxSources {
		front := g.order.Front()
		if front == nil {
			break
		}
		delete(g.sources, front.Value.(*budgetEntry).key)
		g.order.Remove(front)
	}
	e := &budgetEntry{key: key, windowStart: now}
	g.sources[key] = g.order.PushBack(e)
	return e
}

// reserve charges one unit to src, or refuses with the time left in its window when none remain. A refusal
// charges nothing and does not extend the window.
func (g *CredentialGuard) reserve(src string) (budgetReservation, time.Duration, bool) {
	now := g.cfg.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entryLocked(src, now)
	if e.count >= g.cfg.MaxFailures {
		if !e.warned {
			e.warned = true
			// Visible on purpose: a source that exhausts its budget is an attacker, a poll loop with a
			// revoked API token — or a MISCONFIGURED proxy trust that collapsed every user onto the
			// proxy's address (then this line names the proxy, and says so). Nothing else would show it.
			g.cfg.Logf("control-plane: credential failure budget exhausted for source %s (%d failed lookups per %s); "+
				"429 until the window ends. If this is a reverse proxy or NAT address, check the trusted-proxy configuration",
				src, g.cfg.MaxFailures, g.cfg.Window)
		}
		// writeThrottled rounds this up to a whole second and never below 1, so no floor is needed here.
		retry := e.windowStart.Add(g.cfg.Window).Sub(now)
		return budgetReservation{}, retry, false
	}
	e.count++
	return budgetReservation{key: src, windowStart: e.windowStart, held: true}, 0, true
}

// refund gives a reservation back, unless its window has already rolled over.
func (g *CredentialGuard) refund(r budgetReservation) {
	if !r.held {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if el, ok := g.sources[r.key]; ok {
		if e := el.Value.(*budgetEntry); e.windowStart.Equal(r.windowStart) && e.count > 0 {
			e.count--
		}
	}
}

// charge records one failure for src that was never reserved (a known token that stopped validating).
func (g *CredentialGuard) charge(src string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.entryLocked(src, g.cfg.Now()).count++
}

// trackedSources reports how many sources the budget holds (tests: the memory bound).
func (g *CredentialGuard) trackedSources() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.sources)
}

// -------------------------------------------------------------------------------------
// Recently-valid set
// -------------------------------------------------------------------------------------

func (g *CredentialGuard) isValid(h [32]byte) bool {
	now := g.cfg.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	el, ok := g.valid[h]
	if !ok {
		return false
	}
	if !now.Before(el.Value.(*validEntry).expires) {
		g.validLL.Remove(el)
		delete(g.valid, h)
		return false
	}
	return true
}

func (g *CredentialGuard) markValid(h [32]byte) {
	now := g.cfg.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if el, ok := g.valid[h]; ok {
		el.Value.(*validEntry).expires = now.Add(g.cfg.ValidTTL)
		g.validLL.MoveToBack(el)
		return
	}
	for len(g.valid) >= g.cfg.ValidMax {
		front := g.validLL.Front()
		if front == nil {
			break
		}
		delete(g.valid, front.Value.(*validEntry).hash)
		g.validLL.Remove(front)
	}
	g.valid[h] = g.validLL.PushBack(&validEntry{hash: h, expires: now.Add(g.cfg.ValidTTL)})
}

func (g *CredentialGuard) forget(h [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if el, ok := g.valid[h]; ok {
		g.validLL.Remove(el)
		delete(g.valid, h)
	}
}

// -------------------------------------------------------------------------------------
// Global cap
// -------------------------------------------------------------------------------------

// acquire takes a lookup slot: immediately when one is free, else after waiting up to QueueWait in a room
// that holds at most MaxQueue waiters. false = busy (the 503).
func (g *CredentialGuard) acquire(ctx context.Context) (release func(), ok bool) {
	release = func() { <-g.slots }
	select {
	case g.slots <- struct{}{}:
		return release, true
	default:
	}
	if g.queued.Add(1) > int64(g.cfg.MaxQueue) {
		g.queued.Add(-1)
		return nil, false
	}
	defer g.queued.Add(-1)
	t := time.NewTimer(g.cfg.QueueWait)
	defer t.Stop()
	select {
	case g.slots <- struct{}{}:
		return release, true
	case <-t.C:
	case <-ctx.Done():
	}
	return nil, false
}

// beginFirstLookup elects the leader of h's first lookup in ONE critical section, so two simultaneous
// arrivals can never both lead. leader=true: the caller registered h and must call done on every exit (it
// unregisters h and wakes the followers). leader=false: another request leads, and done is the leader's
// wake channel for awaitFirstLookup. The map is capped at MaxLookups+MaxQueue entries in the same critical
// section (only that many leaders can be admitted at once anyway): with it full, the caller gets neither
// (nil, nil, false) and goes through the ordinary gates without coalescing.
func (g *CredentialGuard) beginFirstLookup(h [32]byte) (done func(), leading <-chan struct{}, leader bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ch, ok := g.inflight[h]; ok {
		return nil, ch, false
	}
	if len(g.inflight) >= g.cfg.MaxLookups+g.cfg.MaxQueue {
		return nil, nil, false
	}
	ch := make(chan struct{})
	g.inflight[h] = ch
	return func() {
		g.mu.Lock()
		delete(g.inflight, h)
		g.mu.Unlock()
		close(ch)
	}, nil, true
}

// awaitFirstLookup waits (at most QueueWait, or until ctx ends) for the leader to close leading and reports
// whether it waited. A follower occupies a seat of the SAME waiting room acquire uses, so followers are
// bounded by MaxQueue like any other waiter; with no seat free it does not wait at all (false) and goes
// through the ordinary gates instead, charged and capped like any other unproven lookup. Likewise after
// the wait, if the leader failed.
func (g *CredentialGuard) awaitFirstLookup(ctx context.Context, leading <-chan struct{}) bool {
	if g.queued.Add(1) > int64(g.cfg.MaxQueue) {
		g.queued.Add(-1)
		return false
	}
	defer g.queued.Add(-1)
	t := time.NewTimer(g.cfg.QueueWait)
	defer t.Stop()
	select {
	case <-leading:
	case <-t.C:
	case <-ctx.Done():
	}
	return true
}

// -------------------------------------------------------------------------------------
// Authenticator front
// -------------------------------------------------------------------------------------

// GuardedAuthenticator runs Next under Guard. It is wired OUTERMOST (in front of APITokenAuthenticator),
// so every credential the protected chain would look up passes the guard first. A request with no
// credential goes straight to Next, which answers it without a store call.
type GuardedAuthenticator struct {
	Next       Authenticator
	Guard      *CredentialGuard
	CookieName string
}

var _ Authenticator = (*GuardedAuthenticator)(nil)

// Authenticate implements Authenticator.
func (a *GuardedAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	name := a.CookieName
	if name == "" {
		name = DefaultSessionCookie
	}
	tok, api := presentedCredential(r, name)
	if tok == "" {
		return a.Next.Authenticate(r)
	}
	var p *Principal
	err := a.Guard.Lookup(r, tok, api, func() error {
		var e error
		p, e = a.Next.Authenticate(r)
		return e
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

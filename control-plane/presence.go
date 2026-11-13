package controlplane

// Machine presence (docs/01 §4) — teaching the console which machines are actually online.
//
// The `machine` table records who is ENROLLED. Who is CONNECTED is a fact only the signaling
// server has: an agent holds its live WebSocket there, and is reachable exactly when the broker
// can find it in its registry. So presence is READ from signaling
// (GET /internal/presence, service-token gated — server/signaling/presence.go) rather than
// approximated from an agent heartbeat the control plane would have to invent a new authenticated
// endpoint to receive.
//
// TENANT SCOPING — the load-bearing rule. The signaling registry is cross-tenant by construction,
// so the feed returns device ids from EVERY tenant. This package never exposes that list: a
// caller intersects it with the tenant's own RLS-scoped machine rows and reports presence only for
// ids it already owns (see Server.handleListMachines). An id in the feed that the tenant does not
// own is simply not in the answer — it is never echoed, counted, or distinguished from an id that
// does not exist. That intersection is what keeps one MSP from enumerating another's fleet through
// a shared signaling server.
//
// FAILING SOFT, deliberately. Presence is a console convenience, not a security control: nothing is
// authorized on it and nothing is denied for lack of it. When signaling is unreachable, the token
// is unset, or the request times out, the source reports ErrPresenceUnavailable and the machine
// listing degrades to "presence unknown" instead of failing the request. That is the opposite of
// how this repo treats an authorization dependency (which fails CLOSED) — and it is the right call
// here precisely because presence grants nothing.
//
// One nuance since the os refresh: the feed now also CARRIES agent-asserted inventory (each
// device's `os` string, announced at register_agent), which annotatePresence PERSISTS into
// machine.os — the column is otherwise write-once at enrollment and goes stale on the first OS
// upgrade. That does not change the authorization posture (nothing reads machine.os to decide
// anything), but it does mean presence data now outlives the snapshot: the bound (255 bytes,
// enforced again at the store) and the tenant intersection below are what keep a compromised or
// misconfigured signaling server from writing garbage into another tenant's rows.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ErrPresenceUnavailable is returned when the presence feed could not be consulted. Callers treat
// it as "unknown", never as "offline" — reporting a live machine as offline because signaling was
// briefly unreachable would send a technician chasing a phantom outage.
var ErrPresenceUnavailable = errors.New("presence feed unavailable")

// Presence is the parsed feed: the set of device ids currently connected, with each one's last
// heartbeat. Keyed by device id for the O(1) intersection the listing does.
type Presence struct {
	// Online maps device id → the moment signaling last heard from it.
	Online map[string]time.Time
	// OSByDevice maps device id → the agent-asserted os description, for devices that announced
	// one (absent key = agent sent none; empty strings are never stored). Inventory input for the
	// machine.os refresh, nothing more.
	OSByDevice map[string]string
	// VersionByDevice maps device id -> the agent-asserted build identity, for devices that
	// announced one (absent key = agent sent none; empty strings are never stored). Inventory input
	// for the machine.agent_version refresh (migrations/0039), nothing more. The absent-vs-empty
	// distinction is load-bearing: a silent agent must never blank a version already recorded.
	VersionByDevice map[string]string
	// RequireByDevice maps device id → the agent-asserted require_session_policy flag, for devices
	// that ACTUALLY REPORTED one. An absent key means the agent said nothing — a pre-loop-86 build,
	// a controller, or a dev peer — and is emphatically NOT the same as a stored `false`: writing
	// false for a silent agent would clear a flag its operator had set. Input for the
	// machine.require_session_policy refresh (migrations/0037), nothing more.
	RequireByDevice map[string]bool
	// GrantPinnedByDevice maps device id → the agent-reported "grant issuer key pinned" posture, only for
	// devices that reported (audit #9). Live-only: shown on the machine list, never stored or authorized on.
	GrantPinnedByDevice map[string]bool
	// PolicyRequiredByDevice: same, for the agent-reported session_policy_required posture.
	PolicyRequiredByDevice map[string]bool
	// LoggedInUserByDevice maps device id → the agent-asserted interactive-session user (e.g.
	// "CORP\alice"), for devices that announced one (absent key = agent sent none; empty strings are
	// never stored). Input for the machine.logged_in_user refresh (migrations/0048). The
	// absent-vs-value distinction is load-bearing: a silent agent must never blank a user already
	// recorded — an interactive user does not become "nobody" just because the agent rebooted.
	LoggedInUserByDevice map[string]string
	// AsOf is signaling's clock when the snapshot was taken.
	AsOf time.Time
}

// IsOnline reports whether a device id was in the snapshot. A nil Presence answers false, so a
// caller that skipped the lookup does not need a nil check at every use.
func (p *Presence) IsOnline(deviceID string) bool {
	if p == nil || p.Online == nil {
		return false
	}
	_, ok := p.Online[deviceID]
	return ok
}

// LastSeen returns signaling's heartbeat stamp for a device, if it is online.
func (p *Presence) LastSeen(deviceID string) (time.Time, bool) {
	if p == nil || p.Online == nil {
		return time.Time{}, false
	}
	t, ok := p.Online[deviceID]
	return t, ok
}

// ObservedOS returns the os description a device announced, if it announced one.
func (p *Presence) ObservedOS(deviceID string) (string, bool) {
	if p == nil || p.OSByDevice == nil {
		return "", false
	}
	os, ok := p.OSByDevice[deviceID]
	return os, ok
}

// ObservedAgentVersion returns the build identity a device announced, and whether it announced one
// at all. The second return is the guard that stops an older agent's silence from blanking a stored
// version — the same rule RequiresSessionPolicy exists to enforce for the floor flag.
func (p *Presence) ObservedAgentVersion(deviceID string) (string, bool) {
	if p == nil || p.VersionByDevice == nil {
		return "", false
	}
	v, ok := p.VersionByDevice[deviceID]
	return v, ok
}

// RequiresSessionPolicy returns the floor flag a device announced, and whether it announced one at
// all. The second return is the whole point: only a device that REPORTED may cause a write, so an
// older agent's silence can never clear machine.require_session_policy.
func (p *Presence) RequiresSessionPolicy(deviceID string) (bool, bool) {
	if p == nil || p.RequireByDevice == nil {
		return false, false
	}
	v, ok := p.RequireByDevice[deviceID]
	return v, ok
}

// GrantKeyPinned returns the posture a device reported and whether it reported one.
func (p *Presence) GrantKeyPinned(deviceID string) (bool, bool) {
	if p == nil || p.GrantPinnedByDevice == nil {
		return false, false
	}
	v, ok := p.GrantPinnedByDevice[deviceID]
	return v, ok
}

// SessionPolicyRequired returns the require_session_policy posture a device reported, and whether it did.
func (p *Presence) SessionPolicyRequired(deviceID string) (bool, bool) {
	if p == nil || p.PolicyRequiredByDevice == nil {
		return false, false
	}
	v, ok := p.PolicyRequiredByDevice[deviceID]
	return v, ok
}

// ObservedLoggedInUser returns the interactive-session user a device announced, and whether it
// announced one at all. The second return is the guard that stops a silent agent from blanking a
// logged_in_user already recorded — the same rule ObservedAgentVersion enforces for the version.
func (p *Presence) ObservedLoggedInUser(deviceID string) (string, bool) {
	if p == nil || p.LoggedInUserByDevice == nil {
		return "", false
	}
	u, ok := p.LoggedInUserByDevice[deviceID]
	return u, ok
}

// PresenceSource is the seam for reading the feed. Production wires SignalingPresenceSource;
// tests wire InMemoryPresenceSource. Following the repo's interface-plus-fake pattern, and so the
// listing handler can be tested with no signaling server at all.
type PresenceSource interface {
	// FetchPresence returns the current snapshot, or ErrPresenceUnavailable.
	FetchPresence(ctx context.Context) (*Presence, error)
}

// -------------------------------------------------------------------------------------
// SignalingPresenceSource — the HTTP client for GET /internal/presence.
// -------------------------------------------------------------------------------------

// presenceEntry / presenceResponse mirror server/signaling/presence.go's wire types exactly.
type presenceEntry struct {
	DeviceID       string `json:"device_id"`
	LastSeenUnixMs int64  `json:"last_seen_unix_ms"`
	// OS is omitted by signaling when the agent announced none; absent decodes as "".
	OS string `json:"os"`
	// RequireSessionPolicy is omitted by signaling when the agent announced none. A POINTER so
	// absent decodes as nil rather than false — see Presence.RequireByDevice for why the two must
	// stay distinguishable all the way through.
	RequireSessionPolicy  *bool `json:"require_session_policy"`
	GrantKeyPinned        *bool `json:"grant_key_pinned"`
	SessionPolicyRequired *bool `json:"session_policy_required"`
	// AgentVersion is omitted by signaling when the agent announced none; absent decodes as "".
	// Mirrors server/signaling/presence.go's PresenceEntry.AgentVersion.
	AgentVersion string `json:"agent_version"`
	// LoggedInUser is omitted by signaling when the agent announced none; absent decodes as "".
	// Mirrors server/signaling/presence.go's PresenceEntry.LoggedInUser.
	LoggedInUser string `json:"logged_in_user"`
}

type presenceResponse struct {
	Devices    []presenceEntry `json:"devices"`
	AsOfUnixMs int64           `json:"as_of_unix_ms"`
}

// DefaultPresenceTimeout bounds the call to signaling. Short on purpose: this runs inside a console
// page load, and a slow signaling server must degrade the machine list to "presence unknown"
// rather than hang the request behind it.
const DefaultPresenceTimeout = 2 * time.Second

// DefaultPresenceCacheTTL is how long a fetched snapshot is reused. Presence changes on the order
// of the signaling heartbeat (30s), so re-querying on every console poll adds load without adding
// information; it also bounds the blast radius of a signaling outage on console latency to one
// slow request per TTL instead of one per page load.
const DefaultPresenceCacheTTL = 5 * time.Second

// DefaultPresenceFailureCooldown is how long a FAILED fetch is remembered, so the failure is as
// cached as a success is.
//
// This is the load-bearing half of the "one slow request per TTL" promise above, and caching only
// SUCCESS silently broke it: during a signaling black-hole nothing ever populated the cache, so
// every GET /machines fell through to a fresh fetch and paid the full Timeout — while holding the
// request's tenant-pinned pgx connection. An outage of the thing presence is a convenience for
// would have become a latency outage of the machine listing, which is the opposite of failing soft.
//
// Shorter than the success TTL on purpose: presence must recover promptly once signaling returns,
// and the cost of an over-eager retry is one 2s request, not a wrong answer.
const DefaultPresenceFailureCooldown = 3 * time.Second

// maxPresenceBodyBytes caps the response the control plane will buffer from signaling. Signaling is
// a trusted service, but "trusted" is not "will never be compromised or misconfigured", and an
// unbounded read on a console path is an easy memory-exhaustion lever. 8 MiB is far above any
// plausible fleet (a device id plus a timestamp is ~70 bytes, so this is >100k agents).
const maxPresenceBodyBytes = 8 << 20

// SignalingPresenceSource reads the feed over HTTP with the shared service token, caching the
// result for CacheTTL and the FAILURE for FailureCooldown, and collapsing concurrent misses into
// one in-flight request.
type SignalingPresenceSource struct {
	// URL is the full presence endpoint, e.g. http://127.0.0.1:8080/internal/presence.
	URL string
	// Token is the shared secret presented as `Authorization: Bearer …` (SIGNALING_PRESENCE_TOKEN).
	Token string
	// HTTPClient is injectable for tests; nil uses a client with Timeout.
	HTTPClient *http.Client
	// CacheTTL is how long to reuse a snapshot. 0 → DefaultPresenceCacheTTL; negative disables caching.
	CacheTTL time.Duration
	// FailureCooldown is how long a failed fetch short-circuits later ones.
	// 0 → DefaultPresenceFailureCooldown; negative disables negative caching.
	FailureCooldown time.Duration
	// Timeout bounds one fetch. 0 → DefaultPresenceTimeout. It is applied to the detached fetch
	// context as well as to the default HTTP client, so an injected client with no timeout of its
	// own still cannot pin a fetch open forever.
	Timeout time.Duration
	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time

	mu       sync.Mutex
	cached   *Presence
	cachedAt time.Time
	// failErr/failedAt are the NEGATIVE cache: the error the last fetch produced and when.
	// Cleared by the next success.
	failErr  error
	failedAt time.Time
	// inflight is the single-flight slot: non-nil while a fetch is running, so N concurrent console
	// page loads during an outage produce ONE 2s request rather than N.
	inflight *presenceFetch
}

// presenceFetch is one in-flight fetch shared by every caller that missed the cache while it ran.
// `done` is closed once p/err are set, which is the happens-before edge the waiters read through.
type presenceFetch struct {
	base context.Context
	done chan struct{}
	p    *Presence
	err  error
}

var _ PresenceSource = (*SignalingPresenceSource)(nil)

func (s *SignalingPresenceSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *SignalingPresenceSource) client() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: s.timeout()}
}

func (s *SignalingPresenceSource) cacheTTL() time.Duration {
	if s.CacheTTL == 0 {
		return DefaultPresenceCacheTTL
	}
	return s.CacheTTL
}

func (s *SignalingPresenceSource) failureCooldown() time.Duration {
	if s.FailureCooldown == 0 {
		return DefaultPresenceFailureCooldown
	}
	return s.FailureCooldown
}

func (s *SignalingPresenceSource) timeout() time.Duration {
	if s.Timeout <= 0 {
		return DefaultPresenceTimeout
	}
	return s.Timeout
}

// FetchPresence implements PresenceSource: return the cached snapshot when fresh, the cached
// FAILURE when one is still in its cooldown, else fetch — joining an already-running fetch rather
// than starting a second one.
//
// A failed fetch does NOT serve stale data. Reporting a machine online because it was online five
// minutes ago is worse than reporting it unknown — the technician clicks Connect and waits on a
// session that can never establish. Unknown is honest; stale is a lie with a plausible face. The
// negative cache below caches the ERROR, never the previous snapshot, so this stays true.
func (s *SignalingPresenceSource) FetchPresence(ctx context.Context) (*Presence, error) {
	if s == nil || s.URL == "" || s.Token == "" {
		return nil, ErrPresenceUnavailable
	}
	s.mu.Lock()
	now := s.now()
	if ttl := s.cacheTTL(); ttl > 0 && s.cached != nil && now.Sub(s.cachedAt) < ttl {
		cached := s.cached
		s.mu.Unlock()
		return cached, nil
	}
	if cd := s.failureCooldown(); cd > 0 && s.failErr != nil && now.Sub(s.failedAt) < cd {
		err := s.failErr
		s.mu.Unlock()
		return nil, err
	}
	call := s.inflight
	if call == nil {
		// This caller is the leader. The fetch runs DETACHED (see runFetch): its result is shared,
		// so it must not die because the browser tab that happened to trigger it navigated away —
		// that would hand every waiter a context.Canceled and poison the cooldown with an error
		// that says nothing about signaling's health.
		call = &presenceFetch{base: ctx, done: make(chan struct{})}
		s.inflight = call
		s.mu.Unlock()
		go s.runFetch(call)
	} else {
		s.mu.Unlock()
	}
	return awaitPresence(ctx, call)
}

// awaitPresence blocks on a shared fetch, but never past the CALLER's own context: a request that
// is cancelled or times out stops waiting immediately and degrades to "presence unknown", while the
// fetch itself continues for whoever is still listening.
func awaitPresence(ctx context.Context, call *presenceFetch) (*Presence, error) {
	select {
	case <-call.done:
		return call.p, call.err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", ErrPresenceUnavailable, ctx.Err())
	}
}

// runFetch performs the shared fetch and publishes its result into the cache (positive or
// negative). It runs on a context DERIVED FROM the leader's — keeping request-scoped values such as
// trace ids — but with the leader's cancellation dropped and our own Timeout applied instead.
func (s *SignalingPresenceSource) runFetch(call *presenceFetch) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(call.base), s.timeout())
	defer cancel()

	p, err := s.fetch(ctx)

	s.mu.Lock()
	if err != nil {
		s.failErr, s.failedAt = err, s.now()
	} else {
		s.cached, s.cachedAt = p, s.now()
		s.failErr, s.failedAt = nil, time.Time{}
	}
	s.inflight = nil
	s.mu.Unlock()

	call.p, call.err = p, err
	close(call.done)
}

func (s *SignalingPresenceSource) fetch(ctx context.Context) (*Presence, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: signaling returned %d", ErrPresenceUnavailable, resp.StatusCode)
	}
	var body presenceResponse
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxPresenceBodyBytes)).Decode(&body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPresenceUnavailable, err)
	}
	out := &Presence{
		Online:                 make(map[string]time.Time, len(body.Devices)),
		OSByDevice:             make(map[string]string),
		RequireByDevice:        make(map[string]bool),
		GrantPinnedByDevice:    make(map[string]bool),
		PolicyRequiredByDevice: make(map[string]bool),
		VersionByDevice:        make(map[string]string),
		LoggedInUserByDevice:   make(map[string]string),
		AsOf:                   time.UnixMilli(body.AsOfUnixMs).UTC(),
	}
	for _, d := range body.Devices {
		if d.DeviceID == "" {
			continue
		}
		out.Online[d.DeviceID] = time.UnixMilli(d.LastSeenUnixMs).UTC()
		if d.OS != "" {
			out.OSByDevice[d.DeviceID] = d.OS
		}
		// Empty is "said nothing" and records nothing, so a silent agent can never blank a stored
		// version — the same absent-vs-value rule the floor flag gets from its pointer.
		if d.AgentVersion != "" {
			out.VersionByDevice[d.DeviceID] = d.AgentVersion
		}
		// Only a non-nil pointer becomes an entry: a `false` that was SENT is recorded (so clearing
		// the flag propagates), while a field that was absent records nothing at all.
		if d.RequireSessionPolicy != nil {
			out.RequireByDevice[d.DeviceID] = *d.RequireSessionPolicy
		}
		if d.GrantKeyPinned != nil {
			out.GrantPinnedByDevice[d.DeviceID] = *d.GrantKeyPinned
		}
		if d.SessionPolicyRequired != nil {
			out.PolicyRequiredByDevice[d.DeviceID] = *d.SessionPolicyRequired
		}
		// Same absent-vs-value rule as AgentVersion: empty string = agent said nothing, which must
		// not overwrite a previously recorded user. A logged-out machine may report "" but that still
		// means "no interactive user right now" — the control plane records that change explicitly.
		if d.LoggedInUser != "" {
			out.LoggedInUserByDevice[d.DeviceID] = d.LoggedInUser
		}
	}
	return out, nil
}

// -------------------------------------------------------------------------------------
// InMemoryPresenceSource — the fake, for tests and DEV mode.
// -------------------------------------------------------------------------------------

// InMemoryPresenceSource reports a fixed set of device ids as online. Concurrency-safe.
type InMemoryPresenceSource struct {
	mu     sync.Mutex
	online map[string]time.Time
	os     map[string]string
	// require holds only devices that REPORTED, mirroring Presence.RequireByDevice — a device
	// missing from this map announced nothing, which is different from announcing false.
	require map[string]bool
	// grantPinned mirrors Presence.GrantPinnedByDevice (only devices that reported posture).
	grantPinned    map[string]bool
	policyRequired map[string]bool
	// version holds only devices that REPORTED a build identity, mirroring Presence.VersionByDevice
	// — a device missing from this map announced nothing, which is different from announcing "".
	version map[string]string
	// loggedInUser holds only devices that REPORTED an interactive user, mirroring
	// Presence.LoggedInUserByDevice — a device missing from this map announced nothing.
	loggedInUser map[string]string
	// Err, when set, is returned instead of a snapshot — used to exercise the degraded path.
	Err error
}

// NewInMemoryPresenceSource constructs an empty source (nothing online).
func NewInMemoryPresenceSource() *InMemoryPresenceSource {
	return &InMemoryPresenceSource{
		online:         make(map[string]time.Time),
		os:             make(map[string]string),
		require:        make(map[string]bool),
		grantPinned:    make(map[string]bool),
		policyRequired: make(map[string]bool),
		version:        make(map[string]string),
		loggedInUser:   make(map[string]string),
	}
}

var _ PresenceSource = (*InMemoryPresenceSource)(nil)

// SetOnline marks a device id online at the given time (announcing no os).
func (s *InMemoryPresenceSource) SetOnline(deviceID string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.online[deviceID] = at
}

// SetOnlineWithOS marks a device id online with an agent-asserted os description.
func (s *InMemoryPresenceSource) SetOnlineWithOS(deviceID string, at time.Time, os string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.online[deviceID] = at
	if os != "" {
		s.os[deviceID] = os
	} else {
		delete(s.os, deviceID)
	}
}

// SetOnlineRequiringSessionPolicy marks a device id online AND reporting the given floor flag.
// Use this rather than a setter that only takes `true`: reporting false is a real, distinct event
// (the operator cleared the flag) and the refresh has to carry it.
func (s *InMemoryPresenceSource) SetOnlineRequiringSessionPolicy(deviceID string, at time.Time, require bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.online[deviceID] = at
	s.require[deviceID] = require
}

// SetOnlineWithGrantKeyPinned marks a device online AND reporting its grant-key posture (audit #9).
// SetOnlineWithPolicyRequired marks a device online AND reporting its session_policy_required posture.
func (s *InMemoryPresenceSource) SetOnlineWithPolicyRequired(deviceID string, at time.Time, required bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.online[deviceID] = at
	s.policyRequired[deviceID] = required
}

func (s *InMemoryPresenceSource) SetOnlineWithGrantKeyPinned(deviceID string, at time.Time, pinned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.online[deviceID] = at
	s.grantPinned[deviceID] = pinned
}

// SetOnlineWithVersion marks a device online AND reporting a build identity, the shape a
// post-0039 agent produces.
func (s *InMemoryPresenceSource) SetOnlineWithVersion(deviceID string, at time.Time, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.online[deviceID] = at
	s.version[deviceID] = version
}

// SetOnlineWithLoggedInUser marks a device online AND reporting an interactive-session user, the
// shape a post-0048 agent produces.
func (s *InMemoryPresenceSource) SetOnlineWithLoggedInUser(deviceID string, at time.Time, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.online[deviceID] = at
	if user != "" {
		s.loggedInUser[deviceID] = user
	} else {
		delete(s.loggedInUser, deviceID)
	}
}

// SetOffline removes a device id from the snapshot.
func (s *InMemoryPresenceSource) SetOffline(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.online, deviceID)
	delete(s.os, deviceID)
	delete(s.require, deviceID)
	delete(s.grantPinned, deviceID)
	delete(s.policyRequired, deviceID)
	delete(s.version, deviceID)
	delete(s.loggedInUser, deviceID)
}

// FetchPresence implements PresenceSource.
func (s *InMemoryPresenceSource) FetchPresence(context.Context) (*Presence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return nil, s.Err
	}
	out := &Presence{
		Online:                 make(map[string]time.Time, len(s.online)),
		OSByDevice:             make(map[string]string, len(s.os)),
		RequireByDevice:        make(map[string]bool, len(s.require)),
		GrantPinnedByDevice:    make(map[string]bool, len(s.grantPinned)),
		PolicyRequiredByDevice: make(map[string]bool, len(s.policyRequired)),
		VersionByDevice:        make(map[string]string, len(s.version)),
		LoggedInUserByDevice:   make(map[string]string, len(s.loggedInUser)),
		AsOf:                   time.Now().UTC(),
	}
	for k, v := range s.online {
		out.Online[k] = v
	}
	for k, v := range s.os {
		out.OSByDevice[k] = v
	}
	for k, v := range s.require {
		out.RequireByDevice[k] = v
	}
	for k, v := range s.grantPinned {
		out.GrantPinnedByDevice[k] = v
	}
	for k, v := range s.policyRequired {
		out.PolicyRequiredByDevice[k] = v
	}
	for k, v := range s.version {
		out.VersionByDevice[k] = v
	}
	for k, v := range s.loggedInUser {
		out.LoggedInUserByDevice[k] = v
	}
	return out, nil
}

package main

// Device-identity resolution (M3 — docs/11-agent-identity-contract.md §4).
//
// Signaling holds no database, so to check an agent's proof of possession it asks the control
// plane for the key it pinned at enrollment:
//
//	GET <SIGNALING_DEVICE_IDENTITY_URL>/internal/devices/<device id>/identity
//	Authorization: Bearer <SIGNALING_DEVICE_IDENTITY_TOKEN>
//
// The lookup FAILS CLOSED. While the control plane is unreachable, new registrations are refused;
// stale cache entries are never served past their TTL and there is no grace mode. Already
// registered agents are unaffected — their sockets and registry entries persist — so a
// control-plane outage stops new agents coming online without dropping live sessions.

import (
	"container/list"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// deviceIdentityTimeout bounds a single control-plane lookup.
	deviceIdentityTimeout = 5 * time.Second
	// deviceIdentityPositiveTTL is how long a resolved identity is reused without asking again.
	deviceIdentityPositiveTTL = 60 * time.Second
	// deviceIdentityNegativeTTL is how long a 404 is remembered. Short on purpose: it bounds the
	// cost of a burst of bogus device ids without pinning a stale "unknown" across a real
	// enrollment, so a machine that re-enrols is authenticatable within seconds.
	deviceIdentityNegativeTTL = 10 * time.Second
	// deviceIdentityCacheEntries caps the combined positive + negative cache. On overflow the
	// oldest negative is evicted first; a new negative is silently declined when only positives
	// remain so that anonymous unknown-device lookups cannot displace still-valid known devices.
	// A new positive evicts the oldest positive when no negatives remain.
	//
	// This cap bounds retained-entry memory, not upstream request volume: an attacker can still
	// drive O(n) control-plane lookups by rotating device IDs faster than the negative TTL, and
	// a burst of enrollments above the cap size rotates out older positives.
	deviceIdentityCacheEntries = 4096
	// deviceIdentityTokenMinLen matches the control plane's wiring-time minimum for
	// CP_DEVICE_IDENTITY_TOKEN — this token is the only thing guarding a cross-tenant lookup.
	deviceIdentityTokenMinLen = 32
)

// DeviceIdentity is the control plane's answer: the tenant that owns a device id and the Ed25519
// public key it pinned for it.
type DeviceIdentity struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id"`
	Pubkey   string `json:"pubkey"` // lowercase hex, 64 chars
	// Status is the machine's lifecycle status as the control plane reports it: "active",
	// "quarantined" or "retired". Empty (an older control plane) is treated as active. A "retired"
	// identity is only ever answered because signaling sends restricted=1; such a connection gets
	// the RESTRICTED channel (docs/65 D-C1): directives only, never brokered, never present.
	Status string `json:"status"`
}

// identityStatusRetired is the Status that selects restricted registration.
const identityStatusRetired = "retired"

// ErrDeviceUnknown reports that the control plane has no pinned identity for a device id — either
// it does not exist or it has no pinned pubkey (a legacy POST /enroll machine). Such a machine is
// unauthenticatable by design; re-enrol it through POST /enroll/redeem.
var ErrDeviceUnknown = errors.New("device identity unknown")

// IdentityResolver resolves a device id to its control-plane-pinned identity. ErrDeviceUnknown is
// a definitive "no such device"; any other error is a transport or configuration failure and must
// never be treated as an authentication decision.
type IdentityResolver interface {
	Resolve(ctx context.Context, deviceID string) (*DeviceIdentity, error)
}

// identityCacheEntry caches one lookup outcome. A nil identity is a cached ErrDeviceUnknown.
// elem points to the device ID's node in positiveQ (identity != nil) or negativeQ (identity == nil).
type identityCacheEntry struct {
	identity  *DeviceIdentity
	expiresAt time.Time
	elem      *list.Element
}

// httpIdentityResolver is the IdentityResolver backed by the control plane's device-identity
// endpoint, with a TTL cache in front of it.
type httpIdentityResolver struct {
	baseURL string
	token   string
	client  *http.Client
	now     func() time.Time

	mu        sync.Mutex
	cache     map[string]identityCacheEntry
	positiveQ *list.List // device IDs of positive entries; front = oldest
	negativeQ *list.List // device IDs of negative entries; front = oldest
}

// newHTTPIdentityResolver validates the endpoint configuration up front so a misconfigured
// deployment fails at startup rather than at the first agent registration.
func newHTTPIdentityResolver(baseURL, token string) (*httpIdentityResolver, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("SIGNALING_DEVICE_IDENTITY_URL must be an http(s) base URL, e.g. https://cp.example:8443")
	}
	if len(token) < deviceIdentityTokenMinLen {
		return nil, fmt.Errorf("SIGNALING_DEVICE_IDENTITY_TOKEN must be at least %d characters", deviceIdentityTokenMinLen)
	}
	return &httpIdentityResolver{
		baseURL:   baseURL,
		token:     token,
		client:    &http.Client{Timeout: deviceIdentityTimeout},
		now:       time.Now,
		cache:     make(map[string]identityCacheEntry),
		positiveQ: list.New(),
		negativeQ: list.New(),
	}, nil
}

// Resolve returns the pinned identity for deviceID, serving a cached answer while it is within
// TTL. Transport failures (timeout, 5xx, 401, malformed body) are NEVER cached and always surface
// as errors, so a broken control plane refuses registrations instead of quietly authorizing them.
func (r *httpIdentityResolver) Resolve(ctx context.Context, deviceID string) (*DeviceIdentity, error) {
	if len(deviceID) == 0 || len(deviceID) > 128 {
		return nil, ErrDeviceUnknown
	}
	if identity, err, ok := r.cached(deviceID); ok {
		return identity, err
	}
	identity, err := r.fetch(ctx, deviceID)
	switch {
	case err == nil:
		r.store(deviceID, identity, deviceIdentityPositiveTTL)
		return identity, nil
	case errors.Is(err, ErrDeviceUnknown):
		r.store(deviceID, nil, deviceIdentityNegativeTTL)
		return nil, err
	default:
		return nil, err
	}
}

// cached reports a still-fresh cache entry. An expired entry is evicted and reported as a miss —
// stale identities are never served.
func (r *httpIdentityResolver) cached(deviceID string) (*DeviceIdentity, error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.cache[deviceID]
	if !ok {
		return nil, nil, false
	}
	if !r.now().Before(entry.expiresAt) {
		if entry.identity != nil {
			r.positiveQ.Remove(entry.elem)
		} else {
			r.negativeQ.Remove(entry.elem)
		}
		delete(r.cache, deviceID)
		return nil, nil, false
	}
	if entry.identity == nil {
		return nil, ErrDeviceUnknown, true
	}
	return entry.identity, nil, true
}

// store caches an outcome for ttl. identity == nil caches the negative result.
//
// Eviction when the combined cap is reached: the oldest negative is preferred so that anonymous
// unknown-device lookups do not displace still-valid known devices. A new negative is silently
// declined (not stored) when the cache holds only positives. A new positive evicts the oldest
// positive when no negatives are available.
//
// Refreshing an existing key removes the stale queue node before re-inserting, so there are never
// duplicate nodes for the same device ID.
func (r *httpIdentityResolver) store(deviceID string, identity *DeviceIdentity, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Remove any existing queue node for this key to prevent stale duplicates on refresh.
	if existing, ok := r.cache[deviceID]; ok {
		if existing.identity != nil {
			r.positiveQ.Remove(existing.elem)
		} else {
			r.negativeQ.Remove(existing.elem)
		}
		delete(r.cache, deviceID)
	}

	if len(r.cache) >= deviceIdentityCacheEntries {
		if identity == nil {
			// New negative: evict the oldest negative, or decline if none exist.
			if r.negativeQ.Len() == 0 {
				return
			}
			r.evictFrontNegative()
		} else {
			// New positive: prefer evicting a negative to protect known devices.
			if r.negativeQ.Len() > 0 {
				r.evictFrontNegative()
			} else {
				r.evictFrontPositive()
			}
		}
	}

	var elem *list.Element
	if identity == nil {
		elem = r.negativeQ.PushBack(deviceID)
	} else {
		elem = r.positiveQ.PushBack(deviceID)
	}
	r.cache[deviceID] = identityCacheEntry{identity: identity, expiresAt: r.now().Add(ttl), elem: elem}
}

// evictFrontNegative removes the oldest negative cache entry. Must be called with r.mu held.
func (r *httpIdentityResolver) evictFrontNegative() {
	if front := r.negativeQ.Front(); front != nil {
		delete(r.cache, front.Value.(string))
		r.negativeQ.Remove(front)
	}
}

// evictFrontPositive removes the oldest positive cache entry. Must be called with r.mu held.
func (r *httpIdentityResolver) evictFrontPositive() {
	if front := r.positiveQ.Front(); front != nil {
		delete(r.cache, front.Value.(string))
		r.positiveQ.Remove(front)
	}
}

// fetch performs one uncached lookup.
func (r *httpIdentityResolver) fetch(ctx context.Context, deviceID string) (*DeviceIdentity, error) {
	// restricted=1 ALWAYS: it is how this signaling says it understands the restricted channel. A
	// control plane answers a retired machine only to such a caller (and 404s it otherwise, so an
	// older signaling never admits a retired agent).
	endpoint := r.baseURL + "/internal/devices/" + url.PathEscape(deviceID) + "/identity?restricted=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("device identity request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device identity lookup: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrDeviceUnknown
	default:
		return nil, fmt.Errorf("device identity lookup: control plane returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("device identity lookup: read body: %w", err)
	}
	var identity DeviceIdentity
	if err := json.Unmarshal(body, &identity); err != nil {
		return nil, fmt.Errorf("device identity lookup: malformed body: %w", err)
	}
	identity.Pubkey = strings.ToLower(strings.TrimSpace(identity.Pubkey))
	raw, err := hex.DecodeString(identity.Pubkey)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("device identity lookup: pubkey is not a hex-encoded 32-byte Ed25519 key")
	}
	if identity.TenantID == "" {
		// The tenant is signed into the agent-auth preimage and becomes Peer.Tenant, so an empty
		// one would silently disable the broker's cross-tenant guard.
		return nil, errors.New("device identity lookup: response carries no tenant id")
	}
	switch identity.Status {
	case "", "active", "quarantined", identityStatusRetired:
	default:
		// Fail closed on a status this build does not understand rather than admit it as active.
		return nil, fmt.Errorf("device identity lookup: unknown status %q", clipForLog(identity.Status))
	}
	identity.DeviceID = deviceID
	return &identity, nil
}

// identityResolverFromEnv builds the resolver from SIGNALING_DEVICE_IDENTITY_URL and
// SIGNALING_DEVICE_IDENTITY_TOKEN. Returns (nil, nil) when either is unset; main() then refuses to
// start unless -insecure-no-agent-auth was passed explicitly.
func identityResolverFromEnv() (IdentityResolver, error) {
	base := strings.TrimSpace(os.Getenv("SIGNALING_DEVICE_IDENTITY_URL"))
	token := strings.TrimSpace(os.Getenv("SIGNALING_DEVICE_IDENTITY_TOKEN"))
	if base == "" || token == "" {
		return nil, nil
	}
	resolver, err := newHTTPIdentityResolver(base, token)
	if err != nil {
		return nil, err
	}
	return resolver, nil
}

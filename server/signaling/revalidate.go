package main

// Periodic re-validation of registered agents (platform-operator design v4, item 1).
//
// An agent's identity is checked against the control plane only at registration. Once a tenant is
// suspended the control plane stops resolving its devices (cp_machine_identity_by_device_id), new
// registrations are refused, and new session tickets can no longer be minted or redeemed; but an
// agent that registered before the suspension would stay connected (and show online) indefinitely.
// This sweep re-resolves every registered agent at a fixed interval, bypassing the identity cache,
// and closes the connection of any agent the control plane DEFINITIVELY no longer vouches for:
// unknown device (suspended tenant, removed machine), a different tenant, or a different pinned key.
//
// A transport or control-plane failure is NOT a verdict and never drops anyone: signaling's
// established rule is that a control-plane outage stops new agents coming online without dropping
// live ones (deviceidentity.go).
//
// This is PRESENCE cleanup and it is best effort. The suspension contract's hard bound is on leased
// sessions (they end within the lease TTL because renewals are refused), and on new authorization
// (tickets can be neither minted nor redeemed); neither depends on this sweep. Nominally an agent is
// dropped within one interval plus the sweep's duration of a suspension, while the control plane
// answers. Lookups run with bounded concurrency and a per-lookup deadline, in a fresh random order each
// sweep, so a few slow lookups delay the rest by at most one lookup deadline per worker, and the
// random order reduces (it does not eliminate) the chance of skipping the same agents repeatedly.

import (
	"context"
	"errors"
	"log"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// AgentRevalidationInterval is how often registered agents are re-checked.
const AgentRevalidationInterval = 60 * time.Second

const (
	// revalidateConcurrency bounds the lookups one sweep has in flight against the control plane.
	revalidateConcurrency = 8
	// revalidateLookupTimeout bounds one lookup, so one slow answer cannot hold a worker for the sweep.
	revalidateLookupTimeout = 5 * time.Second
)

// freshIdentityResolver is implemented by resolvers that can bypass their cache; the sweep must not
// be served a positive answer cached before the suspension.
type freshIdentityResolver interface {
	ResolveFresh(ctx context.Context, deviceID string) (*DeviceIdentity, error)
}

// ResolveFresh asks the control plane directly (no cache read) and refreshes the cache with the
// answer, so registrations right after a sweep also see it.
func (r *httpIdentityResolver) ResolveFresh(ctx context.Context, deviceID string) (*DeviceIdentity, error) {
	if len(deviceID) == 0 || len(deviceID) > 128 {
		return nil, ErrDeviceUnknown
	}
	identity, err := r.fetch(ctx, deviceID)
	switch {
	case err == nil:
		r.store(deviceID, identity, deviceIdentityPositiveTTL)
	case errors.Is(err, ErrDeviceUnknown):
		r.store(deviceID, nil, deviceIdentityNegativeTTL)
	}
	return identity, err
}

// registeredPeers returns the currently registered peers (fresh or not) without holding the lock
// afterwards. (Snapshot, in presence.go, is the read-only presence projection; this returns the peers.)
func (r *Registry) registeredPeers() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Peer, 0, len(r.peers)+len(r.restricted))
	for _, p := range r.peers {
		out = append(out, p)
	}
	// Restricted (retired) connections are re-validated too: one whose machine is active again must
	// be reconnected so it registers normally.
	for _, p := range r.restricted {
		out = append(out, p)
	}
	return out
}

// RevalidateAgents runs one sweep and returns how many agents were disconnected. Agents registered
// without a control-plane identity (dev mode: no resolver) are never touched. When ctx ends, lookups not
// yet started are skipped (they keep their connection until a later sweep).
func (s *Server) RevalidateAgents(ctx context.Context) int {
	if s.identity == nil {
		return 0
	}
	resolve := s.identity.Resolve
	if fr, ok := s.identity.(freshIdentityResolver); ok {
		resolve = fr.ResolveFresh
	}
	lookupTimeout := s.revalidateLookupTimeout
	if lookupTimeout <= 0 {
		lookupTimeout = revalidateLookupTimeout
	}
	peers := s.reg.registeredPeers()
	rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })

	var (
		mu                         sync.Mutex
		dropped, failed, unchecked int
		checked                    int
		wg                         sync.WaitGroup
	)
	work := make(chan *Peer)
	for i := 0; i < revalidateConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
				id, err := resolve(lctx, p.DeviceId)
				cancel()
				var reason string
				switch {
				case errors.Is(err, ErrDeviceUnknown):
					reason = "device no longer authorized"
				case err != nil:
					mu.Lock()
					failed++ // outage, timeout or transport failure: not a verdict
					mu.Unlock()
					continue
				case id.TenantID != p.Tenant:
					reason = "device moved to another tenant"
				case id.Pubkey != p.Pubkey:
					reason = "device key changed"
				case p.restricted && id.Status != identityStatusRetired:
					// The machine is active (or quarantined) again: a CLEAN close, so the agent
					// re-registers and gets the normal channel (docs/65 D-C1).
					s.closeForReregistration(p, "device no longer retired; re-register")
					mu.Lock()
					dropped++
					mu.Unlock()
					continue
				case !p.restricted && id.Status == identityStatusRetired:
					// Retired while connected normally: reconnect so it lands in restricted mode
					// instead of staying brokerable and visible as online.
					s.closeForReregistration(p, "device retired; re-register")
					mu.Lock()
					dropped++
					mu.Unlock()
					continue
				default:
					continue
				}
				s.dropAgent(p, reason)
				mu.Lock()
				dropped++
				mu.Unlock()
			}
		}()
	}
	for _, p := range peers {
		if p.Tenant == "" || p.Pubkey == "" {
			continue // not an identity-verified agent
		}
		if ctx.Err() != nil {
			unchecked++
			continue
		}
		select {
		case work <- p:
			checked++
		case <-ctx.Done():
			unchecked++
		}
	}
	close(work)
	wg.Wait()
	if failed > 0 || unchecked > 0 {
		log.Printf("revalidate: %d agents checked, %d lookups failed, %d not reached before the sweep deadline, %d dropped",
			checked, failed, unchecked, dropped)
	}
	return dropped
}

// dropAgent removes the registry entry (only if it still names this connection) and closes the
// socket with a normal-closure frame, so the agent reconnects and re-registers through the full
// identity check.
func (s *Server) dropAgent(p *Peer, reason string) {
	s.reg.Remove(p.DeviceId, p.conn)
	if p.conn == nil {
		return
	}
	p.writeMu.Lock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(peerWriteTimeout))
	_ = p.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason))
	p.writeMu.Unlock()
	_ = p.conn.Close()
	log.Printf("revalidate: dropped agent %s: %s", clipForLog(p.DeviceId), reason)
}

// closeForReregistration removes p's registry entry (only if it still names this connection) and
// closes the socket with a NORMAL-closure frame, the signal every agent version handles by
// reconnecting at once.
func (s *Server) closeForReregistration(p *Peer, reason string) {
	s.reg.Remove(p.DeviceId, p.conn)
	if p.conn == nil {
		return
	}
	closePeer(p, reason)
	log.Printf("revalidate: closed agent %s for re-registration: %s", clipForLog(p.DeviceId), reason)
}

// StartAgentRevalidation runs RevalidateAgents every interval until ctx is done.
func (s *Server) StartAgentRevalidation(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweepCtx, cancel := context.WithTimeout(ctx, interval)
				s.RevalidateAgents(sweepCtx)
				cancel()
			}
		}
	}()
}

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	lanFeature        = "lan_v1"
	wakeFeature       = "wake_v1"
	deviceGateTimeout = 2 * time.Second
	wakeWriteTimeout  = 5 * time.Second
	maxWakeBody       = 4096
)

type LanEntry struct {
	MAC         string  `json:"mac"`
	IPv4Network string  `json:"ipv4_network"`
	GatewayMAC  *string `json:"gateway_mac"`
}
type LanReport struct {
	Seq     *uint64    `json:"seq"`
	Entries []LanEntry `json:"entries"`
}
type LanReportAck struct {
	Seq uint64 `json:"seq"`
}
type WakeHello struct {
	Challenge string `json:"challenge"`
}
type Wake struct {
	Artifact json.RawMessage `json:"artifact"`
}
type wakeConnRef struct {
	Incarnation string `json:"incarnation"`
	Generation  uint64 `json:"generation"`
}
type peerWakeState struct {
	// Registration fields become immutable at publication.
	ref                             wakeConnRef
	proved, lanFeature, wakeFeature bool

	installedActive atomic.Bool // revocation is serialized by the device gate and registry lock
	// revoked is STICKY and set BEFORE waiting on the device gate (Codex branch review r4): a forward that
	// already holds the gate and is waiting for the WebSocket writer re-checks eligibility right before it
	// writes, so a verdict that arrives during that wait stops the write. Only a new registration (a new
	// peer) is eligible again.
	revoked atomic.Bool

	// The socket read loop owns epoch and the committed watermark. A successful
	// acknowledgement and the challenge are also read by presence and wake handlers.
	epoch        *int64
	committed    *LanReportAck
	digest       [32]byte
	acknowledged atomic.Bool
	challenge    atomic.Pointer[[16]byte]
	disconnected atomic.Bool
}

func newIncarnation() string {
	var id [16]byte
	rand.Read(id[:])
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}

// Caller holds the registry read or write lock.
func (r *Registry) wakeEligibleLocked(p *Peer, feature string) bool {
	return p != nil && r.peers[p.DeviceId] == p &&
		!p.restricted && !r.expired(p) && p.wake.proved && p.wake.installedActive.Load() && !p.wake.revoked.Load() &&
		((feature == lanFeature && p.wake.lanFeature) || (feature == wakeFeature && p.wake.wakeFeature))
}

func (r *Registry) wakeReadyLocked(p *Peer) bool {
	return r.wakeActive.Load() && r.wakeEligibleLocked(p, wakeFeature) && p.wake.challenge.Load() != nil && p.wake.acknowledged.Load()
}

// wakePeer is a non-mutating lookup. The caller holds the device gate.
func (r *Registry) wakePeer(id string) *Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p := r.peers[id]
	if r.wakeReadyLocked(p) {
		return p
	}
	return nil
}

// revokeReportingPeer clears Wake eligibility and readiness for p if it is still the device's current peer,
// under the delivery gate (it waits out an in-flight, time-bounded Wake write), like a revalidation verdict.
// A replacement registered meanwhile is untouched: it reports for itself and gets its own verdict.
func (r *Registry) revokeReportingPeer(p *Peer) {
	// Sticky, and before the gate: the reporting socket itself is no longer eligible, whether or not a
	// replacement has been published since (a replacement is a different peer and keeps its own state).
	p.wake.revoked.Store(true)
	release, _ := r.gates.acquire(p.DeviceId, -1)
	defer release()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers[p.DeviceId] == p {
		p.wake.installedActive.Store(false)
		p.wake.challenge.Store(nil)
		p.wake.acknowledged.Store(false)
	}
}

func (s *Server) lanEligible(p *Peer) bool {
	s.reg.mu.RLock()
	defer s.reg.mu.RUnlock()
	return s.reg.wakeActive.Load() && s.reg.wakeEligibleLocked(p, lanFeature)
}

func lowerHex(s string, size int) ([]byte, bool) {
	if len(s) != size*2 {
		return nil, false
	}
	raw, err := hex.DecodeString(s)
	return raw, err == nil && hex.EncodeToString(raw) == s
}

func (s *Server) handleWakeHello(p *Peer, msg *WakeHello) {
	raw, valid := lowerHex(msg.Challenge, 16)
	if !valid {
		s.wakeDrops.Add(1)
		return
	}
	release, ok := s.reg.gates.acquire(p.DeviceId, deviceGateTimeout)
	if !ok {
		s.wakeDrops.Add(1)
		return
	}
	defer release()
	s.reg.mu.RLock()
	defer s.reg.mu.RUnlock()
	if !s.reg.wakeEligibleLocked(p, wakeFeature) {
		s.wakeDrops.Add(1)
		return
	}
	challenge := [16]byte(raw)
	p.wake.challenge.Store(&challenge)
}

func validLanMAC(value string) bool {
	mac, err := net.ParseMAC(value)
	return err == nil && len(mac) == 6 && mac.String() == value &&
		mac[0]&1 == 0 && value != "00:00:00:00:00:00"
}

func (r *LanReport) snapshotDigest() ([32]byte, bool) {
	if r.Seq == nil || *r.Seq > math.MaxInt64 || r.Entries == nil || len(r.Entries) > 4 {
		return [32]byte{}, false
	}
	entries := append([]LanEntry(nil), r.Entries...)
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry.IPv4Network)
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 ||
			prefix.Masked().String() != entry.IPv4Network || !validLanMAC(entry.MAC) ||
			(entry.GatewayMAC != nil && !validLanMAC(*entry.GatewayMAC)) {
			return [32]byte{}, false
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].MAC != entries[j].MAC {
			return entries[i].MAC < entries[j].MAC
		}
		return entries[i].IPv4Network < entries[j].IPv4Network
	})
	// Hash the concatenation of ASCII lines "mac<TAB>ipv4_network<TAB>gateway_mac<LF>",
	// sorted by MAC then network. Null gateway is an empty third column. The empty
	// snapshot hashes zero bytes. CP compares the decoded 32-byte digest as an opaque watermark.
	var canonical strings.Builder
	for i, entry := range entries {
		if i > 0 && entry.MAC == entries[i-1].MAC && entry.IPv4Network == entries[i-1].IPv4Network {
			return [32]byte{}, false
		}
		canonical.WriteString(entry.MAC)
		canonical.WriteByte('\t')
		canonical.WriteString(entry.IPv4Network)
		canonical.WriteByte('\t')
		if entry.GatewayMAC != nil {
			canonical.WriteString(*entry.GatewayMAC)
		}
		canonical.WriteByte('\n')
	}
	return sha256.Sum256([]byte(canonical.String())), true
}

type wakeClient struct {
	baseURL, token string
	http           *http.Client
	budgetMu       sync.Mutex
	// A bucket is represented by the time it would become full again.
	refillAt  map[string]time.Time
	nextPrune time.Time
}

func newWakeClient(baseURL, token string) *wakeClient {
	return &wakeClient{
		baseURL: baseURL,
		token:   token,
		http: &http.Client{
			Timeout:       deviceIdentityTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		refillAt: make(map[string]time.Time),
	}
}

func (c *wakeClient) charge(device string, now time.Time) bool {
	const tokenInterval = 10 * time.Second
	c.budgetMu.Lock()
	defer c.budgetMu.Unlock()
	if !now.Before(c.nextPrune) {
		for id, full := range c.refillAt {
			if !full.After(now) {
				delete(c.refillAt, id)
			}
		}
		c.nextPrune = now.Add(30 * time.Second)
	}
	full := c.refillAt[device]
	if full.Before(now) {
		full = now
	}
	full = full.Add(tokenInterval)
	if full.After(now.Add(3 * tokenInterval)) {
		return false
	}
	c.refillAt[device] = full
	return true
}

type wakeCPReply struct {
	Revision *int64 `json:"revision"`
	Epoch    *int64 `json:"epoch"`
	Status   string `json:"status"`
	Error    string `json:"error"`
}

func (c *wakeClient) call(ctx context.Context, method, path string, body any) (int, wakeCPReply) {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return 0, wakeCPReply{}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return 0, wakeCPReply{}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		// Retransmissions must return through the per-device budget.
		req.GetBody = nil
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, wakeCPReply{}
	}
	defer resp.Body.Close()
	var reply wakeCPReply
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxWakeBody+1))
	if dec.Decode(&reply) != nil || dec.Decode(new(json.RawMessage)) != io.EOF {
		return resp.StatusCode, wakeCPReply{}
	}
	return resp.StatusCode, reply
}

func (s *Server) activateWake(ctx context.Context) {
	const path = "/internal/signaling/incarnation"
	for delay := 100 * time.Millisecond; ctx.Err() == nil; delay = min(delay*2, 5*time.Second) {
		status, reply := s.wakeCP.call(ctx, http.MethodGet, path, nil)
		if status == http.StatusOK && reply.Revision != nil && *reply.Revision >= 0 {
			body := struct {
				Incarnation      string `json:"incarnation"`
				ExpectedRevision int64  `json:"expected_revision"`
			}{s.reg.incarnation, *reply.Revision}
			status, reply = s.wakeCP.call(ctx, http.MethodPost, path, body)
			if status == http.StatusOK && reply.Revision != nil && *reply.Revision >= 0 {
				s.reg.wakeActive.Store(true)
				return
			}
		}
		// A revision_moved response and transient failures both require a new GET.
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type lanConnection struct {
	DeviceID     string `json:"device_id"`
	DevicePubkey string `json:"device_pubkey"`
	wakeConnRef
}

func (s *Server) forwardLan(p *Peer, path string, body any) (int, wakeCPReply) {
	if !s.lanEligible(p) || !s.wakeCP.charge(p.DeviceId, s.reg.now()) {
		s.wakeDrops.Add(1)
		return 0, wakeCPReply{}
	}
	status, reply := s.wakeCP.call(context.Background(), http.MethodPost, path, body)
	if status == http.StatusConflict {
		// Log only codes in the CP contract. Never log an arbitrary response field.
		switch reply.Error {
		case "stale_incarnation", "superseded", "not_eligible", "stale_epoch", "seq_reused":
			log.Print(reply.Error)
		default:
			log.Print("lan_conflict")
		}
		// The control plane says this device is no longer an active installed machine with this key (Codex
		// branch review r3): revoke the connection's Wake readiness under the delivery gate exactly like a
		// revalidation verdict, so a Wake issued before the change can no longer be written to it. Regaining
		// eligibility needs a fresh registration.
		if reply.Error == "not_eligible" {
			s.reg.revokeReportingPeer(p)
		}
	}
	return status, reply
}

func (s *Server) handleLanReport(p *Peer, report *LanReport) {
	if s.wakeCP == nil || !s.lanEligible(p) {
		s.wakeDrops.Add(1)
		return
	}
	digest, valid := report.snapshotDigest()
	if !valid {
		s.wakeDrops.Add(1)
		return
	}
	seq := *report.Seq
	if p.wake.committed == nil || p.wake.committed.Seq != seq || p.wake.digest != digest {
		// Both calls use the proved identity. Retransmissions after transport errors
		// reuse the connection reference, and each outbound attempt spends a token.
		connection := lanConnection{p.DeviceId, p.Pubkey, p.wake.ref}
		if p.wake.epoch == nil {
			status, reply := s.forwardLan(p, "/internal/devices/lan-epoch", connection)
			if status != http.StatusOK || reply.Epoch == nil || *reply.Epoch < 0 {
				return
			}
			p.wake.epoch = reply.Epoch
		}
		body := struct {
			lanConnection
			Epoch   int64      `json:"epoch"`
			Seq     uint64     `json:"seq"`
			Digest  string     `json:"digest"`
			Entries []LanEntry `json:"entries"`
		}{connection, *p.wake.epoch, seq, hex.EncodeToString(digest[:]), report.Entries}
		status, reply := s.forwardLan(p, "/internal/devices/lan", body)
		if status != http.StatusOK || (reply.Status != "applied" && reply.Status != "duplicate") {
			return
		}
		p.wake.committed = &LanReportAck{Seq: seq}
		p.wake.digest = digest
	}
	if s.lanEligible(p) && p.Send(*p.wake.committed) == nil {
		s.reg.mu.RLock()
		if s.reg.wakeEligibleLocked(p, lanFeature) {
			p.wake.acknowledged.Store(true)
		}
		s.reg.mu.RUnlock()
	}
}

type wakeContext struct {
	ConnRef         wakeConnRef `json:"conn_ref"`
	Epoch           int64       `json:"epoch"`
	Challenge       string      `json:"challenge"`
	DeviceKeySHA256 string      `json:"device_key_sha256"`
}

func wakeContextFor(p *Peer) wakeContext {
	key, _ := hex.DecodeString(p.Pubkey)
	hash := sha256.Sum256(key)
	challenge := p.wake.challenge.Load()
	return wakeContext{p.wake.ref, *p.wake.epoch, hex.EncodeToString(challenge[:]), hex.EncodeToString(hash[:])}
}

func (s *Server) mountWake(mux *http.ServeMux, token string) {
	if len(token) < presenceTokenMinLen {
		return
	}
	mux.HandleFunc("POST /internal/devices/{device_id}/wake-context", s.wakeHandler(token, false))
	mux.HandleFunc("POST /internal/devices/{device_id}/wake", s.wakeHandler(token, true))
}

func writeWakeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) wakeHandler(token string, forward bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fail := func(status int, code string) {
			if status == http.StatusConflict {
				s.wakeDrops.Add(1)
			}
			writeWakeJSON(w, status, map[string]string{"error": code})
		}
		if !presenceAuthorized(r, token) {
			fail(http.StatusUnauthorized, "unauthorized")
			return
		}
		refuse := "not_ready"
		if forward {
			refuse = "not_written"
		}
		if !s.reg.wakeActive.Load() {
			fail(http.StatusConflict, refuse)
			return
		}

		var body struct {
			ConnRef  wakeConnRef     `json:"conn_ref"`
			Artifact json.RawMessage `json:"artifact"`
		}
		var artifact struct {
			Claims struct {
				Tenant    string `json:"tenant_id"`
				KeyHash   string `json:"relay_key_sha256"`
				Challenge string `json:"wake_challenge"`
			} `json:"claims"`
		}
		if forward {
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWakeBody))
			dec.DisallowUnknownFields()
			if dec.Decode(&body) != nil || dec.Decode(new(json.RawMessage)) != io.EOF ||
				json.Unmarshal(body.Artifact, &artifact) != nil {
				fail(http.StatusConflict, refuse)
				return
			}
		}
		id := r.PathValue("device_id")
		release, ok := s.reg.gates.acquire(id, deviceGateTimeout)
		if !ok {
			fail(http.StatusConflict, refuse)
			return
		}
		defer release()
		p := s.reg.wakePeer(id)
		if p == nil || r.Context().Err() != nil {
			release()
			fail(http.StatusConflict, refuse)
			return
		}
		current := wakeContextFor(p)
		if !forward {
			release()
			writeWakeJSON(w, http.StatusOK, current)
			return
		}
		claims := artifact.Claims
		if body.ConnRef != current.ConnRef || claims.Tenant != p.Tenant ||
			claims.KeyHash != current.DeviceKeySHA256 || claims.Challenge != current.Challenge {
			release()
			fail(http.StatusConflict, refuse)
			return
		}
		attempted, err := p.sendWake(r.Context(), Wake{Artifact: body.Artifact}, func() bool { return s.reg.wakePeer(id) == p })
		release()
		switch {
		case !attempted:
			fail(http.StatusConflict, refuse)
		case err != nil:
			fail(http.StatusBadGateway, "write_failed")
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}
}

// One deadline covers waiting for the existing WebSocket writer and its write.
func (p *Peer) sendWake(ctx context.Context, msg Wake, stillReady func() bool) (attempted bool, err error) {
	deadline := time.Now().Add(wakeWriteTimeout)
	wait, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if !p.writeMu.TryLock() {
		retry := time.NewTicker(5 * time.Millisecond)
		defer retry.Stop()
		for !p.writeMu.TryLock() {
			select {
			case <-wait.Done():
				return false, wait.Err()
			case <-retry.C:
			}
		}
	}
	defer p.writeMu.Unlock()
	if wait.Err() != nil || !time.Now().Before(deadline) || !stillReady() {
		return false, wait.Err()
	}
	if err := p.conn.SetWriteDeadline(deadline); err != nil {
		return false, err
	}
	return true, p.conn.WriteJSON(ServerToClient{Type: "wake", Payload: msg})
}

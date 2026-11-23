package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The default logger serializes Write calls. Copy each record into a bounded
// channel so assertions never race a handler's buffer writes.
type reviewLogSink chan string

func (s reviewLogSink) Write(p []byte) (int, error) {
	select {
	case s <- string(p):
	default:
	}
	return len(p), nil
}

func TestReviewAuthenticatedIdentityLogEscaping(t *testing.T) {
	sink := make(reviewLogSink, 32)
	old := log.Writer()
	log.SetOutput(sink)
	t.Cleanup(func() { log.SetOutput(old) })
	device, tenant := "device\nFORGED\x1b", "tenant\r\nFORGED\u2028"
	resolver := &fakeResolver{identities: map[string]*DeviceIdentity{
		device: {DeviceID: device, TenantID: tenant, Pubkey: agentAuthGoldenPubkeyHex},
	}}
	ts := newTestSignaling(t, time.Minute, nil, resolver, admissionLimits{
		maxTotal: 4, maxPending: 4, preAuthTimeout: 5 * time.Second,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatal(err)
	}
	writeJSONMsg(t, c, "register_agent", RegisterAgent{Device: device, Pubkey: agentAuthGoldenPubkeyHex})
	ch := readChallenge(t, c, time.Second)
	nonce := mustHex(t, ch.Nonce)
	priv := ed25519.NewKeyFromSeed(mustHex(t, agentAuthGoldenSeedHex))
	sig := ed25519.Sign(priv, agentAuthSigningBytes(device, tenant, nonce))
	writeJSONMsg(t, c, "agent_auth_response", AgentAuthResponse{Device: device, Nonce: ch.Nonce, Sig: hex.EncodeToString(sig)})
	readUntil(t, c, "registered", time.Second)
	await := func(prefix, want string) {
		t.Helper()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for {
			select {
			case record := <-sink:
				if !strings.Contains(record, prefix) {
					continue
				}
				if !strings.Contains(record, want) || strings.ContainsAny(strings.TrimSuffix(record, "\n"), "\n\r\t\x1b\u2028\u2029") {
					t.Fatalf("identity was not one escaped log record: %q; want %q", record, want)
				}
				return
			case <-timer.C:
				t.Fatalf("missing log %q", prefix)
			}
		}
	}
	// These identities came from a synthetic pinned resolver with real proof of
	// possession. This is formatting coverage, not an anonymous enrollment claim.
	await("agent auth OK:", fmt.Sprintf("agent auth OK: device %q registered with its control-plane-pinned key (tenant %q)", device, tenant))
	writeJSONMsg(t, c, "heartbeat", Heartbeat{Device: "different"})
	readUntil(t, c, "rejected", time.Second)
	await("heartbeat from", fmt.Sprintf("heartbeat from %q named a different device %q", device, "different"))
}

// A registered (authenticated) peer can name any device in a heartbeat. The mismatch diagnostic goes
// through the per-connection limiter, which bounds lines per second, not line size, so the named
// device must be clipped. The short-device case (logged in full, escaped) is the test above.
func TestHeartbeatMismatchLogClipsNamedDevice(t *testing.T) {
	sink := make(reviewLogSink, 32)
	old := log.Writer()
	log.SetOutput(sink)
	t.Cleanup(func() { log.SetOutput(old) })
	device, tenant := "hb-device", "hb-tenant"
	resolver := &fakeResolver{identities: map[string]*DeviceIdentity{
		device: {DeviceID: device, TenantID: tenant, Pubkey: agentAuthGoldenPubkeyHex},
	}}
	ts := newTestSignaling(t, time.Minute, nil, resolver, admissionLimits{
		maxTotal: 4, maxPending: 4, preAuthTimeout: 5 * time.Second,
	})
	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatal(err)
	}
	writeJSONMsg(t, c, "register_agent", RegisterAgent{Device: device, Pubkey: agentAuthGoldenPubkeyHex})
	ch := readChallenge(t, c, time.Second)
	priv := ed25519.NewKeyFromSeed(mustHex(t, agentAuthGoldenSeedHex))
	sig := ed25519.Sign(priv, agentAuthSigningBytes(device, tenant, mustHex(t, ch.Nonce)))
	writeJSONMsg(t, c, "agent_auth_response", AgentAuthResponse{Device: device, Nonce: ch.Nonce, Sig: hex.EncodeToString(sig)})
	readUntil(t, c, "registered", time.Second)

	huge := strings.Repeat("x", 60*1024)
	writeJSONMsg(t, c, "heartbeat", Heartbeat{Device: huge})
	readUntil(t, c, "rejected", time.Second)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case record := <-sink:
			if !strings.Contains(record, "heartbeat from") {
				continue
			}
			if len(record) >= 512 || strings.Contains(record, huge) {
				t.Fatalf("heartbeat mismatch log is %d bytes / carries the full named device", len(record))
			}
			if !strings.Contains(record, fmt.Sprintf("...(%d bytes)", len(huge))) {
				t.Fatalf("clipped device lacks its original-length marker: %q", record)
			}
			return
		case <-timer.C:
			t.Fatal("missing heartbeat mismatch log")
		}
	}
}

func TestReviewAnonymousRelayLogEscaping(t *testing.T) {
	// No parallelism: the logger is process-global. Each child restores it after
	// its clients close and its server joins all hijacked connection handlers.
	for _, tag := range []string{"candidate", "sdp", "close"} {
		t.Run(tag, func(t *testing.T) {
			sink := make(reviewLogSink, 32)
			old := log.Writer()
			log.SetOutput(sink)
			t.Cleanup(func() { log.SetOutput(old) })
			ts := newTestSignaling(t, time.Minute, nil, &fakeResolver{}, admissionLimits{
				maxTotal: 4, maxPending: 4, preAuthTimeout: 5 * time.Second,
			})
			c, _, err := ts.dialWS()
			if err != nil {
				t.Fatal(err)
			}
			attack := "missing\nFORGED\r\t\x1b[31m\u2028\u2029end"
			if tag == "candidate" {
				writeJSONMsg(t, c, tag, CandidateMsg{Session: attack})
			} else if tag == "sdp" {
				writeJSONMsg(t, c, tag, SdpMsg{Session: attack, Sdp: "synthetic", Kind: SdpOffer})
			} else {
				if err := c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, attack), time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			prefix := tag + " relay: "
			want := prefix + fmt.Sprintf("%q", tag+": unknown session "+attack)
			if tag == "close" {
				prefix = "read error from "
				want = prefix + fmt.Sprintf("%q: %q", "", "websocket: close 1008 (policy violation): "+attack)
			}
			deadline := time.NewTimer(2 * time.Second)
			defer deadline.Stop()
			for {
				select {
				case record := <-sink:
					if !strings.Contains(record, prefix) {
						continue
					}
					if !strings.Contains(record, want) || strings.ContainsAny(strings.TrimSuffix(record, "\n"), "\n\r\t\x1b\u2028\u2029") {
						t.Fatalf("request error was not one escaped log record: %q; want field %q", record, want)
					}
					return
				case <-deadline.C:
					t.Fatal("actual anonymous relay request produced no expected error log")
				}
			}
		})
	}
}

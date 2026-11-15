package main

// F19 log-escaping: request-derived session strings and device IDs must be quoted with %q
// so control chars cannot inject fake log lines. Uses real loopback WebSocket routes via
// newTestSignaling/dialWS (websocket_limits_test.go). No t.Parallel: global logger redirected.

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncLogWriter wraps bytes.Buffer with a mutex and a notification channel so waitFor
// can wake immediately on new output without sleeping.
type syncLogWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	notify chan struct{}
}

func newSyncLogWriter() *syncLogWriter { return &syncLogWriter{notify: make(chan struct{}, 1)} }

func (w *syncLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	select {
	case w.notify <- struct{}{}:
	default:
	}
	return n, err
}

func (w *syncLogWriter) captured() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (w *syncLogWriter) waitFor(match string, deadline time.Time) bool {
	for {
		if strings.Contains(w.captured(), match) {
			return true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		if remaining > 5*time.Millisecond {
			remaining = 5 * time.Millisecond
		}
		select {
		case <-w.notify:
		case <-time.After(remaining):
		}
	}
}

// captureLog redirects the global logger; call BEFORE newTestSignaling so LIFO cleanup runs
// server teardown before restoring the logger (handler goroutines must exit first).
func captureLog(t *testing.T) *syncLogWriter {
	t.Helper()
	w := newSyncLogWriter()
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(w)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return w
}

const (
	forgedLine     = "FAKE_LOG: source=attacker level=CRITICAL"
	hostileSession = "real-sid\r\n\t\x1b\u2028" + forgedLine // newline/CR/tab/ESC/LS + forged payload
	hostileDevice  = "bad-dev\r\n\t\x1b\u2028" + forgedLine  // ≤128 bytes, passes length gate
)

var escapingTestLimits = admissionLimits{maxTotal: 4, maxPending: 4, preAuthTimeout: 5 * time.Second}

// TestCandidateRelayErrorQuotesSession: relay error must be logged with %q so the LF in the
// hostile session does not inject forgedLine as a separate log line.
func TestCandidateRelayErrorQuotesSession(t *testing.T) {
	w := captureLog(t)
	ts := newTestSignaling(t, time.Minute, nil, nil, escapingTestLimits)

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dialWS: %v", err)
	}
	writeJSONMsg(t, c, "candidate", CandidateMsg{
		Session:   hostileSession,
		Candidate: Candidate{Addr: "127.0.0.1:9999", Kind: CandidateHost},
	})
	if !w.waitFor("candidate relay:", time.Now().Add(2*time.Second)) {
		t.Fatal("candidate relay log entry not observed within deadline")
	}
	assertLogEscaped(t, w.captured(), "candidate relay:", "session in candidate relay error")
}

// TestSdpRelayErrorQuotesSession: SDP counterpart to TestCandidateRelayErrorQuotesSession.
func TestSdpRelayErrorQuotesSession(t *testing.T) {
	w := captureLog(t)
	ts := newTestSignaling(t, time.Minute, nil, nil, escapingTestLimits)

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dialWS: %v", err)
	}
	writeJSONMsg(t, c, "sdp", SdpMsg{Session: hostileSession, Sdp: "v=0", Kind: SdpOffer})
	if !w.waitFor("sdp relay:", time.Now().Add(2*time.Second)) {
		t.Fatal("sdp relay log entry not observed within deadline")
	}
	assertLogEscaped(t, w.captured(), "sdp relay:", "session in sdp relay error")
}

// TestFailedAgentAuthQuotesDeviceID: hostile device ID (≤128 bytes, passes length gate) through
// the full enforced handshake against an empty resolver (ErrDeviceUnknown). Server logs device
// at rejection with %q. This guard predates this patch: retain it as regression
// coverage without counting it as a newly repaired identifier path.
func TestFailedAgentAuthQuotesDeviceID(t *testing.T) {
	emptyResolver := &fakeResolver{identities: map[string]*DeviceIdentity{}}
	w := captureLog(t)
	ts := newTestSignaling(t, time.Minute, nil, emptyResolver, escapingTestLimits)

	c, _, err := ts.dialWS()
	if err != nil {
		t.Fatalf("dialWS: %v", err)
	}
	writeJSONMsg(t, c, "register_agent", RegisterAgent{
		Device: hostileDevice, Pubkey: agentAuthGoldenPubkeyHex, Nat: NatOpen,
	})
	ch := readChallenge(t, c, 2*time.Second)

	// Correct nonce (passes nonce check) + valid-length garbage sig (reaches resolver lookup).
	// Empty resolver returns ErrDeviceUnknown → server logs hostile device at rejection.
	writeJSONMsg(t, c, "agent_auth_response", AgentAuthResponse{
		Device: hostileDevice, Nonce: ch.Nonce, Sig: strings.Repeat("00", 64),
	})
	if !waitForClose(c, 2*time.Second) { // do not retry after a terminal read error
		t.Fatal("rejected agent connection did not close")
	}

	if !w.waitFor("agent auth rejected", time.Now().Add(time.Second)) {
		t.Fatal("agent auth rejection log entry not observed within deadline")
	}
	assertLogEscaped(t, w.captured(), "agent auth rejected", "device ID in auth rejection")
}

// assertLogEscaped checks opPrefix's log line for raw control bytes and forged-line injection.
// Removing %q from the error path fails the injection check; from the identifier path it fails
// the raw-byte checks — the two failure modes are distinct.
func assertLogEscaped(t *testing.T, captured, opPrefix, fieldDesc string) {
	t.Helper()

	var opLine string
	for _, line := range strings.Split(captured, "\n") {
		if strings.Contains(line, opPrefix) {
			opLine = line
			break
		}
	}
	if opLine == "" {
		t.Fatalf("no log line containing %q in captured output:\n%s", opPrefix, captured)
	}

	// Literal newline before forgedLine = injection; fires when %q removed from error/identifier.
	if strings.Contains(captured, "\n"+forgedLine) {
		t.Errorf("%s: raw newline before forged payload — log injection not prevented (%%q missing)", fieldDesc)
	}

	// Raw control bytes must not survive; after %q they become escape sequences.
	for _, raw := range []string{"\r", "\t", "\x1b", "\u2028"} {
		if strings.Contains(opLine, raw) {
			t.Errorf("%s: raw control byte %q on log line — field must be quoted with %%q:\n  %s", fieldDesc, raw, opLine)
		}
	}

	// Escaped \n must be present, confirming the newline was actually quoted (not absent or raw).
	if !strings.Contains(opLine, `\n`) {
		t.Errorf("%s: escape sequence \\n absent — field may not be quoted with %%q:\n  %s", fieldDesc, opLine)
	}
}

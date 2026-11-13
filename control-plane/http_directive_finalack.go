package controlplane

// POST /agent/directives/{id}/final-ack - the removal-confirmation route (docs/65 sec. 2b, operator decision
// 2026-11-01). PUBLIC (outside the auth -> tenant chain, like /enroll/redeem): the only credential is the
// device-key SIGNATURE (RMTDIRACKv1), verified against the STORED row's tenant / device / key fingerprint and the
// machine's stored public key. The body carries NO device id: nothing the caller says picks the device or the
// tenant. After a removal the device is a tombstone on every other path (registration, identity lookup,
// enrollment); this route can only confirm, or record, the TERMINAL REMOVAL RESULT of an uninstall that was
// really issued, and it never delivers directives, registers, shows presence or touches sessions.
//
// Answers (every body carries "outcome" except 404/403/429/400, which are the plain error shape):
//
//	200 {"outcome":"applied"|"replay","state":S}   applied now / already applied (a lost response)
//	409 {"outcome":"refused","state":S,"error":..} bad transition / stale / non-terminal to / key changed at apply
//	404 {"error":"unknown directive"}               EVERY pre-authentication failure, identical: unknown id,
//	                                                malformed id, wrong kind, bad signature, another device's
//	                                                key, key changed (no oracle on ids, keys or state)
//	410 {"error":..}                                the 7-day window after the result has passed, or the directive was
//	                                                closed because an Owner FORGOT the machine (docs/65 sec. 8): a
//	                                                late result is neither applied nor confirmed, whatever it says
//	429 {"error":..}                                rate limited (Retry-After): failures AND total volume
//	400 {"error":..}                                malformed body
//
// Only a request that PROVED possession of the device key (valid signature over the stored row) can ever see
// the directive's state in an answer.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
)

type directiveFinalAckBody struct {
	From   string `json:"from"`
	To     string `json:"to"`
	TsMs   int64  `json:"ts_ms"`
	Detail string `json:"detail"`
	Sig    string `json:"sig"`
}

// finalAckWindowOpen reports whether the route still answers for a directive in state st that last changed at
// updatedAt: always while it is active; for directiveFinalAckWindow after it reached complete / failed.
// Anything else (cancelled, expired) never carried a removal result, and a FORGOTTEN directive (an Owner closed
// it with the machine, docs/65 sec. 8) is closed for good: a late result must not resurrect it, so it is never
// open, however recent.
func finalAckWindowOpen(st DirectiveState, updatedAt, now time.Time) bool {
	switch {
	case st.active():
		return true
	case st == DirectiveComplete || st == DirectiveFailed:
		return !now.After(updatedAt.Add(directiveFinalAckWindow))
	}
	return false
}

// finalAckClosedMessage is the 410 body for a directive whose final-ack window is closed. The caller has
// already PROVED the device key by then, so it may be told why: a forgotten directive is closed by an Owner's
// decision, not by the clock.
func finalAckClosedMessage(st DirectiveState) string {
	if st == DirectiveForgotten {
		return "this removal was closed when an owner forgot the machine; no result was recorded"
	}
	return "the final-acknowledgement window for this directive has passed"
}

// Defaults for the total-volume cap: generous for a helper that retries a bounded number of times, far below
// anything a scanner needs.
const (
	finalAckDefaultBurst  = 30
	finalAckDefaultPerSec = 30.0 / 600.0
)

func (s *Server) finalAckTotal() *rateLimiter {
	s.finalAckOnce.Do(func() {
		burst, per := s.FinalAckBurst, s.FinalAckPerSec
		if burst <= 0 {
			burst = finalAckDefaultBurst
		}
		if per <= 0 {
			per = finalAckDefaultPerSec
		}
		s.finalAckLimiter = newRateLimiter(per, burst, 100000)
	})
	return s.finalAckLimiter
}

// finalAckEd25519Verify is ed25519.Verify; a test counts its calls per path.
var finalAckEd25519Verify = ed25519.Verify

// dummyFinalAckKey / dummyFinalAckSig stand in when there is no usable target key or signature, so
// finalAckVerify does the same work on every path.
var (
	dummyFinalAckKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	dummyFinalAckSig = make([]byte, ed25519.SignatureSize)
	dummyFinalAckFP  = strings.Repeat("0", 64) // a well-formed fingerprint, so the preimage is built the same way
)

// finalAckVerify performs EXACTLY ONE ed25519 verification over a signing preimage built the same way on
// every path: an unknown id (tgt == nil), a key that no longer matches the directive's fingerprint, an
// undecodable signature and a wrong signature each make one verifier call, so the handler does not do
// visibly more work for a known id. (One call is not equal work in a variable-time verifier; residual
// differences are bounded by the throttles.) It reports true only for a valid signature by the stored key.
func finalAckVerify(tgt *DirectiveFinalAckTarget, dirID string, a DirectiveAck) bool {
	usable := tgt != nil
	key, tenant, device, keyFP := dummyFinalAckKey, dirID, dirID, dummyFinalAckFP
	if tgt != nil {
		tenant, device, keyFP = tgt.TenantID, tgt.DeviceID, tgt.KeyFP
		raw, err := hex.DecodeString(tgt.MachinePubkey)
		fp := fingerprintOf(tgt.MachinePubkey)
		if err == nil && len(raw) == ed25519.PublicKeySize && fp != "" && fp == tgt.KeyFP {
			key = ed25519.PublicKey(raw)
		} else {
			usable = false
		}
	}
	sig, err := hex.DecodeString(a.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		sig, usable = dummyFinalAckSig, false
	}
	msg, err := directiveAckSigningBytes(tenant, device, dirID, keyFP, a.From, a.To, a.TsMs, a.Detail)
	if err != nil {
		msg, usable = []byte(dirID), false
	}
	ok := finalAckEd25519Verify(key, msg, sig)
	return usable && ok
}

func (s *Server) handleDirectiveFinalAck(w http.ResponseWriter, r *http.Request) {
	th := s.throttle()
	ip := clientIP(r)
	keys := []string{ipKey("directive-final-ack", ip)}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	// The total-volume cap counts EVERY request (successes too), before any work.
	if !s.finalAckTotal().allow(ip, time.Now()) {
		writeThrottled(w, time.Duration(float64(time.Second)/s.finalAckTotal().perSec))
		return
	}
	// unknown is THE answer to every pre-authentication failure: same status, same body.
	unknown := func() {
		th.Fail(keys...)
		writeError(w, http.StatusNotFound, "unknown directive")
	}
	var body directiveFinalAckBody
	if !decodeStrict(w, r, &body) {
		th.Fail(keys...)
		return
	}
	dirID := r.PathValue("id")
	if validateDirectiveID(dirID) != nil {
		unknown() // syntactic: says nothing about which ids exist
		return
	}
	if len(body.Detail) > maxDirectiveDetailBytes || len(body.From) > 32 || len(body.To) > 32 {
		th.Fail(keys...)
		writeError(w, http.StatusBadRequest, "malformed acknowledgement")
		return
	}
	ack := DirectiveAck{DirectiveID: dirID, From: body.From, To: body.To, TsMs: body.TsMs, Detail: body.Detail, Sig: body.Sig}
	tgt, err := s.Directives.FinalAckTarget(r.Context(), dirID)
	if err != nil && !errors.Is(err, ErrDirectiveNotFound) {
		writeError(w, http.StatusInternalServerError, "could not read the directive")
		return
	}
	if err != nil {
		tgt = nil
	}
	// The row's identity, never the message's: tenant, device, key fingerprint and id are all stored values.
	// Unknown id, bad signature, another device's key AND a key that no longer matches the directive's
	// fingerprint are all the SAME answer after the SAME work: the caller has not proven the key.
	if !finalAckVerify(tgt, dirID, ack) {
		unknown()
		return
	}
	// Past the signature, so none of what follows is an oracle for an unauthenticated caller.
	// A directive an Owner closed by forgetting its machine answers 410 whatever the result says: the removal's
	// outcome is no longer something this control plane will record, confirm or replay (the agent ends its
	// report as not confirmed and finishes its own cleanup).
	if tgt.State == DirectiveForgotten {
		writeError(w, http.StatusGone, finalAckClosedMessage(tgt.State))
		return
	}
	if to := directiveAckTarget(body.To); to != DirectiveComplete && to != DirectiveFailed {
		writeJSON(w, http.StatusConflict, map[string]string{"outcome": "refused", "state": string(tgt.State),
			"error": "only a terminal removal result is accepted on this route"})
		return
	}
	if !finalAckWindowOpen(tgt.State, tgt.UpdatedAt, tgt.Now) {
		writeError(w, http.StatusGone, finalAckClosedMessage(tgt.State))
		return
	}
	got, applied, err := s.Directives.ApplyAckVia(r.Context(), tgt.TenantID, dirID, tgt.DeviceID, ack, directiveFinalAckChannel)
	if err != nil {
		switch {
		case errors.Is(err, ErrDirectiveBadTransition), errors.Is(err, ErrDirectiveKeyChanged), errors.Is(err, ErrDirectiveBadTimestamp),
			errors.Is(err, ErrDirectiveStaleAck), errors.Is(err, ErrDirectiveExpired):
			st := tgt.State
			if got != nil {
				st = got.State
			}
			writeJSON(w, http.StatusConflict, map[string]string{"outcome": "refused", "state": string(st), "error": err.Error()})
		case errors.Is(err, ErrDirectiveFinalAckWindowClosed):
			// Judged on the LOCKED row: a forget that landed between the lookup and the apply reads as forgotten here.
			closedState := tgt.State
			if got != nil {
				closedState = got.State
			}
			writeError(w, http.StatusGone, finalAckClosedMessage(closedState))
		case errors.Is(err, ErrDirectiveNotFound):
			unknown()
		default:
			writeError(w, http.StatusInternalServerError, "could not apply the acknowledgement")
		}
		return
	}
	th.Reset(keys...)
	outcome := "replay"
	if applied {
		outcome = "applied"
	}
	writeJSON(w, http.StatusOK, map[string]string{"outcome": outcome, "state": string(got.State)})
}

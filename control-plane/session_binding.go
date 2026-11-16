package controlplane

// Session binding trust material (docs/69 §3.1, §3.6). Every route that brokers a session takes the
// console's ephemeral Ed25519 public key (`console_pubkey`) and answers with `device_binding`:
//
//	{"mode": "warn"|"require", "device_pubkey": "<hex>", "grant": "<RMTBINDGv1 JSON>"}
//
// The console takes the machine's key ONLY from here (never from signaling) and forwards the grant to
// the agent unchanged. `mode` is the tenant's policy for a session that ends up unbound. Ed decided
// (2026-11-15) that every tenant starts at warn.

import (
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

// SessionBindingMode is the tenant's policy for sessions that cannot be bound.
type SessionBindingMode string

const (
	// SessionBindingWarn: an unbound session is allowed and the console marks it "not verified".
	SessionBindingWarn SessionBindingMode = "warn"
	// SessionBindingRequire: a session that cannot be bound is refused (here when the trust material
	// cannot be issued; in the console when the agent's proof is missing or wrong).
	SessionBindingRequire SessionBindingMode = "require"
)

// bindingGrantTTL bounds how long a grant may sit between issuance and the console installing it on the
// agent, which happens only after ICE, DTLS and the data channel. The agent checks it at install time.
const bindingGrantTTL = 2 * time.Minute

// consoleKeyBody is embedded in request bodies that may carry the console key.
type consoleKeyBody struct {
	ConsolePubkey string `json:"console_pubkey,omitempty"`
}

// validConsolePubkey reports whether h is a 32-byte key in hex. An empty value is "not sent", which the
// caller handles separately.
func validConsolePubkey(h string) bool {
	_, err := parseConsolePubkey(h)
	return err == nil
}

// refuseMalformedConsoleKey writes 400 for a console key that was sent but is not a key, so routes can
// refuse it BEFORE they create a session record. Returns true when it wrote the refusal.
func refuseMalformedConsoleKey(w http.ResponseWriter, h string) bool {
	if h != "" && !validConsolePubkey(h) {
		writeError(w, http.StatusBadRequest, "console_pubkey must be a hex-encoded 32-byte Ed25519 public key")
		return true
	}
	return false
}

// sessionBindingMode is the tenant's binding policy: Server.BindingMode when wired, else warn (docs/69
// §8: every tenant starts at warn; require once the fleet runs the enforcing agent). Any value other than
// the two known modes is treated as require (§3.6: an unreadable setting fails closed).
func (s *Server) sessionBindingMode(tenantID string) SessionBindingMode {
	if s.BindingMode == nil {
		return SessionBindingWarn
	}
	switch m := s.BindingMode(tenantID); m {
	case SessionBindingWarn, SessionBindingRequire:
		return m
	default:
		return SessionBindingRequire
	}
}

// normalisedDeviceKey returns a stored Ed25519 public key (a machine's enrolled key, or an attended
// guest's key pinned at redemption) as lowercase hex, or "" when it is missing or malformed. Never falls
// back to anything signaling reports.
func normalisedDeviceKey(stored string) string {
	b, err := hex.DecodeString(stored)
	if err != nil || len(b) != 32 {
		return ""
	}
	return hex.EncodeToString(b)
}

// bindingFailureReasons is the closed set a console may report (docs/69 §3.5). A closed set keeps the
// audit trail queryable and stops free text from a browser reaching the hash chain.
var bindingFailureReasons = map[string]bool{
	"bad_signature":        true, // the agent's proof did not verify against device_pubkey
	"fingerprint_mismatch": true, // the transcript did not match the console's live DTLS association
	"no_proof":             true, // the agent sent no proof in time where one was required
	"multiple_transports":  true, // the peer connection used more than one DTLS transport
	"unsupported_browser":  true, // no WebCrypto Ed25519 or certificate stats
	"agent_refused":        true, // the agent refused the console's proof or the grant
}

type bindingFailedRequest struct {
	Reason string `json:"reason"`
}

// handleSessionBindingFailed: POST /sessions/{id}/binding-failed. The console reports that it could not
// verify the session (and has ended it). Only the session's own technician may report, and it is
// recorded as `session.binding_failed`. The id may name an unattended session record or an attended
// session.
func (s *Server) handleSessionBindingFailed(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req bindingFailedRequest
	if err := decodeJSONBody(w, r, maxSmallJSONBodyBytes, &req, "malformed request body"); err != nil {
		return
	}
	if !bindingFailureReasons[req.Reason] {
		writeError(w, http.StatusBadRequest, "unknown binding failure reason")
		return
	}
	id := r.PathValue("id")
	meta := map[string]any{"reason": req.Reason}
	found := false
	if s.SessionRecords != nil {
		rec, err := s.SessionRecords.GetSession(r.Context(), p.TenantID, id)
		switch {
		case err == nil:
			if !sameUserID(rec.TechnicianID, p.UserID) {
				writeError(w, http.StatusForbidden, "only the session's technician may report its verification")
				return
			}
			meta["machine_id"] = rec.MachineID
			found = true
		case !errors.Is(err, ErrSessionRecordNotFound):
			writeError(w, http.StatusInternalServerError, "could not resolve session")
			return
		}
	}
	if !found && s.Attended != nil {
		a, err := s.Attended.Get(r.Context(), p.TenantID, id)
		switch {
		case err == nil:
			if !sameUserID(a.TechnicianID, p.UserID) {
				writeError(w, http.StatusForbidden, "only the session's technician may report its verification")
				return
			}
			meta["device_id"] = a.DeviceID
			meta["attended"] = true
			found = true
		case !errors.Is(err, ErrAttendedNotFound):
			writeError(w, http.StatusInternalServerError, "could not resolve attended session")
			return
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "unknown session")
		return
	}
	if err := s.recordMgmtAudit(r, "session.binding_failed", "session", id, meta); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recorded": true})
}

// attachDeviceBinding adds `device_binding` to a brokered-session response. It refuses only in require
// mode; in warn mode a session that cannot be bound is still brokered and the console shows it as not
// verified.
// sessionID is the control-plane session id the ticket carries; deviceID the agent's device id;
// storedDeviceKey the key the control plane holds for that device.
func (s *Server) attachDeviceBinding(resp map[string]any, sessionID, deviceID, storedDeviceKey, userID, tenantID string,
	access SessionAccessLevel, consolePubkey string, nowMs int64) *sessionRefusal {
	if !s.BindingEnabled {
		return nil // not rolled out yet: no device_binding at all, and the console shows no mark
	}
	mode := s.sessionBindingMode(tenantID)
	binding := map[string]any{"mode": string(mode)}
	resp["device_binding"] = binding
	if consolePubkey == "" {
		if mode == SessionBindingRequire {
			return &sessionRefusal{Status: http.StatusBadRequest,
				Msg: "this organisation requires verified sessions; reload the console to update it"}
		}
		binding["unavailable"] = "console did not send a key"
		return nil
	}
	deviceKey := normalisedDeviceKey(storedDeviceKey)
	if deviceKey == "" {
		if mode == SessionBindingRequire {
			return &sessionRefusal{Status: http.StatusConflict,
				Msg: "this machine has no enrolled device key, so the session cannot be verified; re-enrol the agent"}
		}
		binding["unavailable"] = "machine has no enrolled device key"
		return nil
	}
	grant, err := s.Grants.MintBindingGrant(sessionID, deviceID, tenantID, userID, access, consolePubkey,
		nowMs, nowMs+bindingGrantTTL.Milliseconds())
	if err != nil {
		if mode == SessionBindingRequire {
			return &sessionRefusal{Status: http.StatusInternalServerError, Msg: "the session verification grant could not be issued"}
		}
		binding["unavailable"] = "grant could not be issued"
		return nil
	}
	js, err := grant.JSON()
	if err != nil {
		return &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not encode the session verification grant"}
	}
	binding["device_pubkey"] = deviceKey
	binding["grant"] = js
	return nil
}

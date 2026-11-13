package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

type GuestEndOutcome string

const (
	GuestEndEnded        GuestEndOutcome = "ended"
	GuestEndAlreadyEnded GuestEndOutcome = "already_ended"
	GuestEndNotFound     GuestEndOutcome = "not_found"
	GuestEndOtherDevice  GuestEndOutcome = "other_device"
)

// GuestEndStore ends only sessions belonging to the supplied tenant and device. Exactly one
// concurrent caller can transition an open record: that caller commits the end and its device
// audit event together, or neither. Already-ended records retain their timestamp and write no
// audit, including records ended by an administrator. Invisible records return not_found;
// another device's record returns other_device even when it is already ended.
type GuestEndStore interface {
	EndSessionForDevice(ctx context.Context, tenantID, sessionID, deviceID string, at time.Time, report SessionEndReport) (GuestEndOutcome, error)
}

// SessionEndReason is why an agent says one of its sessions ended (docs/49). It is recorded in
// the session.end audit event; it never changes what the transition does.
type SessionEndReason string

const (
	EndReasonGuestEnded  SessionEndReason = "guest_ended"
	EndReasonViewerLeft  SessionEndReason = "viewer_left"
	EndReasonLeaseLapsed SessionEndReason = "lease_lapsed"
	EndReasonMaxDuration SessionEndReason = "max_duration"
	EndReasonIdle        SessionEndReason = "idle"
	EndReasonPolicy      SessionEndReason = "policy"
	EndReasonServiceStop SessionEndReason = "service_stop"
	EndReasonOther       SessionEndReason = "other"
)

// SessionEndReport is what the agent says about one ended session (docs/49 §4): why, and how long
// the report waited in the agent's queue before this request. ended_at records when the control
// plane OBSERVED the end; QueueAgeMs (nil when the agent did not send it) lets reports label an
// agent-reported duration as approximate.
type SessionEndReport struct {
	Reason     SessionEndReason
	QueueAgeMs *int64
}

// maxReportQueueAgeMs bounds a believable queue age: 30 days, far beyond any agent queue's life.
const maxReportQueueAgeMs = 30 * 24 * 60 * 60 * 1000

// normalizeEndReason maps any value outside the enum to "other": a newer agent's reason must
// never fail its report.
func normalizeEndReason(s string) SessionEndReason {
	switch r := SessionEndReason(s); r {
	case EndReasonGuestEnded, EndReasonViewerLeft, EndReasonLeaseLapsed, EndReasonMaxDuration,
		EndReasonIdle, EndReasonPolicy, EndReasonServiceStop, EndReasonOther:
		return r
	}
	return EndReasonOther
}

// SessionEndedFeature is advertised by GET /internal/capabilities when POST
// /internal/sessions/{id}/ended is mounted. Signaling advertises it to agents only after a
// positive probe (docs/49 v4).
const SessionEndedFeature = "session_ended_v1"

// handleInternalCapabilities answers signaling's probe with what this control plane supports. A
// 404 (route absent) means an older control plane; the session-end report then stays guest-only.
func (s *Server) handleInternalCapabilities(w http.ResponseWriter, r *http.Request) {
	if !s.deviceIdentityAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	features := []string{}
	if s.GuestEnds != nil && s.Machines != nil {
		features = append(features, SessionEndedFeature)
	}
	if s.directiveInternalMounted() {
		features = append(features, DirectiveFeature)
	}
	if s.HelpRequests != nil && s.Machines != nil {
		features = append(features, HelpRequestFeature)
	}
	writeJSON(w, http.StatusOK, map[string][]string{"features": features})
}

type guestEndRequest struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id"`
}

// The shared raw-text decoder deliberately uses json.Unmarshal. Reject unknown fields here
// without changing its behavior for the other endpoints that use it.
func (b *guestEndRequest) UnmarshalJSON(raw []byte) error {
	type body guestEndRequest
	var out body
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return err
	}
	*b = guestEndRequest(out)
	return nil
}

// sessionEndedRequest is guestEndRequest plus the agent's reason (docs/49).
type sessionEndedRequest struct {
	DeviceID   string `json:"device_id"`
	TenantID   string `json:"tenant_id"`
	Reason     string `json:"reason"`
	QueueAgeMs *int64 `json:"queue_age_ms,omitempty"`
}

func (b *sessionEndedRequest) UnmarshalJSON(raw []byte) error {
	type body sessionEndedRequest
	var out body
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return err
	}
	*b = sessionEndedRequest(out)
	return nil
}

// handleGuestEnded is the original guest-only report; it stays for agents and signaling that
// predate POST /internal/sessions/{id}/ended.
func (s *Server) handleGuestEnded(w http.ResponseWriter, r *http.Request) {
	s.handleSessionEndReport(w, r, false)
}

// handleSessionEnded is the generalised report: the agent ended one of its sessions for `reason`.
// Same authority, transition and audit as the guest-ended report; only the reason differs.
func (s *Server) handleSessionEnded(w http.ResponseWriter, r *http.Request) {
	s.handleSessionEndReport(w, r, true)
}

func (s *Server) handleSessionEndReport(w http.ResponseWriter, r *http.Request, withReason bool) {
	th := s.throttle()
	keys := []string{ipKey("guest-ended", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	if !s.deviceIdentityAuthorized(r) {
		th.Fail(keys...)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var body guestEndRequest
	report := SessionEndReport{Reason: EndReasonGuestEnded}
	if withReason {
		var full sessionEndedRequest
		if err := decodeStrictJSONBody(w, r, 1024, &full, "invalid session end"); err != nil {
			return
		}
		if full.QueueAgeMs != nil && (*full.QueueAgeMs < 0 || *full.QueueAgeMs > maxReportQueueAgeMs) {
			writeError(w, http.StatusBadRequest, "invalid queue age")
			return
		}
		body = guestEndRequest{DeviceID: full.DeviceID, TenantID: full.TenantID}
		report = SessionEndReport{Reason: normalizeEndReason(full.Reason), QueueAgeMs: full.QueueAgeMs}
	} else if err := decodeStrictJSONBody(w, r, 1024, &body, "invalid guest end"); err != nil {
		return
	}
	tenant, tenantOK := parsePgUUID(body.TenantID)
	device, deviceOK := parsePgUUID(body.DeviceID)
	id, idOK := parsePgUUID(r.PathValue("id"))
	if !tenantOK || !deviceOK || !idOK {
		writeError(w, http.StatusBadRequest, "invalid UUID")
		return
	}
	identity, err := s.Machines.LookupDeviceIdentity(r.Context(), device)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			writeError(w, http.StatusNotFound, "unknown device")
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"outcome": "unavailable"})
		}
		return
	}
	if canonicalUUIDish(identity.TenantID) != tenant {
		writeError(w, http.StatusForbidden, "device not in tenant")
		return
	}
	// Authenticated misses must not fail the shared signaling-IP throttle. The store owns
	// both the transition and audit so a failed append remains retryable.
	outcome, err := s.GuestEnds.EndSessionForDevice(r.Context(), tenant, id, device, time.Now().UTC(), report)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"outcome": "unavailable"})
		return
	}
	switch outcome {
	case GuestEndEnded, GuestEndAlreadyEnded:
		// docs/51 §8: the agent's authenticated end report is the one statement that the session no
		// longer exists on the machine. Record it (first report wins) and finalize a releasing
		// transfer of it, in the transfer store's lock order. Both outcomes mean "closed", so an agent
		// retry after a failed finalize completes it. An unavailable store is a 503 the agent retries.
		if withReason && !s.noteTransferAgentEnded(r.Context(), tenant, id) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"outcome": "unavailable"})
			return
		}
		th.Reset(keys...)
		writeJSON(w, http.StatusOK, map[string]GuestEndOutcome{"outcome": outcome})
	case GuestEndNotFound:
		writeError(w, http.StatusNotFound, "session not found")
	case GuestEndOtherDevice:
		writeError(w, http.StatusForbidden, "session not on device")
	default:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"outcome": "unavailable"})
	}
}

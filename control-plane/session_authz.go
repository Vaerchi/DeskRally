package controlplane

// checkHeldSession is the authorization a session's HOLDER needs to keep acting on it: what a lease
// renewal requires, factored out so the toolbox run endpoint (docs/design-shared-toolbox.md) asks
// exactly the same question ("would a renewal be granted now?") without minting or extending
// anything. It performs NO writes. The one renewal step that writes, ending a session that has
// exceeded the tenant's maximum duration, is reported as refusal.expired for the renewal handler to
// carry out; other callers just refuse.

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type heldSession struct {
	Rec     *SessionRecord
	Machine *Machine
	// Access is the level the control plane would sign for this session NOW: the group's current
	// mandate, re-read on every call (never frozen at session start).
	Access SessionAccessLevel
}

type sessionRefusal struct {
	Status int
	Msg    string
	Denied error // set for a capability denial (rendered with writeDenied)
	// Expired: the session exceeded the tenant's MaxSessionSeconds. Renewal ends it; others refuse.
	Expired bool
}

func (r *sessionRefusal) write(w http.ResponseWriter) {
	if r.Denied != nil {
		writeDenied(w, r.Denied)
		return
	}
	writeError(w, r.Status, r.Msg)
}

// verb completes the refusal messages ("renew a session lease", "run a toolbox item").
func (s *Server) checkHeldSession(ctx context.Context, p *Principal, sessionID, verb string) (*heldSession, *sessionRefusal) {
	if s.SessionRecords == nil {
		return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "session store not configured"}
	}
	if s.Machines == nil {
		return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "machine store not configured"}
	}
	rec, err := s.SessionRecords.GetSession(ctx, p.TenantID, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionRecordNotFound) {
			return nil, &sessionRefusal{Status: http.StatusNotFound, Msg: "unknown session"}
		}
		return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not resolve session"}
	}
	// Group-scoped on the STORED record's machine group (the machine's LIVE group), so a caller cannot
	// widen their scope by naming a session they cannot see, and a machine moved out of the caller's
	// reach stops being usable by them immediately.
	if err := p.Grant.RequireMachine(CapStartSession, rec.MachineGroupID); err != nil {
		return nil, &sessionRefusal{Denied: err}
	}
	// 409 rather than 404 so a console can tell "someone ended this" from "no such session".
	if rec.EndedAt != nil {
		return nil, &sessionRefusal{Status: http.StatusConflict, Msg: "session has ended"}
	}
	// Only the technician holding the session. Not redundant with the capability: an Admin holds
	// CapStartSession tenant-wide and could otherwise act on SOMEONE ELSE'S session. Precedes the
	// max-age check, so an unauthorized caller never learns or triggers the expiry.
	if !sameUserID(p.UserID, rec.TechnicianID) {
		return nil, &sessionRefusal{Status: http.StatusForbidden, Msg: "only the technician holding this session may " + verb}
	}
	if s.SessionPolicies != nil {
		pol, perr := s.SessionPolicies.Get(ctx, p.TenantID)
		if perr != nil {
			return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not resolve session policy"}
		}
		if pol.MaxSessionSeconds > 0 && time.Since(rec.StartedAt) > time.Duration(pol.MaxSessionSeconds)*time.Second {
			return &heldSession{Rec: rec}, &sessionRefusal{Status: http.StatusConflict,
				Msg: "session has exceeded its maximum duration", Expired: true}
		}
	}
	m, err := s.Machines.GetMachine(ctx, p.TenantID, rec.MachineDeviceID)
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			return nil, &sessionRefusal{Status: http.StatusNotFound, Msg: "unknown machine"}
		}
		return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not resolve machine"}
	}
	// An administratively out-of-service machine stops being usable within one lease.
	if m.Status == MachineStatusQuarantined || m.Status == MachineStatusRetired || m.Status == MachineStatusRemoved {
		return nil, &sessionRefusal{Status: http.StatusConflict, Msg: "machine is " + m.Status + "; reactivate it to " + verb}
	}
	access := SessionAccessControl
	if s.GroupSessionPolicies != nil && rec.MachineGroupID != "" {
		eff, gerr := s.EffectivePolicy(ctx, p.TenantID, rec.MachineGroupID)
		if gerr != nil {
			return nil, &sessionRefusal{Status: http.StatusInternalServerError, Msg: "could not resolve group session policy"}
		}
		if eff.Conflict != "" {
			return nil, &sessionRefusal{Status: http.StatusConflict, Msg: eff.Conflict}
		}
		gp := eff.GroupSessionPolicy
		if gp.EnforceViewOnly {
			access = SessionAccessViewOnly
		}
	}
	return &heldSession{Rec: rec, Machine: m, Access: access}, nil
}

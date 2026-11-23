package controlplane

// Tenant recording policy API (docs/63 D5, §2a C10):
//
//	GET /tenant/recording-policy   the policy (CapManageTenant or CapViewRecordings)
//	PUT /tenant/recording-policy   replace it (CapManageTenant), AUDITED
//
// FAIL-CLOSED. The PUT body must name every field (DecodeRecordingPolicyPut): a stale console, a
// full-overwrite client that predates the setting, or a body that merely lacks retention_days is a 400 —
// it can never switch storage on by omission or by a default. retention_days is 0 (do not store) or
// 1..365; the caps are refused, never clamped, when out of range.
//
// AUDIT FIRST. Turning central storage on, or widening a cap, changes what the server keeps about a
// customer's screen. So the audit row is persisted BEFORE the policy changes, and an audit store that
// cannot be written leaves the policy exactly as it was (500). The reverse order (the repo's usual
// "mutate, then audit") would leave a change that nobody can account for if the audit write failed.
//
// Changing the policy never touches existing recordings except through the sweeper's rule (C10): a
// SHORTER retention applies to existing rows on the next sweep, a longer one is NEVER applied to them,
// and 0 only refuses new creates. API tokens are refused outright.

import (
	"errors"
	"io"
	"log"
	"net/http"
)

type recPolicyJSON struct {
	RetentionDays     int   `json:"retention_days"`
	MaxRecordingBytes int64 `json:"max_recording_bytes"`
	QuotaBytes        int64 `json:"quota_bytes"`
	Enabled           bool  `json:"enabled"`
	// StorageAvailable is false when this deployment has no recording volume / master key configured:
	// the policy can be read but nothing will be stored whatever it says.
	StorageAvailable bool `json:"storage_available"`
}

func (s *Server) recPolicyJSON(p RecordingPolicy) recPolicyJSON {
	return recPolicyJSON{RetentionDays: p.RetentionDays, MaxRecordingBytes: p.MaxRecordingBytes,
		QuotaBytes: p.QuotaBytes, Enabled: p.Enabled(), StorageAvailable: s.Recording.ready()}
}

func (s *Server) handleGetRecordingPolicy(w http.ResponseWriter, r *http.Request) {
	recNoStore(w)
	p := principalFrom(r.Context())
	if p == nil || p.Grant == nil {
		recErr(w, http.StatusUnauthorized, "unauthenticated", nil)
		return
	}
	if p.APIToken {
		recErr(w, http.StatusForbidden, "recording settings are not available to API tokens", nil)
		return
	}
	if err := p.Grant.RequireAny(CapManageTenant, CapViewRecordings); err != nil {
		recJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	pol, err := s.Recording.Store.GetPolicy(r.Context(), p.TenantID)
	if err != nil {
		log.Printf("recording policy: read: %v", err)
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return
	}
	recJSON(w, http.StatusOK, s.recPolicyJSON(pol))
}

func (s *Server) handleSetRecordingPolicy(w http.ResponseWriter, r *http.Request) {
	recNoStore(w)
	p := principalFrom(r.Context())
	if p == nil || p.Grant == nil {
		recErr(w, http.StatusUnauthorized, "unauthenticated", nil)
		return
	}
	if p.APIToken {
		recErr(w, http.StatusForbidden, "recording settings are not available to API tokens", nil)
		return
	}
	if err := p.Grant.Require(CapManageTenant); err != nil {
		recJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			recErr(w, http.StatusRequestEntityTooLarge, "body_too_large", nil)
			return
		}
		recErr(w, http.StatusBadRequest, "unreadable body", nil)
		return
	}
	next, err := DecodeRecordingPolicyPut(body)
	if err != nil {
		recErr(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	prev, err := s.Recording.Store.GetPolicy(r.Context(), p.TenantID)
	if err != nil {
		log.Printf("recording policy: read before write: %v", err)
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return
	}
	// Audit first (see the header): no audit row, no change.
	if s.MgmtAudit == nil {
		recErr(w, http.StatusInternalServerError, "audit_unavailable", nil)
		return
	}
	if err := s.recordMgmtAudit(r, "tenant.recording_policy.set", "tenant", p.TenantID, map[string]any{
		"old": map[string]any{"retention_days": prev.RetentionDays, "max_recording_bytes": prev.MaxRecordingBytes, "quota_bytes": prev.QuotaBytes},
		"new": map[string]any{"retention_days": next.RetentionDays, "max_recording_bytes": next.MaxRecordingBytes, "quota_bytes": next.QuotaBytes},
	}); err != nil {
		log.Printf("recording policy: audit: %v", err)
		recErr(w, http.StatusInternalServerError, "audit_unavailable", nil)
		return
	}
	if err := s.Recording.Store.SetPolicy(r.Context(), p.TenantID, next); err != nil {
		log.Printf("recording policy: write: %v", err)
		// The audit row above already says the change was made; say, just as durably, that it was not.
		// Best effort (the store that just failed may be the same database): a failure here is logged, and
		// the 500 below is the answer either way. The error text is NOT recorded (it can carry
		// driver/DSN detail); only the attempted values and the fixed reason are.
		if aerr := s.recordMgmtAudit(r, "tenant.recording_policy.set_failed", "tenant", p.TenantID, map[string]any{
			"reason": "store_write_failed",
			"old":    map[string]any{"retention_days": prev.RetentionDays, "max_recording_bytes": prev.MaxRecordingBytes, "quota_bytes": prev.QuotaBytes},
			"new":    map[string]any{"retention_days": next.RetentionDays, "max_recording_bytes": next.MaxRecordingBytes, "quota_bytes": next.QuotaBytes},
		}); aerr != nil {
			log.Printf("recording policy: compensating audit row (tenant.recording_policy.set_failed) not written: %v", aerr)
		}
		recErr(w, http.StatusInternalServerError, "internal", nil)
		return
	}
	recJSON(w, http.StatusOK, s.recPolicyJSON(next))
}

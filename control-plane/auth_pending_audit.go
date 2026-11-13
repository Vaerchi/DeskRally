package controlplane

// F20 partial follow-up: sampled telemetry for the second-factor-pending state.
//
// One event attempt is admitted per 30 seconds per AuthService instance, using constant state.
// Sampling can omit other accounts' or tenants' events during that interval. It provides a
// partial credential-stuffing signal; per-account completeness and cross-tenant fairness would
// require a separate telemetry policy. F20's tenant-slug timing question is unchanged.

import (
	"log"
	"net/http"
	"time"
)

// pendingAuditCooldown is the minimum interval between auth.second_factor_pending events
// across the whole AuthService instance. Service-wide — NOT per account or per tenant.
const pendingAuditCooldown = 30 * time.Second

// tryRecordPendingAudit emits a best-effort auth.second_factor_pending management audit event
// when a login presents a correct password for a TOTP-enrolled account but supplies no code.
//
// Rate limit: at most one attempt per pendingAuditCooldown per AuthService instance. The slot
// is reserved under the mutex BEFORE the store call so the mutex is never held during I/O,
// and a failed write still consumes the slot so a misbehaving store cannot amplify log output.
// A backward clock is safe: if s.now() < nextPendingAuditAt the slot is not granted.
//
// Actor and target are always empty — the caller has not authenticated, so any attribution
// would let an attacker write another user's audit trail. The attempted email and source IP
// travel in metadata only, exactly as auth.login_failed.
func (s *AuthService) tryRecordPendingAudit(r *http.Request, tenantID, email string) {
	if s.MgmtAudit == nil {
		return
	}
	now := s.now()
	s.pendingMu.Lock()
	if now.Before(s.nextPendingAuditAt) {
		s.pendingMu.Unlock()
		return
	}
	// Reserve the slot before releasing; I/O happens after the unlock.
	s.nextPendingAuditAt = now.Add(pendingAuditCooldown)
	s.pendingMu.Unlock()

	err := s.recordAuthEvent(r.Context(), tenantID, "", "auth.second_factor_pending", map[string]any{
		"email":   email,
		"ip":      clientIP(r),
		"sampled": true,
	})
	if err != nil {
		log.Printf("could not record auth.second_factor_pending for tenant %q: %q", tenantID, err)
	}
}

package controlplane

// POST /audit/ingest must bind the batch's `technician_id` to the AUTHENTICATED caller.
//
// PREMISE, declared locally so this cannot drift: the forwarded backstage trail is the record of who
// did what on someone's machine, and the whole point of the hash chain is that the record is
// tamper-EVIDENT. That guarantee is about the bytes, not about the identity in them: the chain
// proves nobody edited the batch after the fact, and says nothing about whether the person named in
// it is the person the server authenticated. `technician_id` arrives in the request BODY, and the
// only gate on this route was `Require(CapBackstageShell)` — the tenant-wide form (`Grant.Require`
// "reports whether ANY membership grants the capability, ignoring group scope").
//
// So a technician could forge a correctly-chained batch attributing a SYSTEM shell to a colleague:
// `audit_canonical.go` is a byte-for-byte port of the agent's encoder, so anyone can compute a valid
// `hash`, and the export would then re-emit the forgery as an authentic record.
//
// How this was measured before the fix: `TestIngestValidBatchStored` PASSED while
// `technicianPrincipal()` was "u1" and `mkAuditEvent` stamped every event for
// "11111111-…". A green run of a test whose caller and subject disagree IS the proof that nothing
// compared them.
//
// NOT tested here, deliberately: authorizing `machine_id` by resolving the session's group. The
// ingest `session_id` is a browser-minted uuid that is never written to `session_record`
// (migrations/0004_audit.sql), so there is no row to resolve and such a check would reject every
// legitimate ingest. Recorded so a later hunt does not re-derive it as a missing defence.

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestIngestRejectsABatchAttributedToAnotherTechnician(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())

	// Negative control FIRST: the caller's OWN batch is accepted. Without this leg a handler that
	// rejected every ingest would satisfy the assertion below.
	own := chainRange(testSession, 0, 2)
	if rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: own}); rec.Code != http.StatusOK {
		t.Fatalf("premise not met: the caller's own batch = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	// The measurement: same well-formed, correctly-hash-chained batch, but attributed to somebody
	// else. Re-hashed after the swap so the CHAIN is valid — this must be refused on identity
	// grounds, not because the hash stopped matching. (If it were rejected as a bad hash the error
	// would mention linkage/tamper, which the assertion below rules out.)
	const colleague = "99999999-9999-4999-8999-999999999999"
	const otherSession = "33333333-3333-4333-8333-333333333333"
	forged := chainRange(otherSession, 0, 2)
	prev := ""
	for i := range forged {
		forged[i].TechnicianID = colleague
		forged[i].PrevHash = prev
		h, err := recomputeHash(forged[i])
		if err != nil {
			t.Fatalf("recompute forged hash: %v", err)
		}
		forged[i].Hash = h
		prev = h
	}

	rec := postIngest(t, srv, auditIngestRequest{SessionID: otherSession, Events: forged})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("SECURITY: batch attributed to %s accepted with status %d, want 403 (body %s)",
			colleague, rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "technician_id") {
		t.Fatalf("denial should name technician_id as the reason, got %s", body)
	}

	// And nothing may have been written. A 403 that still appended would be the worse bug.
	if tail, err := store.AuditTail(context.Background(), "tenant-123", otherSession); err == nil && tail.Seq > 0 {
		t.Fatalf("SECURITY: refused batch still extended the chain to seq %d", tail.Seq)
	}
}

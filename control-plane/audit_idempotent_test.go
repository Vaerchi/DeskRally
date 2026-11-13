package controlplane

// Idempotent re-send (resolveOverlap). A forwarder that lost the 2xx for a committed batch re-sends
// it; that must succeed without storing anything twice, while every way of overlapping the stored
// range that CANNOT be proven identical to it is still refused. Each test runs against the
// in-memory store here and, for the cases that matter, against Postgres in
// audit_idempotent_pgstore_test.go (fake and pg must agree).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// forkFrom returns events [from, to] of a chain that agrees with chainRange up to seq forkAt-1 and
// then diverges: from forkAt on, the action differs, so every hash from forkAt differs too. The
// result is internally consistent (correct content hashes and prev_hash links), which is what makes
// it a real fork rather than a tampered batch.
func forkFrom(sessionID string, forkAt, from, to uint64) []AuditEvent {
	other := json.RawMessage(`{"kind":"service_control","service":"spooler","verb":"start"}`)
	all := make([]AuditEvent, 0, to+1)
	prev := GenesisPrevHash
	for s := uint64(0); s <= to; s++ {
		action := defaultAuditAction
		if s >= forkAt {
			action = other
		}
		e := mkAuditEvent(sessionID, s, prev, action, defaultAuditOutcome)
		all = append(all, e)
		prev = e.Hash
	}
	return all[from : to+1]
}

func storedCount(s *InMemoryAuditStore, tenant, session string) (chain, ingest int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.chains[auditKey(tenant, session)]), len(s.ingest[tenant])
}

func TestAuditResendOfAStoredBatchIsANoOp(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	batch := chainRange(testSession, 0, 3)
	if _, err := s.AppendAudit(ctx, "t1", testSession, batch); err != nil {
		t.Fatalf("initial: %v", err)
	}
	tail, err := s.AppendAudit(ctx, "t1", testSession, batch) // the lost-2xx re-send
	if err != nil {
		t.Fatalf("re-send of a stored batch must succeed, got %v", err)
	}
	if tail.Seq != 2 || tail.Hash != batch[2].Hash {
		t.Fatalf("tail = %+v, want the stored tail (seq 2)", tail)
	}
	if c, i := storedCount(s, "t1", testSession); c != 3 || i != 3 {
		t.Fatalf("stored chain=%d ingest=%d, want 3/3 (nothing stored twice)", c, i)
	}
}

func TestAuditOverlappingBatchAppendsOnlyTheNewSuffix(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 3)); err != nil {
		t.Fatalf("initial: %v", err)
	}
	over := chainRange(testSession, 1, 4) // seq 1..4; 1 and 2 are stored, 3 and 4 are new
	tail, err := s.AppendAudit(ctx, "t1", testSession, over)
	if err != nil {
		t.Fatalf("overlapping batch: %v", err)
	}
	if tail.Seq != 4 || tail.Hash != over[3].Hash {
		t.Fatalf("tail = %+v, want seq 4", tail)
	}
	if c, i := storedCount(s, "t1", testSession); c != 5 || i != 5 {
		t.Fatalf("stored chain=%d ingest=%d, want 5/5", c, i)
	}
	// The next ordinary continuation still links.
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 5, 1)); err != nil {
		t.Fatalf("continuation after an overlap: %v", err)
	}
}

func TestAuditOverlapThatEndsBeforeTheTailIsStillRefused(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 3)); err != nil {
		t.Fatalf("initial: %v", err)
	}
	_, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 2)) // seq 0..1, tail is 2
	var le *LinkageError
	if !errors.As(err, &le) {
		t.Fatalf("err = %v, want *LinkageError (nothing in the batch reaches the tail)", err)
	}
}

func TestAuditForkAtTheTailIsRefusedAndStoresNothing(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 3)); err != nil {
		t.Fatalf("initial: %v", err)
	}
	// Agrees on seq 0..1, diverges from seq 2 (the stored tail) and continues to seq 3.
	fork := forkFrom(testSession, 2, 1, 3)
	_, err := s.AppendAudit(ctx, "t1", testSession, fork)
	var le *LinkageError
	if !errors.As(err, &le) {
		t.Fatalf("err = %v, want *LinkageError for a fork at the tail", err)
	}
	if tail, _ := s.AuditTail(ctx, "t1", testSession); tail.Seq != 2 {
		t.Fatalf("tail = %+v, want unchanged seq 2", tail)
	}
	if c, _ := storedCount(s, "t1", testSession); c != 3 {
		t.Fatalf("stored %d events, want 3", c)
	}
}

// A fork that ENDS at the tail has no suffix whose prev_hash could expose it, so only the tail-hash
// comparison stops it being "accepted" as an already-stored re-send.
func TestAuditForkEndingExactlyAtTheTailIsRefused(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 3)); err != nil {
		t.Fatalf("initial: %v", err)
	}
	_, err := s.AppendAudit(ctx, "t1", testSession, forkFrom(testSession, 2, 1, 2)) // seq 1, then a different seq 2
	var le *LinkageError
	if !errors.As(err, &le) {
		t.Fatalf("err = %v, want *LinkageError: a different event at the tail's seq is a fork, not a re-send", err)
	}
}

func TestAuditOverlapWithATamperedPrefixIsRefused(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 3)); err != nil {
		t.Fatalf("initial: %v", err)
	}
	over := chainRange(testSession, 1, 4)
	over[0].Outcome = json.RawMessage(`{"result":"failed","error":"edited"}`) // hash kept, content changed
	_, err := s.AppendAudit(ctx, "t1", testSession, over)
	var ce *ContentTamperError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *ContentTamperError: an overlapping prefix is verified, not trusted", err)
	}
	if tail, _ := s.AuditTail(ctx, "t1", testSession); tail.Seq != 2 {
		t.Fatalf("tail = %+v, want unchanged seq 2", tail)
	}
}

// The forwarder drops a batch only on 2xx with accepted == len(batch). A re-sent batch must
// therefore get exactly that, or the forwarder retries forever.
func TestIngestResendAfterALostResponseIsAcceptedInFull(t *testing.T) {
	srv, store := auditServer(technicianPrincipal())
	batch := auditIngestRequest{SessionID: testSession, Events: chainRange(testSession, 0, 3)}
	for i := 0; i < 2; i++ {
		rec := postIngest(t, srv, batch)
		if rec.Code != http.StatusOK {
			t.Fatalf("send %d: status %d body %s", i, rec.Code, rec.Body.String())
		}
		var resp auditIngestResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("send %d: decode: %v", i, err)
		}
		if resp.Accepted != 3 || resp.TailSeq != 2 {
			t.Fatalf("send %d: %+v, want accepted 3 tail 2", i, resp)
		}
	}
	if c, _ := storedCount(store, technicianPrincipal().TenantID, testSession); c != 3 {
		t.Fatalf("stored %d, want 3", c)
	}
}

// An empty batch is refused by the store, as before the overlap handling (whose "everything already
// stored" no-op must not swallow it).
func TestAuditEmptyBatchIsStillRefusedByTheStore(t *testing.T) {
	s := NewInMemoryAuditStore()
	ctx := context.Background()
	if _, err := s.AppendAudit(ctx, "t1", testSession, chainRange(testSession, 0, 1)); err != nil {
		t.Fatalf("initial: %v", err)
	}
	var le *LinkageError
	if _, err := s.AppendAudit(ctx, "t1", testSession, nil); !errors.As(err, &le) {
		t.Fatalf("err = %v, want *LinkageError for an empty batch", err)
	}
}

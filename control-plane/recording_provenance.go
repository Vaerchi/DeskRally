package controlplane

// Provenance of an uploaded recording (docs/63 §2a C4).
//
// There are exactly TWO labels, and neither says "verified":
//
//	"Agent-signed; matches session audit"      ProvMatchesAudit   a SIGNED recording_stopped event on the
//	      accepted audit chain of the same tenant and session, for the same machine, signed by the SAME
//	      enrollment key that signed the upload, carries the same ordered digest list AND the same
//	      truncation, dropped-frame and segment-count metadata;
//	"Agent-signed; no matching stop event"     ProvNoStopEvent    nothing on the chain claims this
//	      recording (an abnormal end seals no stop event, or the chain is not stored).
//
// A recording_stopped event that CLAIMS the same recording but disagrees (it shares a digest with the
// upload, or the metadata differs) is a CONFLICT: the upload is refused, never relabelled. Both labels
// mean only that the endpoint's agent key said so — whoever controls that key can fabricate either, and
// neither is independent capture verification. Docs and UI must say that plainly.
//
// What counts as "a signed event on the accepted chain": it is stored (the audit store verified its
// linkage at ingest); its content re-hashes to its stored hash (the signature signs that hash, so this is
// what ties the signature to the fields we read); its agent signature verifies under the machine's
// CURRENT pinned key; that key's fingerprint equals the one the upload was created under; and its
// session and machine are the recording's. Events failing any of those are ignored — they can neither
// match nor conflict.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// recProvenanceMaxPages bounds the audit traversal: pages of maxAuditExportLimit events (10k), so the walk
// reads at most 2M events of ONE session before giving up. A variable only so a test can lower it.
var recProvenanceMaxPages = 200

// errProvenanceTooLong is returned when the session's audit chain exceeds the traversal bound.
var errProvenanceTooLong = errors.New("the session audit chain is longer than the provenance scan allows")

// errProvenanceConflict marks a signed stop event that claims this recording but disagrees with it.
var errProvenanceConflict = errors.New("a signed recording_stopped event on the session chain disagrees with the uploaded recording")

// recFinishMeta is the agent-attested metadata of a finish call.
type recFinishMeta struct {
	Digests       []string
	Truncated     *string
	DroppedFrames uint64
	Frames        *uint64
	PayloadBytes  *uint64
}

type stoppedAction struct {
	Kind          string    `json:"kind"`
	Frames        uint64    `json:"frames"`
	PayloadBytes  uint64    `json:"payload_bytes"`
	Truncated     *string   `json:"truncated"`
	DroppedFrames uint64    `json:"dropped_frames"`
	SegmentSha256 *[]string `json:"segment_sha256"`
}

func strPtrEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func digestListsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func digestListsOverlap(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, d := range a {
		set[d] = struct{}{}
	}
	for _, d := range b {
		if _, ok := set[d]; ok {
			return true
		}
	}
	return false
}

// matchStoppedEvent classifies one decoded stop event against a finish: (matches, conflicts).
func matchStoppedEvent(a stoppedAction, fin recFinishMeta, segmentCount int) (bool, bool) {
	if a.SegmentSha256 == nil {
		return false, false
	}
	theirs := *a.SegmentSha256
	if !digestListsOverlap(theirs, fin.Digests) && !digestListsEqual(theirs, fin.Digests) {
		return false, false // a different recording's stop event
	}
	same := digestListsEqual(theirs, fin.Digests) && len(theirs) == segmentCount &&
		strPtrEq(a.Truncated, fin.Truncated) && a.DroppedFrames == fin.DroppedFrames
	if same && fin.Frames != nil && *fin.Frames != a.Frames {
		same = false
	}
	if same && fin.PayloadBytes != nil && *fin.PayloadBytes != a.PayloadBytes {
		same = false
	}
	if same {
		return true, false
	}
	return false, true
}

// recordingProvenance walks the session's stored chain. It returns the label, the matched event's seq
// (nil unless matched) or errProvenanceConflict. A chain that cannot be read is an ERROR (the caller
// answers 503 and the agent retries) — it must never silently degrade to the weaker label.
func (s *Server) recordingProvenance(ctx context.Context, tenantID string, row *RecordingRow, machine *Machine, fin recFinishMeta) (string, *int64, error) {
	if s.Audit == nil {
		return ProvNoStopEvent, nil, nil
	}
	pub, err := hex.DecodeString(machine.Pubkey)
	if err != nil || len(pub) != 32 {
		return ProvNoStopEvent, nil, nil
	}
	if fp := sha256.Sum256(pub); fp != row.EnrollmentFP {
		return "", nil, errors.New("machine key changed since the upload was created")
	}
	var matched *int64
	cursor := auditExportStart
	for page := 0; ; page++ {
		// The walk is bounded in pages and in time: a session with an enormous (or hostile) chain must not
		// pin the finish. Exceeding either is an ERROR (503, the agent retries), never a weaker label.
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		if page >= recProvenanceMaxPages {
			return "", nil, errProvenanceTooLong
		}
		events, next, err := s.Audit.ListAuditEventsAsc(ctx, tenantID, AuditExportQuery{
			SessionID: row.SessionID, AfterIngestSeq: cursor, Limit: maxAuditExportLimit})
		if err != nil {
			return "", nil, err
		}
		for _, e := range events {
			if err := ctx.Err(); err != nil { // up to 10k events (each a signature check) per page
				return "", nil, err
			}
			if e.SessionID != row.SessionID || (e.MachineID != machine.ID && e.MachineID != machine.DeviceID) {
				continue
			}
			var probe struct {
				Kind string `json:"kind"`
			}
			if json.Unmarshal(e.Action, &probe) != nil || probe.Kind != "recording_stopped" {
				continue
			}
			if !validAgentAuditSignature(e, machine.Pubkey) {
				continue // unsigned, or signed by another key: not evidence of anything
			}
			if h, herr := recomputeHash(e); herr != nil || h != e.Hash {
				continue // fields no longer match what was signed
			}
			var a stoppedAction
			if json.Unmarshal(e.Action, &a) != nil {
				continue
			}
			ok, conflict := matchStoppedEvent(a, fin, len(row.Segments))
			if conflict {
				return "", nil, errProvenanceConflict
			}
			if ok && matched == nil {
				seq := int64(e.Seq)
				matched = &seq
			}
		}
		if len(events) == 0 || next <= cursor {
			break
		}
		cursor = next
	}
	if matched != nil {
		return ProvMatchesAudit, matched, nil
	}
	return ProvNoStopEvent, nil, nil
}

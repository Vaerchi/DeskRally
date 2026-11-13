package controlplane

// Canonical audit v1 (Milestone H2b) — a byte-for-byte Go port of the Rust
// agent/src/backstage/canonical.rs `audit_preimage`. H2 stored each event's `hash` as an opaque
// chain pointer (linkage only). H2b lets the control-plane RECOMPUTE each event's SHA-256 content
// hash from its fields and reject any event whose fields were altered — full content
// tamper-evidence, not just self-consistent pointers.
//
// The action/outcome are carried as opaque json.RawMessage on AuditEvent (they are internally
// tagged Rust enums). To rebuild the canonical preimage this file decodes each into its typed
// variant and re-encodes it in declaration order with the matching primitive, exactly as Rust's
// `encode_action`/`encode_outcome` do. Every variant is enumerated explicitly (no catch-all): an
// unknown tag is a hard error (deny-by-default), and TestAuditGoldenVectorV1 proves the bytes match
// Rust.
//
// Layout (canonical audit v1 — big-endian; str = u32be(len)||utf8; uuid = 16 raw bytes):
//
//	auditDomainTag                            // 12 bytes: "RMTAUDITv1\x00\x00"
//	|| uuid(id) || u64be(seq)
//	|| uuid(session_id) || uuid(technician_id) || uuid(machine_id)
//	|| i64be(occurred_at_unix_ms)
//	|| canonical(action) || canonical(outcome)
//	|| str(prev_hash)

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// auditDomainTag is the 12-byte canonical-audit-v1 domain-separation tag: ASCII "RMTAUDITv1"
// followed by two 0x00 bytes. Hex: 52 4d 54 41 55 44 49 54 76 31 00 00. Must equal Rust's
// AUDIT_DOMAIN_TAG and MUST differ from grantDomainTag (domain separation).
var auditDomainTag = []byte("RMTAUDITv1\x00\x00")

// auditPreimage builds the canonical audit v1 preimage for one event's content fields (everything
// except its own `hash`). Returns an error if a UUID string or the action/outcome JSON is malformed.
func auditPreimage(e AuditEvent) ([]byte, error) {
	id, err := uuidBytes(e.ID)
	if err != nil {
		return nil, fmt.Errorf("id: %w", err)
	}
	sess, err := uuidBytes(e.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session_id: %w", err)
	}
	tech, err := uuidBytes(e.TechnicianID)
	if err != nil {
		return nil, fmt.Errorf("technician_id: %w", err)
	}
	mach, err := uuidBytes(e.MachineID)
	if err != nil {
		return nil, fmt.Errorf("machine_id: %w", err)
	}
	var w canonicalWriter
	w.auditTag()
	w.raw16(id)
	w.u64(e.Seq)
	w.raw16(sess)
	w.raw16(tech)
	w.raw16(mach)
	w.i64(e.OccurredAtUnixMs)
	if err := encodeAuditAction(&w, e.Action); err != nil {
		return nil, fmt.Errorf("action: %w", err)
	}
	if err := encodeAuditOutcome(&w, e.Outcome); err != nil {
		return nil, fmt.Errorf("outcome: %w", err)
	}
	w.lpStr(e.PrevHash)
	return w.buf, nil
}

// recomputeHash returns the lower-hex SHA-256 of the canonical audit v1 preimage — the value the
// event's `hash` field must equal if no content field was altered.
func recomputeHash(e AuditEvent) (string, error) {
	pre, err := auditPreimage(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pre)
	return hex.EncodeToString(sum[:]), nil
}

// encodeUUIDField parses a hyphenated UUID string into 16 raw bytes and appends them (used for
// nested ids inside actions, e.g. shell_id).
func encodeUUIDField(w *canonicalWriter, s string) error {
	b, err := uuidBytes(s)
	if err != nil {
		return err
	}
	w.raw16(b)
	return nil
}

// encodeDirection appends str("input")/str("output"). The raw JSON is exactly that snake_case
// string (Rust Direction's serde rename_all), so we validate and re-emit it.
func encodeDirection(w *canonicalWriter, raw json.RawMessage) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("direction: %w", err)
	}
	if s != "input" && s != "output" {
		return fmt.Errorf("unknown direction %q", s)
	}
	w.lpStr(s)
	return nil
}

// encodeRunAs mirrors Rust encode_run_as: str(variant) then fields. Serde tag is "as".
func encodeRunAs(w *canonicalWriter, raw json.RawMessage) error {
	var probe struct {
		As string `json:"as"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("run_as: %w", err)
	}
	w.lpStr(probe.As)
	switch probe.As {
	case "system":
		// no fields
	case "logged_in_user":
		var r struct {
			Username string `json:"username"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		w.lpStr(r.Username)
	case "credential":
		var r struct {
			Username string `json:"username"`
			Domain   string `json:"domain"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		w.lpStr(r.Username)
		w.lpStr(r.Domain)
	default:
		return fmt.Errorf("unknown run_as variant %q", probe.As)
	}
	return nil
}

// encodeAuditAction mirrors Rust encode_action: str(variant "kind") then fields in declaration
// order. Every AuditAction variant is enumerated; an unknown kind is rejected.
func encodeAuditAction(w *canonicalWriter, raw json.RawMessage) error {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("kind: %w", err)
	}
	w.lpStr(probe.Kind)
	switch probe.Kind {
	case "shell_open":
		var a struct {
			ShellID  string          `json:"shell_id"`
			Program  string          `json:"program"`
			Identity json.RawMessage `json:"identity"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if err := encodeUUIDField(w, a.ShellID); err != nil {
			return err
		}
		w.lpStr(a.Program)
		return encodeRunAs(w, a.Identity)
	case "shell_close":
		var a struct {
			ShellID  string `json:"shell_id"`
			ExitCode *int32 `json:"exit_code"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if err := encodeUUIDField(w, a.ShellID); err != nil {
			return err
		}
		if a.ExitCode == nil {
			w.u8(0)
		} else {
			w.u8(1)
			w.i32(*a.ExitCode)
		}
	case "shell_data":
		var a struct {
			ShellID      string          `json:"shell_id"`
			Direction    json.RawMessage `json:"direction"`
			BytesLen     uint32          `json:"bytes_len"`
			RedactedText string          `json:"redacted_text"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if err := encodeUUIDField(w, a.ShellID); err != nil {
			return err
		}
		if err := encodeDirection(w, a.Direction); err != nil {
			return err
		}
		w.u32(a.BytesLen)
		w.lpStr(a.RedactedText)
	case "file_browse":
		var a struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.lpStr(a.Path)
	case "service_control":
		var a struct {
			Service string `json:"service"`
			Verb    string `json:"verb"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.lpStr(a.Service)
		w.lpStr(a.Verb)
	case "service_config_change":
		var a struct {
			Service string `json:"service"`
			Before  string `json:"before"`
			After   string `json:"after"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.lpStr(a.Service)
		w.lpStr(a.Before)
		w.lpStr(a.After)
	case "process_kill":
		var a struct {
			Pid   uint32 `json:"pid"`
			Image string `json:"image"`
			Owner string `json:"owner"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.u32(a.Pid)
		w.lpStr(a.Image)
		w.lpStr(a.Owner)
	case "registry_write":
		var a struct {
			Path   string  `json:"path"`
			Value  string  `json:"value"`
			Before *string `json:"before"`
			After  string  `json:"after"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.lpStr(a.Path)
		w.lpStr(a.Value)
		if a.Before == nil {
			w.u8(0)
		} else {
			w.u8(1)
			w.lpStr(*a.Before)
		}
		w.lpStr(a.After)
	case "file_transfer":
		var a struct {
			Direction json.RawMessage `json:"direction"`
			Path      string          `json:"path"`
			Sha256    string          `json:"sha256"`
			Bytes     uint64          `json:"bytes"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if err := encodeDirection(w, a.Direction); err != nil {
			return err
		}
		w.lpStr(a.Path)
		w.lpStr(a.Sha256)
		w.u64(a.Bytes)
	case "file_delete":
		var a struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.lpStr(a.Path)
	// docs/58 file management. Pinned against Rust by TestAuditGoldenFileManageV1.
	case "file_create_dir":
		var a struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.lpStr(a.Path)
	case "file_rename":
		var a struct {
			From string `json:"from"`
			To   string `json:"to"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.lpStr(a.From)
		w.lpStr(a.To)
	case "file_place":
		var a struct {
			TransferID string `json:"transfer_id"`
			Sha256     string `json:"sha256"`
			To         string `json:"to"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if err := encodeUUIDField(w, a.TransferID); err != nil {
			return err
		}
		w.lpStr(a.Sha256)
		w.lpStr(a.To)
	case "credential_use":
		var a struct {
			Username string `json:"username"`
			Domain   string `json:"domain"`
			Purpose  string `json:"purpose"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.lpStr(a.Username)
		w.lpStr(a.Domain)
		w.lpStr(a.Purpose)
	case "consent_signal":
		var a struct {
			UserNotified bool   `json:"user_notified"`
			Policy       string `json:"policy"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if a.UserNotified {
			w.u8(1)
		} else {
			w.u8(0)
		}
		w.lpStr(a.Policy)
	// Session recording (loop 91). These arms are NOT optional bookkeeping: `encodeAuditAction`
	// ends in a hard `default` below, and `verifyLinkage` calls `recomputeHash` on every ingested
	// event — so a Rust variant with no Go arm makes the batch a ContentTamperError (400), and
	// because the chain is strictly sequential the agent can never move past it and the WHOLE
	// session's trail wedges forever. Exactly the failure mode the NUL bug had. The loop-90 design
	// note said "adding a variant is the whole wire change — no new preimage"; that was measured
	// FALSE here before anything shipped.
	case "recording_started":
		var a struct {
			StartedAtUnixMs int64  `json:"started_at_unix_ms"`
			Directory       string `json:"directory"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		w.i64(a.StartedAtUnixMs)
		w.lpStr(a.Directory)
	case "recording_stopped":
		// `SegmentSha256` is a *[]string, not a []string: Rust encodes the count with u32be, so a
		// MISSING key and an empty list are different preimages and must stay distinguishable. A
		// plain []string decodes both as nil and would hash a truncated event as a valid empty one.
		var a struct {
			Frames        uint64    `json:"frames"`
			PayloadBytes  uint64    `json:"payload_bytes"`
			Truncated     *string   `json:"truncated"`
			DroppedFrames uint64    `json:"dropped_frames"`
			SegmentSha256 *[]string `json:"segment_sha256"`
			Directory     string    `json:"directory"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if a.SegmentSha256 == nil {
			return fmt.Errorf("recording_stopped: segment_sha256 is required")
		}
		w.u64(a.Frames)
		w.u64(a.PayloadBytes)
		if a.Truncated == nil {
			w.u8(0)
		} else {
			w.u8(1)
			w.lpStr(*a.Truncated)
		}
		w.u64(a.DroppedFrames)
		w.u32(uint32(len(*a.SegmentSha256)))
		for _, d := range *a.SegmentSha256 {
			w.lpStr(d)
		}
		w.lpStr(a.Directory)
	case "input_control_handed":
		// docs/61: four uuids then the arbitration epoch, mirroring Rust encode_action. The epoch is a
		// pointer so a MISSING key is refused rather than hashed as zero (the recording_stopped rule).
		var a struct {
			FromSession    string  `json:"from_session"`
			FromTechnician string  `json:"from_technician"`
			ToSession      string  `json:"to_session"`
			ToTechnician   string  `json:"to_technician"`
			Epoch          *uint64 `json:"epoch"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			return err
		}
		if a.Epoch == nil {
			return fmt.Errorf("input_control_handed: epoch is required")
		}
		for _, id := range []string{a.FromSession, a.FromTechnician, a.ToSession, a.ToTechnician} {
			if err := encodeUUIDField(w, id); err != nil {
				return err
			}
		}
		w.u64(*a.Epoch)
	default:
		return fmt.Errorf("unknown audit action kind %q", probe.Kind)
	}
	return nil
}

// encodeAuditOutcome mirrors Rust encode_outcome: str(variant "result") then fields.
func encodeAuditOutcome(w *canonicalWriter, raw json.RawMessage) error {
	var probe struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("result: %w", err)
	}
	w.lpStr(probe.Result)
	switch probe.Result {
	case "ok":
		// no fields
	case "denied":
		var o struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return err
		}
		w.lpStr(o.Reason)
	case "failed":
		var o struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return err
		}
		w.lpStr(o.Error)
	default:
		return fmt.Errorf("unknown outcome result %q", probe.Result)
	}
	return nil
}

// ContentTamperError is returned when an event's recomputed content hash does not match its `hash`
// field (or the fields cannot be canonicalized) — a field-level tamper the linkage checks alone
// would miss. Distinct from *LinkageError so the cause is unambiguous; both map to 400 and store
// nothing. At is the batch index of the offending event.
type ContentTamperError struct {
	At     int
	Reason string
}

func (e *ContentTamperError) Error() string {
	return fmt.Sprintf("audit content-hash mismatch at index %d: %s", e.At, e.Reason)
}

package controlplane

// Canonical mgmt-audit v1 — the preimage + content hash for the hash-chained MANAGEMENT audit
// trail (audit_event), mirroring the backstage chain's canonical encoding (audit_canonical.go)
// but adapted to management events:
//
//   - IDs are length-prefixed STRINGS, not raw UUID bytes. Management events are written by Go
//     handlers whose principals are not guaranteed to carry RFC-4122 ids (DEV mode and the HTTP
//     tests use ids like "tenant-123"), and unlike the backstage chain there is no Rust twin
//     that needs a byte-identical uuid encoding. UUID-ish fields are put through
//     canonicalUUIDish, which renders every spelling the `uuid` COLUMN accepts the way that
//     column reads it back; anything that is not a uuid is merely lowercased.
//   - Metadata (jsonb) is hashed over a CANONICAL re-encoding, not its raw bytes: jsonb does not
//     preserve key order, whitespace, or number spelling, so hashing what the caller sent would
//     make read-back verification report false tampers. canonicalMetadata is a pure function of
//     the JSON value (Go re-marshal sorts object keys), so write-time and read-back hashing
//     agree. Numbers pass through float64 on BOTH paths, which unifies spellings ("1e3" vs
//     "1000") the same way in each direction.
//
// THE CONTRACT BOTH OF THOSE SERVE: this preimage must be a function of the value as PostgreSQL
// STORES it, never of the spelling the caller happened to use. Postgres normalizes on the way in
// — jsonb numbers are `numeric` (no signed zero), the `uuid` type re-renders braced/dashless/
// mixed-case spellings — so any field hashed in the caller's spelling is hashed as one thing and
// read back as another, and GET /audit/verify then reports tampering forever on a trail nobody
// touched. Migration 0006 revokes UPDATE/DELETE from the app role, so such a row can never be
// repaired: getting this wrong is permanent corruption, not a transient bug.
// TestPgMgmtAuditChainSurvivesPgNormalization pins the whole class against a live server, and
// PgMgmtAuditStore.RecordEvent re-hashes what the INSERT actually stored as a backstop for the
// normalizations nobody thought of.
//
// This chain is Go-only (writer and verifier are both this package): no cross-language golden
// vector is required, but TestMgmtAuditVectorV1 pins the exact preimage bytes + hash so an
// accidental encoding change breaks loudly instead of silently re-namespacing every hash.
//
// Layout (canonical mgmt-audit v1 — big-endian; str = u32be(len)||utf8):
//
//	mgmtAuditDomainTag                          // 12 bytes: "RMTMAUDITv1\x00"
//	|| str(uuidish(id)) || u64be(seq)
//	|| str(uuidish(tenant_id))
//	|| str(uuidish(actor_user_id))              // "" when the event has no actor
//	|| str(action)
//	|| str(target_kind)                         // "" when absent
//	|| str(uuidish(target_id))                  // "" when absent
//	|| i64be(occurred_at unix ms)
//	|| str(canonicalMetadata(metadata))
//	|| str(prev_hash)

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// mgmtAuditDomainTag is the 12-byte canonical mgmt-audit v1 domain-separation tag: ASCII
// "RMTMAUDITv1" followed by one 0x00 byte. MUST differ from grantDomainTag ("RMTGRANTv1\x00\x00"),
// auditDomainTag ("RMTAUDITv1\x00\x00") and ticketDomainTag ("RMTTICKETv1\x00").
var mgmtAuditDomainTag = []byte("RMTMAUDITv1\x00")

// MgmtGenesisPrevHash is the prev_hash of a tenant's first chained event (seq 0) — the empty
// string, matching the backstage chain's GenesisPrevHash convention.
const MgmtGenesisPrevHash = ""

// canonicalMetadata reduces a metadata JSON document to its canonical encoding: parse to a Go
// value (float64 numbers, last duplicate key wins — the same resolutions jsonb applies),
// normalize the numbers to the spellings that survive the jsonb round-trip, and re-marshal
// (encoding/json sorts map keys, emits no insignificant whitespace). Empty input canonicalizes
// to "{}", matching the store-side normalization (audit_event.metadata is NOT NULL DEFAULT
// '{}'). Malformed JSON is an error: the value would not survive the jsonb round-trip.
func canonicalMetadata(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "{}", nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("metadata is not valid JSON: %w", err)
	}
	b, err := json.Marshal(normalizeJSONNumbers(v))
	if err != nil {
		return "", fmt.Errorf("metadata cannot be canonicalized: %w", err)
	}
	return string(b), nil
}

// normalizeJSONNumbers rewrites every number in a decoded JSON document into the form that
// survives a jsonb round-trip, recursing through objects and arrays.
//
// Today it does exactly one thing: collapse NEGATIVE ZERO onto positive zero. Go's
// encoding/json marshals a negative-zero float64 as "-0", but jsonb numbers are stored as
// `numeric`, which has no signed zero and normalizes the value to 0 — so hashing the caller's
// "-0" guarantees the read-back hashes "0" and the chain reports a permanent false tamper.
// The `== 0` test catches every spelling at once (-0, -0.0, -0e0 all decode to negative zero,
// and -0.0 == 0.0 is true in Go). Exponent and trailing-zero spellings need no handling: both
// directions decode through float64, so "1e3" and "1000" already converge.
func normalizeJSONNumbers(v any) any {
	switch t := v.(type) {
	case float64:
		if t == 0 {
			return float64(0) // re-materialize without the sign bit
		}
		return t
	case map[string]any:
		for k, x := range t {
			t[k] = normalizeJSONNumbers(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = normalizeJSONNumbers(x)
		}
		return t
	}
	return v // strings, bools, null — jsonb preserves these as decoded
}

// canonicalUUIDish renders an id field the way its `uuid` column will read it back. Values that
// are not uuids — DEV and test principals like "tenant-123" flow through this same preimage —
// are only lowercased, preserving the previous behaviour for them.
func canonicalUUIDish(s string) string {
	if u, ok := parsePgUUID(s); ok {
		return u
	}
	return strings.ToLower(s)
}

// parsePgUUID accepts exactly the spellings PostgreSQL's uuid_in accepts — 32 hex digits,
// optionally wrapped in a matched pair of braces, with at most one OPTIONAL hyphen at each of
// the four group boundaries — and returns the canonical lowercase 8-4-4-4-12 rendering, which is
// what the column reads back as.
//
// The two error directions are NOT symmetric, which is why this matches uuid_in rather than
// being loosely permissive. Accepting something Postgres REJECTS is harmless: the INSERT fails
// and the whole append rolls back. Rejecting something Postgres ACCEPTS is the bug this exists
// to prevent — the value gets hashed in the caller's spelling and read back in Postgres's, an
// unrepairable false tamper. The live server was checked against this parser: leading/trailing
// whitespace, doubled hyphens, hyphens off a group boundary, spaces inside braces and an
// unmatched brace are rejected by both.
func parsePgUUID(s string) (string, bool) {
	if len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}' {
		s = s[1 : len(s)-1]
	}
	const hexDigits = "0123456789abcdef"
	var out [32]byte
	n := 0
	prevHyphen := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			if prevHyphen || (n != 8 && n != 12 && n != 16 && n != 20) {
				return "", false
			}
			prevHyphen = true
			continue
		}
		prevHyphen = false
		if n == 32 {
			return "", false
		}
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return "", false
		}
		out[n] = hexDigits[d]
		n++
	}
	if n != 32 {
		return "", false
	}
	var b strings.Builder
	b.Grow(36)
	for i, c := range out {
		if i == 8 || i == 12 || i == 16 || i == 20 {
			b.WriteByte('-')
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// mgmtAuditPreimage builds the canonical mgmt-audit v1 preimage for one event's content fields
// (everything except its own `hash`). The event's Seq must be set (chained events only).
func mgmtAuditPreimage(e MgmtAuditEvent) ([]byte, error) {
	if e.Seq == nil {
		return nil, fmt.Errorf("event %s has no seq (legacy/unchained rows cannot be hashed)", e.ID)
	}
	meta, err := canonicalMetadata(e.Metadata)
	if err != nil {
		return nil, err
	}
	var w canonicalWriter
	w.buf = append(w.buf, mgmtAuditDomainTag...)
	w.lpStr(canonicalUUIDish(e.ID))
	w.u64(uint64(*e.Seq))
	w.lpStr(canonicalUUIDish(e.TenantID))
	w.lpStr(canonicalUUIDish(e.ActorUserID))
	w.lpStr(e.Action)
	w.lpStr(e.TargetKind)
	w.lpStr(canonicalUUIDish(e.TargetID))
	w.i64(e.OccurredAt.UnixMilli())
	w.lpStr(meta)
	w.lpStr(e.PrevHash)
	return w.buf, nil
}

// recomputeMgmtAuditHash returns the lower-hex SHA-256 of the canonical mgmt-audit v1 preimage —
// the value the event's `hash` field must equal if no content field was altered.
func recomputeMgmtAuditHash(e MgmtAuditEvent) (string, error) {
	pre, err := mgmtAuditPreimage(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(pre)
	return hex.EncodeToString(sum[:]), nil
}

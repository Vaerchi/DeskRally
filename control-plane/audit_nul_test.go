package controlplane

// The U+0000 storability guard must reject events PostgreSQL's jsonb genuinely cannot store, and
// must NOT reject events whose text merely looks like one.
//
// The distinction is load-bearing. The agent's chain is strictly sequential — it cannot skip event
// N — so a wrongly-rejected event is re-POSTed forever and that session's audit trail never persists
// at all. A false positive is therefore not a cosmetic 400; it is a way to make a session unauditable
// by typing six characters into any command.
//
// The original guard scanned the RAW request bytes for the six-byte sequence `\u0000`. That looked
// complete (JSON has exactly one spelling for U+0000) but matched ordinary text too: `echo "\u0000"`
// encodes as `\\u0000`, whose tail is a byte-for-byte match. These tests pin both directions.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// jsonNUL is the six-character JSON escape that really does decode to U+0000, assembled byte by
// byte so this file contains no NUL and no ambiguity about how many backslashes are meant.
func jsonNUL() string { return string([]byte{'\\', 'u', '0', '0', '0', '0'}) }

// jsonLiteralBackslashU is what those same six characters look like as ORDINARY TEXT once JSON has
// encoded them: the backslash is itself escaped. Decoding this yields the seven-character string
// `\u0000`, which contains no U+0000 at all and is perfectly storable.
func jsonLiteralBackslashU() string { return string([]byte{'\\', '\\', 'u', '0', '0', '0', '0'}) }

func TestAuditGuardAcceptsTextThatMerelyLooksLikeANULEscape(t *testing.T) {
	lit := jsonLiteralBackslashU()

	for _, tc := range []struct {
		name            string
		action, outcome json.RawMessage
	}{
		{
			// The motivating case: ordinary text that happens to contain the six characters.
			name:    "a browsed path containing a backslash-u escape",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:/logs/` + lit + `"}`),
			outcome: json.RawMessage(`{"result":"ok"}`),
		},
		{
			// The outcome side of the same session: a command failed and the error text contains it.
			name:    "an error message containing one",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:/logs"}`),
			outcome: json.RawMessage(`{"result":"failed","error":"bad regex: ` + lit + `"}`),
		},
		{
			// Nested, and in a field the canonical encoder does NOT hash — which is the whole reason
			// the storability check must scan the decoded document rather than the hashed subset:
			// jsonb stores the entire `action` value, hashed fields or not.
			name:    "nested in an array in a field that is stored but not hashed",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:/logs","args":["-e","` + lit + `"]}`),
			outcome: json.RawMessage(`{"result":"ok"}`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Premise, declared LOCALLY: the payload really does contain the six-byte sequence the
			// old guard scanned for, so this test would have failed against it. Without this the
			// test could silently stop exercising the false-positive path.
			if !containsRawSequence(tc.action, jsonNUL()) && !containsRawSequence(tc.outcome, jsonNUL()) {
				t.Fatalf("fixture no longer contains the raw sequence the old guard matched, so this "+
					"test proves nothing: action=%s outcome=%s", tc.action, tc.outcome)
			}
			// And the decoded value really has no U+0000 in it.
			if decodedHasNUL(t, tc.action) || decodedHasNUL(t, tc.outcome) {
				t.Fatal("fixture actually decodes to a U+0000; it belongs in the rejection test")
			}

			srv, store := auditServer(technicianPrincipal())
			e := mkAuditEvent(testSession, 0, GenesisPrevHash, tc.action, tc.outcome)

			rec := postIngest(t, srv, auditIngestRequest{SessionID: testSession, Events: []AuditEvent{e}})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 — storable text was rejected, which wedges the "+
					"session's chain forever (body %s)", rec.Code, rec.Body.String())
			}
			if tail, _ := store.AuditTail(context.Background(), "tenant-123", testSession); !tail.Exists {
				t.Fatal("the batch was accepted but nothing was stored")
			}
		})
	}
}

// The true positive must survive the fix, at every depth. Without this control the "fix" could be
// `return false` and every test above would still pass.
func TestAuditGuardStillRejectsARealNULAtAnyDepth(t *testing.T) {
	nul := jsonNUL()

	for _, tc := range []struct {
		name    string
		field   string
		action  json.RawMessage
		outcome json.RawMessage
	}{
		{
			name:    "top-level string value",
			field:   "outcome",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:/logs"}`),
			outcome: json.RawMessage(`{"result":"failed","error":"boom` + nul + `"}`),
		},
		{
			name:    "nested inside an array",
			field:   "action",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:/logs","args":["ok","bad` + nul + `"]}`),
			outcome: json.RawMessage(`{"result":"ok"}`),
		},
		{
			name:    "nested two objects deep",
			field:   "outcome",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:/logs"}`),
			outcome: json.RawMessage(`{"result":"failed","error":"boom","meta":{"inner":{"v":"x` + nul + `"}}}`),
		},
		{
			// jsonb rejects U+0000 in a KEY just as firmly as in a value.
			name:    "in an object key",
			field:   "action",
			action:  json.RawMessage(`{"kind":"file_browse","path":"C:/logs","bad` + nul + `":"v"}`),
			outcome: json.RawMessage(`{"result":"ok"}`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := mkAuditEvent(testSession, 0, GenesisPrevHash, tc.action, tc.outcome)

			var ue *UnstorableError
			err := verifyLinkage(AuditTail{}, []AuditEvent{e})
			if !errors.As(err, &ue) {
				t.Fatalf("verifyLinkage = %v, want *UnstorableError — an unstorable event that "+
					"reaches the INSERT becomes a 500, and the agent then retries it forever", err)
			}
			if ue.Field != tc.field {
				t.Fatalf("UnstorableError names field %q, want %q", ue.Field, tc.field)
			}
		})
	}
}

// --- helpers ---------------------------------------------------------------

func containsRawSequence(raw json.RawMessage, seq string) bool {
	return len(raw) > 0 && indexOfBytes(raw, []byte(seq)) >= 0
}

func indexOfBytes(hay, needle []byte) int {
outer:
	for i := 0; i+len(needle) <= len(hay); i++ {
		for j := range needle {
			if hay[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

func decodedHasNUL(t *testing.T, raw json.RawMessage) bool {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("fixture is not valid JSON: %v (%s)", err, raw)
	}
	return jsonValueHasNUL(v)
}

// The raw-0x00 check must stay BEFORE the escape fast path, and this pins the ordering.
//
// A literal 0x00 byte can only reach here from a caller that builds a RawMessage directly (the HTTP
// decoder rejects one inside a string), and such a payload need not contain the escape sequence at
// all. If the fast path ran first it would answer "no escape present, therefore storable" and wave
// through the exact byte jsonb cannot hold — so the cheap check is not merely an optimisation.
func TestAuditGuardRejectsARawNULByteWithNoEscapePresent(t *testing.T) {
	raw := json.RawMessage(append(append([]byte(`{"kind":"file_browse","path":"a`), 0), []byte(`b"}`)...))

	// Premise, declared locally: this payload contains NO escape sequence, so it can only be caught
	// by the raw-byte check.
	if containsRawSequence(raw, jsonNUL()) {
		t.Fatal("fixture contains the escape sequence, so it does not exercise the raw-byte path")
	}

	e := AuditEvent{
		SessionID: testSession,
		Seq:       0,
		PrevHash:  GenesisPrevHash,
		Action:    raw,
		Outcome:   json.RawMessage(`{"result":"ok"}`),
		// A well-formed hash so the isHex64 check upstream does not fire instead. The event cannot
		// be hashed for real — its action is not decodable JSON — which is the point: the guard has
		// to reject it on bytes alone.
		Hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	var ue *UnstorableError
	if err := verifyLinkage(AuditTail{}, []AuditEvent{e}); !errors.As(err, &ue) {
		t.Fatalf("verifyLinkage = %v, want *UnstorableError for a raw 0x00 byte", err)
	}
	if ue.Field != "action" {
		t.Fatalf("UnstorableError names field %q, want action", ue.Field)
	}
}

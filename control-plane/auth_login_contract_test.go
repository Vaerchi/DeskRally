package controlplane

// The wire contract between the browser console and POST /auth/login.
//
// WHY THIS FILE EXISTS. The console posted `{username, password, totp}`; this package decodes
// `{tenant, email, password, totp_code}`. Only `password` overlapped, so a Postgres-backed console
// could not log in AT ALL — and nothing failed anywhere, because Go's decoder simply leaves an
// unmatched field at its zero value. The login then failed as "invalid credentials", which is
// indistinguishable from a wrong password.
//
// Nothing caught it for two reasons worth keeping in mind:
//   - every Playwright e2e spawns the control plane with DATABASE_URL="" — the StubAuthenticator
//     that treats every request as a full-capability owner — so no test ever posts this body;
//   - both sides had unit tests, each asserting its OWN assumption. The TypeScript test pinned the
//     shape the client SENDS and this side pinned the shape the server DECODES, and no test
//     compared them.
//
// So this test hard-codes the literal JSON the console sends. Its twin is the payload assertion in
// web/viewer/src/lib/controlplane.test.ts. **If you change either, change both** — they are the two
// halves of one contract and the compiler cannot see it.

import (
	"encoding/json"
	"testing"
)

// consoleLoginBody is web/viewer/src/lib/controlplane.ts's request body, verbatim.
const consoleLoginBody = `{"tenant":"acme","email":"owner@acme.test","password":"pw","totp_code":"123456"}`

func TestLoginRequestDecodesTheConsolePayload(t *testing.T) {
	var req loginRequest
	if err := json.Unmarshal([]byte(consoleLoginBody), &req); err != nil {
		t.Fatalf("the console's login body does not decode: %v", err)
	}

	// Every field must arrive. A zero value here is the bug: it does not error, it just fails to
	// authenticate later, in a way that reads like a bad password.
	for _, f := range []struct{ name, got string }{
		{"tenant", req.Tenant},
		{"email", req.Email},
		{"password", req.Password},
		{"totp_code", req.TOTPCode},
	} {
		if f.got == "" {
			t.Errorf("field %q decoded EMPTY from the console's body — the console and the server "+
				"disagree about its name, and login will fail as 'invalid credentials'", f.name)
		}
	}
}

// The negative control, and the actual regression guard: the OLD body must NOT satisfy the decoder.
//
// Without this, a "fix" that made loginRequest accept both spellings would pass the test above while
// leaving the ambiguity that caused the outage. Pinning that the old shape is REJECTED is what says
// the two sides now agree on exactly one spelling.
func TestTheOldConsolePayloadDoesNotAuthenticate(t *testing.T) {
	const old = `{"username":"owner@acme.test","password":"pw","totp":"123456"}`

	var req loginRequest
	if err := json.Unmarshal([]byte(old), &req); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if req.Tenant != "" || req.Email != "" {
		t.Fatalf("the pre-fix console body populated tenant/email (%q/%q); if the server now accepts "+
			"both spellings, delete this test deliberately rather than letting it fail", req.Tenant, req.Email)
	}
	if req.Password == "" {
		t.Error("premise: `password` was the one field that always matched")
	}
}

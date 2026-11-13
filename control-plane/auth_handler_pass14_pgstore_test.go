package controlplane

// Pass 14: Cryptographic ticket and session-policy signature verification.
//
// Closes the gap in codex-pg-auth-review.md §3: "signature validity is not tested —
// decoding JSON and checking claims does not cryptographically verify v1 or compat
// signatures."
//
// Two tests:
//
//   TestPass14_Pg_TicketCryptoVerification
//     POST /sessions returns a SignedSessionTicket. This test decodes it and calls
//     ed25519.Verify(issuerPub, ticketSigningBytes(claims), hexDecode(sig)) directly.
//     Tampered-claim and cross-ticket cases must fail verification.
//
//   TestPass14_Pg_PolicyCryptoVerification
//     POST /sessions/{id}/policy returns a signed session-policy. This test decodes
//     both sig_v1 (10-field preimage) and sig/SigCompat (6-field v0 compat preimage)
//     and verifies each with ed25519.Verify. Cross-preimage and bit-flipped cases must
//     fail.
//
// Both tests reuse newPass13PgFixture: real argon2id login, real PG stores, FORCE RLS,
// genuine SessionAuthenticator. No StubAuthenticator.
//
// Run (disposable PG required):
//
//	TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5490/rmt_test?sslmode=disable \
//	  go test ./control-plane -run TestPass14_Pg_ -v -count=1

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
)

// ─── helper ───────────────────────────────────────────────────────────────────

// startSessionFull calls POST /sessions and expects 201. Returns both the decoded
// SessionRecord and the SignedSessionTicket from the signaling.ticket field.
// Fatals if the response is not 201, if decoding fails, or if the signaling field
// is absent (which would mean the issuer is not wired into the fixture).
func (f *pass13PgFixture) startSessionFull(t *testing.T, sess, csrfCookie *http.Cookie, csrfTok, deviceID string) (*SessionRecord, *SignedSessionTicket) {
	t.Helper()
	rec := doJSONWith(t, f.handler, "POST", "/sessions",
		startSessionRequest{MachineID: deviceID}, csrfTok, sess, csrfCookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("startSessionFull device=%s = %d: %s", deviceID, rec.Code, rec.Body.String())
	}
	var body struct {
		Session   SessionRecord `json:"session"`
		Signaling *struct {
			Ticket *SignedSessionTicket `json:"ticket"`
		} `json:"signaling"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode start-session body: %v (%s)", err, rec.Body.String())
	}
	if body.Signaling == nil || body.Signaling.Ticket == nil {
		t.Fatalf("start-session response missing signaling.ticket — issuer not wired in fixture")
	}
	return &body.Session, body.Signaling.Ticket
}

// p14VerifyTicket performs a complete identity-binding and Ed25519 signature check
// on a SignedSessionTicket issued by the fixture's grant issuer. It fatals on any
// mismatch, so tests can call it and proceed knowing the ticket is genuine.
func p14VerifyTicket(t *testing.T, pub []byte, ticket *SignedSessionTicket, who, technicianID, tenantID, deviceID, sessionID string) {
	t.Helper()
	if ticket.Claims.TechnicianID != technicianID {
		t.Errorf("%s ticket: TechnicianID = %q, want %q", who, ticket.Claims.TechnicianID, technicianID)
	}
	if ticket.Claims.TenantID != tenantID {
		t.Errorf("%s ticket: TenantID = %q, want %q", who, ticket.Claims.TenantID, tenantID)
	}
	if ticket.Claims.DeviceID != deviceID {
		t.Errorf("%s ticket: DeviceID = %q, want %q", who, ticket.Claims.DeviceID, deviceID)
	}
	if ticket.Claims.SessionID != sessionID {
		t.Errorf("%s ticket: SessionID = %q, want %q", who, ticket.Claims.SessionID, sessionID)
	}
	if ticket.Claims.IssuedAtMs <= 0 {
		t.Errorf("%s ticket: IssuedAtMs = %d, want > 0", who, ticket.Claims.IssuedAtMs)
	}
	if ticket.Claims.ExpiresAtMs <= ticket.Claims.IssuedAtMs {
		t.Errorf("%s ticket: ExpiresAtMs (%d) not after IssuedAtMs (%d)",
			who, ticket.Claims.ExpiresAtMs, ticket.Claims.IssuedAtMs)
	}
	if ticket.Sig == "" {
		t.Errorf("%s ticket: Sig is empty", who)
	}
	sigBytes, err := hex.DecodeString(ticket.Sig)
	if err != nil {
		t.Fatalf("%s ticket: decode sig hex: %v", who, err)
	}
	if !ed25519.Verify(pub, ticketSigningBytes(ticket.Claims), sigBytes) {
		t.Errorf("%s ticket: Ed25519 signature does not verify against the grant issuer public key", who)
	}
}

// ─── tests ────────────────────────────────────────────────────────────────────

// TestPass14_Pg_TicketCryptoVerification proves that POST /sessions returns a
// SignedSessionTicket whose Ed25519 signature verifies against the grant issuer's
// actual public key, and that tampering any claim field causes verification to fail.
//
// Distinct from TestPass13_Pg_SignedRenewalClaimsVerified, which asserts non-empty
// signature strings without calling ed25519.Verify. This test closes that gap for
// session tickets.
func TestPass14_Pg_TicketCryptoVerification(t *testing.T) {
	f := newPass13PgFixture(t)

	// Obtain the grant issuer's Ed25519 public key from the fixture's server.
	pubHex := f.srv.Grants.PublicKeyHex()
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decode issuer public key hex: %v", err)
	}

	// Alice and Bob each log in independently and start a session on M1.
	aliceSess, aliceCSRF, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	bobSess, bobCSRF, bobCSRFTok := f.loginAs(t, p13TenantAlpha, p13BobEmail, p13BobPw)

	sessionA, ticketA := f.startSessionFull(t, aliceSess, aliceCSRF, aliceCSRFTok, f.m1DevID)
	sessionB, ticketB := f.startSessionFull(t, bobSess, bobCSRF, bobCSRFTok, f.m1DevID)

	// ── Positive: Alice's ticket verifies with correct identity bindings ───────
	p14VerifyTicket(t, pub, ticketA, "Alice", f.aliceUID, f.alphaTid, f.m1DevID, sessionA.ID)

	// ── Positive: Bob's ticket verifies with correct identity bindings ─────────
	p14VerifyTicket(t, pub, ticketB, "Bob", f.bobUID, f.alphaTid, f.m1DevID, sessionB.ID)

	// ── Positive: Alice and Bob have distinct signatures ───────────────────────
	// Per-session nonce in the preimage (different session_id, technician_id) guarantees this.
	if ticketA.Sig == ticketB.Sig {
		t.Error("Alice and Bob tickets carry the same signature — distinct per-session sigs required")
	}

	// ── Negative: tampered session_id fails ───────────────────────────────────
	// The claims struct is copied (value type), so modifying it does not affect ticketA.
	tampered := *ticketA
	tampered.Claims.SessionID = sessionB.ID
	sigA, _ := hex.DecodeString(ticketA.Sig)
	if ed25519.Verify(pub, ticketSigningBytes(tampered.Claims), sigA) {
		t.Error("tampered session_id still verified — session_id is not in the signed preimage")
	}

	// ── Negative: tampered technician_id fails ────────────────────────────────
	tampered2 := *ticketA
	tampered2.Claims.TechnicianID = f.bobUID
	if ed25519.Verify(pub, ticketSigningBytes(tampered2.Claims), sigA) {
		t.Error("tampered technician_id still verified — technician_id is not in the signed preimage")
	}

	// ── Negative: Bob's signature over Alice's claims fails ────────────────────
	// Cross-ticket replay: hold Alice's claims, present Bob's signature.
	sigB, _ := hex.DecodeString(ticketB.Sig)
	if ed25519.Verify(pub, ticketSigningBytes(ticketA.Claims), sigB) {
		t.Error("Bob's sig verified against Alice's claims — cross-session ticket reuse accepted")
	}

	// ── Negative: bit-flipped signature fails ─────────────────────────────────
	flipped := make([]byte, len(sigA))
	copy(flipped, sigA)
	flipped[0] ^= 0xFF
	if ed25519.Verify(pub, ticketSigningBytes(ticketA.Claims), flipped) {
		t.Error("bit-flipped sig_v1 still verified — Ed25519 is not rejecting corrupted signatures")
	}
}

// TestPass14_Pg_PolicyCryptoVerification proves that POST /sessions/{id}/policy
// returns a SignedSessionPolicy whose sig_v1 (v1/10-field preimage) and sig
// (v0-compat/6-field preimage) both verify against the grant issuer's public key.
// Cross-preimage and bit-flip cases must fail.
//
// Closes codex-pg-auth-review.md §3: "Decoding JSON and checking claims does not
// cryptographically verify v1 or compat signatures."
func TestPass14_Pg_PolicyCryptoVerification(t *testing.T) {
	f := newPass13PgFixture(t)

	pubHex := f.srv.Grants.PublicKeyHex()
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decode issuer public key hex: %v", err)
	}

	// Alice logs in and starts a session; the renewal response carries the signed policy.
	aliceSess, aliceCSRF, aliceCSRFTok := f.loginAs(t, p13TenantAlpha, p13AliceEmail, p13AlicePw)
	sessionA := f.startSession(t, aliceSess, aliceCSRF, aliceCSRFTok, f.m1DevID)

	// Renew to obtain the signed policy.
	rec := f.renewLeaseRaw(t, aliceSess, aliceCSRF, aliceCSRFTok, sessionA.ID)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew lease = %d: %s", rec.Code, rec.Body.String())
	}

	// Decode the outer envelope.
	var outer struct {
		SessionPolicy struct {
			Signed string `json:"signed"`
		} `json:"session_policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &outer); err != nil {
		t.Fatalf("decode renewal envelope: %v (%s)", err, rec.Body.String())
	}
	if outer.SessionPolicy.Signed == "" {
		t.Fatal("session_policy.signed is empty — renewal handler did not mint a policy")
	}

	// Decode the inner SignedSessionPolicy from its wire JSON form.
	var ssp SignedSessionPolicy
	if err := json.Unmarshal([]byte(outer.SessionPolicy.Signed), &ssp); err != nil {
		t.Fatalf("decode SignedSessionPolicy: %v (%s)", err, outer.SessionPolicy.Signed)
	}

	pol := ssp.Claims.Policy

	// ── Positive: sig_v1 (10-field v1 preimage) verifies ─────────────────────
	v1msg, err := sessionPolicySigningBytes(
		pol.TechnicianID, pol.SessionID, pol.MachineID, pol.Access,
		pol.AllowRecording, pol.RequireRecording,
		pol.MaxSessionDurationSeconds, pol.MaxIdleSeconds,
		ssp.Claims.IssuedAtMs, ssp.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("build v1 signing bytes: %v", err)
	}
	v1sig, err := hex.DecodeString(ssp.Sig)
	if err != nil {
		t.Fatalf("decode sig_v1 hex: %v", err)
	}
	if !ed25519.Verify(pub, v1msg, v1sig) {
		t.Error("sig_v1 does not verify against the grant issuer public key")
	}

	// ── Positive: sig / SigCompat (6-field v0-compat preimage) verifies ───────
	// Old deployed agents (735d5a28) compute only the first 6 fields; the v0 sig
	// must verify against that shorter preimage, not against the v1 preimage.
	v0msg, err := sessionPolicySigningBytesV0(
		pol.TechnicianID, pol.SessionID, pol.MachineID, pol.Access,
		ssp.Claims.IssuedAtMs, ssp.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("build v0 signing bytes: %v", err)
	}
	if ssp.SigCompat == "" {
		t.Fatal("sig (v0 compat) is empty — control-level policy must carry both signatures")
	}
	v0sig, err := hex.DecodeString(ssp.SigCompat)
	if err != nil {
		t.Fatalf("decode sig (compat) hex: %v", err)
	}
	if !ed25519.Verify(pub, v0msg, v0sig) {
		t.Error("sig (v0 compat) does not verify against the grant issuer public key")
	}

	// ── Positive: domain separation — v0 sig over v0 preimage, not v1 ─────────
	// If the two preimages were identical the domain separation would be absent,
	// meaning the two "sig" fields would be interchangeable and the upgrade guarantee
	// would be hollow. Prove the preimages differ.
	if string(v0msg) == string(v1msg) {
		t.Error("v0 and v1 signing preimages are identical — domain separation not working")
	}

	// ── Negative: v0 sig does NOT verify against v1 preimage ─────────────────
	// The two sigs cover DIFFERENT preimages; interchanging them must fail.
	if ed25519.Verify(pub, v1msg, v0sig) {
		t.Error("v0-compat sig verified against v1 preimage — domain-separated preimages accepted interchangeably")
	}

	// ── Negative: v1 sig does NOT verify against v0 preimage ─────────────────
	if ed25519.Verify(pub, v0msg, v1sig) {
		t.Error("v1 sig verified against v0 preimage — domain-separated preimages accepted interchangeably")
	}

	// ── Negative: bit-flipped sig_v1 fails ───────────────────────────────────
	flipped := make([]byte, len(v1sig))
	copy(flipped, v1sig)
	flipped[0] ^= 0xFF
	if ed25519.Verify(pub, v1msg, flipped) {
		t.Error("bit-flipped sig_v1 still verified — Ed25519 is not rejecting corrupted signatures")
	}

	// ── Negative: different technician_id causes v1 verification to fail ──────
	wrongMsg, err := sessionPolicySigningBytes(
		f.bobUID, pol.SessionID, pol.MachineID, pol.Access,
		pol.AllowRecording, pol.RequireRecording,
		pol.MaxSessionDurationSeconds, pol.MaxIdleSeconds,
		ssp.Claims.IssuedAtMs, ssp.Claims.ExpiresAtMs)
	if err != nil {
		t.Fatalf("build v1 bytes for wrong technician: %v", err)
	}
	if ed25519.Verify(pub, wrongMsg, v1sig) {
		t.Error("sig_v1 verified for a different technician_id — technician binding not in signed preimage")
	}
}

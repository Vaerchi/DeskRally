package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// =====================================================================================
// GOLDEN CROSS-LANGUAGE VECTOR (session-policy v1).
//
// The SAME fixed fixture is hardcoded in Rust's agent/src/session_policy.rs
// (`tests::golden_vector_v1`). If either language's canonical encoder or Ed25519 signing ever
// drifts, one side stops matching these constants. DO NOT change a value here without changing it
// identically in the Rust test.
//
// The seed is deliberately the SAME one the backstage-grant golden vector uses, so the two vectors
// share an issuer key. That makes the domain tag the ONLY thing separating their signatures — which
// is exactly the property TestSessionPolicyAndGrantPreimagesAreDomainSeparated relies on.
// =====================================================================================

const (
	// V1 preimage (10 fields): domain_tag + tech + session + machine + access + issued_at +
	// expires_at + allow_recording(1) + require_recording(1) + max_session_duration(4) +
	// max_idle(4) = 99 bytes for "view_only". Cross-language agreement is pinned by
	// TestSessionPolicyGoldenVectorV1 here and `golden_vector_v1` in agent/src/session_policy.rs
	// (same fixture, both must produce the same hex for Sig / JSON "sig_v1").
	goldenPolicyPreimageHex = "524d5453504f4c763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000009766965775f6f6e6c7900000192cc09140000000192cc16cfa001000000000000000000"
	// goldenPolicySigHex is the v1-preimage (10-field) signature, emitted as JSON "sig_v1".
	// New agents verify this field. Old agents never see it (they only read "sig").
	goldenPolicySigHex = "173461f73fc4f95521a90dfa2e07ebcfa9c977b34714f2aba0632887a50b8c0d99e87e4c4baebc4d4748705bfbe5990323f923e4e25969bae8dd7195b1d4590c"

	// V0 preimage (6 fields): domain_tag + tech + session + machine + access + issued_at +
	// expires_at = 89 bytes for "view_only". Matches deployed agent 735d5a28's signing_bytes().
	// Old agents compute THIS preimage and verify JSON "sig" against it.
	goldenPolicyV0PreimageHex = "524d5453504f4c763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000009766965775f6f6e6c7900000192cc09140000000192cc16cfa0"
	// goldenPolicyCompatSigHex is the JSON "sig" value for non-restrictive policies: the v0-preimage
	// (6-field) signature. Old agents (735d5a28) verify "sig" against their locally-computed 6-field
	// preimage — so this MUST be a v0 sig, NOT a copy of "sig_v1".
	goldenPolicyCompatSigHex = "e61603c0cfad57952f37be8513e65121a9b1215fe9a1ee8141661054fdd040ae0391e8524fba935b4fd2a96b67e0bcb7fb4124de7bb5a2d5ec92d0847ef41903"

	// The SAME fixture at access=control (loop 83). Its own vector, because `control` had never been
	// minted anywhere in the tree before migration 0036: the attended path now mints one to DISCHARGE
	// a provisional floor, and that is the single most consequential policy this system emits — it is
	// the one that hands input back. A drift in the level's canonical encoding would make the agent
	// reject it, which does not fail loudly: the guest simply stays view-only forever, which is
	// precisely the stranding 0036 exists to prevent. The level string is the ONLY difference from the
	// view_only vector above, so together they also pin that the level is inside the signed bytes at
	// all (a minter that dropped it would produce identical preimages for both).
	goldenPolicyControlPreimageHex = "524d5453504f4c763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000007636f6e74726f6c00000192cc09140000000192cc16cfa001000000000000000000"
	// v1 sig (JSON "sig_v1") for the control fixture.
	goldenPolicyControlSigHex = "6d996a0cafc6088d46505f304b582213bc59932bccd7454b3e41857e357a570654e696c1a98f016ce83dc4913454ea62ee84769ad43bf33cde45dee7a017e309"
	// V0 preimage for control (87 bytes). Matches deployed agent 735d5a28.
	goldenPolicyControlV0PreimageHex = "524d5453504f4c763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000007636f6e74726f6c00000192cc09140000000192cc16cfa0"
	// v0 sig (JSON "sig") for the control fixture — verified by old agents against v0 preimage.
	goldenPolicyControlCompatSigHex = "b9caa7f6010935eb261364ddf9ddd5c1215a7b330f075215ea777c5fd402dafe88aa3ccadf50325dc4e60522ce9c4967bab21fc7b49420dc4fac22d350693a0f"
)

func goldenPolicyIssuer(t *testing.T) *GrantIssuer {
	t.Helper()
	seed, err := hex.DecodeString(goldenSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	iss, err := NewGrantIssuerFromSeed(seed)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss
}

// The preimage AND the signature must match Rust byte-for-byte. Asserting the preimage separately
// from the signature matters: if only the signature were checked, a change that altered the
// preimage and the expected signature together (e.g. a regenerated constant) would still pass, and
// the agent — which computes the preimage itself — would start rejecting every policy.
func TestSessionPolicyGoldenVectorV1(t *testing.T) {
	iss := goldenPolicyIssuer(t)

	if got := iss.PublicKeyHex(); got != goldenPubkeyHex {
		t.Fatalf("pubkey drift:\n got  %s\n want %s", got, goldenPubkeyHex)
	}

	msg, err := sessionPolicySigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenPolicyPreimageHex {
		t.Fatalf("canonical preimage drift (Rust will reject every policy):\n got  %s\n want %s",
			got, goldenPolicyPreimageHex)
	}

	signed, err := iss.MintSessionPolicy(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	t.Logf("new view_only sig_v1 = %s", signed.Sig)
	if signed.Sig != goldenPolicySigHex {
		t.Fatalf("sig_v1 drift:\n got  %s\n want %s", signed.Sig, goldenPolicySigHex)
	}
	t.Logf("new view_only sig (v0 compat) = %s", signed.SigCompat)
	if signed.SigCompat != goldenPolicyCompatSigHex {
		t.Fatalf("compat sig drift (old agents read JSON \"sig\" and verify against v0 preimage):\n got  %s\n want %s",
			signed.SigCompat, goldenPolicyCompatSigHex)
	}
	if signed.Sig == signed.SigCompat {
		t.Fatal("Sig (v1) and SigCompat (v0) must be DIFFERENT — they sign different preimages")
	}

	// Printed so the Rust-side `verifies_go_minted_session_policy` fixture can be captured
	// verbatim (go test -run TestSessionPolicyGoldenVectorV1 -v).
	js, err := signed.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	t.Logf("GO_MINTED_SESSION_POLICY_JSON = %s", js)
}

// The `control` half of the golden vector (loop 83). Same fixture, same key, same window — only the
// level differs — so this pins the encoding of the level that RELEASES input.
func TestSessionPolicyGoldenVectorV1Control(t *testing.T) {
	iss := goldenPolicyIssuer(t)

	msg, err := sessionPolicySigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessControl, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenPolicyControlPreimageHex {
		t.Fatalf("canonical preimage drift for access=control (Rust will reject the policy that "+
			"discharges a provisional floor, stranding the guest in view-only):\n got  %s\n want %s",
			got, goldenPolicyControlPreimageHex)
	}
	// And it must NOT equal the view_only preimage: a minter that dropped the level from the signed
	// bytes would produce the same preimage for both, and every assertion above would still pass.
	if got := hex.EncodeToString(msg); got == goldenPolicyPreimageHex {
		t.Fatal("the control and view_only preimages are IDENTICAL — the access level is not covered " +
			"by the signature, so a view_only policy could be replayed as a control policy")
	}

	signed, err := iss.MintSessionPolicy(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessControl, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	t.Logf("new control sig = %s", signed.Sig)
	if signed.Sig != goldenPolicyControlSigHex {
		t.Fatalf("signature drift:\n got  %s\n want %s", signed.Sig, goldenPolicyControlSigHex)
	}
	if signed.SigCompat != goldenPolicyControlCompatSigHex {
		t.Fatalf("compat sig drift for access=control:\n got  %s\n want %s",
			signed.SigCompat, goldenPolicyControlCompatSigHex)
	}

	// Printed so the Rust-side `verifies_go_minted_control_session_policy` fixture can be captured
	// verbatim (go test -run TestSessionPolicyGoldenVectorV1Control -v).
	js, err := signed.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	t.Logf("GO_MINTED_CONTROL_SESSION_POLICY_JSON = %s", js)
}

// Pins the v0 (deployed-baseline) preimage and its signature against the golden fixture.
// TestSessionPolicyGoldenVectorV1 pins the v1 side; the Rust side pins both:
// `golden_vector_v0` and `golden_vector_v1` in agent/src/session_policy.rs.
//
// If this test drifts from the Rust side the deployed agent (735d5a28) will reject every
// non-restrictive policy emitted by new CP (bad "sig" verification), silently breaking sessions.
func TestSessionPolicyGoldenVectorV0(t *testing.T) {
	iss := goldenPolicyIssuer(t)
	pub := ed25519.PublicKey(iss.priv[32:])

	// view_only v0 preimage.
	msg, err := sessionPolicySigningBytesV0(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("v0 signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenPolicyV0PreimageHex {
		t.Fatalf("v0 preimage drift (deployed agent computes this; Rust golden_vector_v0 must match):\n got  %s\n want %s",
			got, goldenPolicyV0PreimageHex)
	}
	// Verify the compat sig against the v0 preimage (what deployed agents do).
	sigBytes, err := hex.DecodeString(goldenPolicyCompatSigHex)
	if err != nil {
		t.Fatalf("decode compat sig: %v", err)
	}
	if !ed25519.Verify(pub, msg, sigBytes) {
		t.Fatalf("v0 compat sig does not verify against v0 preimage — deployed agent will reject")
	}

	// control v0 preimage.
	ctrlMsg, err := sessionPolicySigningBytesV0(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessControl, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("control v0 signing bytes: %v", err)
	}
	if got := hex.EncodeToString(ctrlMsg); got != goldenPolicyControlV0PreimageHex {
		t.Fatalf("control v0 preimage drift:\n got  %s\n want %s", got, goldenPolicyControlV0PreimageHex)
	}
	ctrlSigBytes, err := hex.DecodeString(goldenPolicyControlCompatSigHex)
	if err != nil {
		t.Fatalf("decode control compat sig: %v", err)
	}
	if !ed25519.Verify(pub, ctrlMsg, ctrlSigBytes) {
		t.Fatalf("control v0 compat sig does not verify against v0 preimage")
	}
	// v0 and v1 preimages MUST differ for the same fixture (sanity: restriction bytes present).
	v1Msg, _ := sessionPolicySigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if bytes.Equal(msg, v1Msg) {
		t.Fatal("v0 and v1 preimages identical — restriction bytes not being appended")
	}
}

// NOTE: TestDomainTagsArePairwiseDistinct used to live here and covered three tags. Loop 87 moved
// it to elevation_mint_test.go and widened it to all SIX — the two it never covered
// (ticketDomainTag, mgmtAuditDomainTag) were pinned only partially, by a different test in a
// different file, so no single test asserted the whole set.

// A policy preimage and a grant preimage built from the SAME (technician, session, machine) and the
// SAME window must not share a prefix beyond byte 0 — the tag separates them immediately. This is
// the cross-artifact half of the Rust
// `a_policy_preimage_is_domain_separated_from_a_grant_preimage` test.
func TestSessionPolicyAndGrantPreimagesAreDomainSeparated(t *testing.T) {
	policy, err := sessionPolicySigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessControl, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("policy preimage: %v", err)
	}
	grant, err := signingBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		goldenCaps, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("grant preimage: %v", err)
	}
	if !bytes.HasPrefix(policy, sessionPolicyDomainTag) {
		t.Fatal("a policy preimage must open with the session-policy tag")
	}
	if bytes.HasPrefix(policy, grantDomainTag) {
		t.Fatal("a policy preimage must NOT open with the grant tag")
	}
	if bytes.Equal(policy[:12], grant[:12]) {
		t.Fatal("policy and grant preimages open with the same 12 bytes")
	}
}

// An unknown access level must fail AT THE MINT, not be signed and shipped. A signed-but-unknown
// level would be rejected by the agent's decoder and silently fall back to its default, turning a
// control-plane bug into an unexplained loss of control for the technician.
func TestMintSessionPolicyRejectsAnUnknownAccessLevel(t *testing.T) {
	iss := goldenPolicyIssuer(t)
	for _, bad := range []SessionAccessLevel{"", "view-only", "VIEW_ONLY", "full", "control "} {
		signed, err := iss.MintSessionPolicy(
			goldenTechnicianID, goldenSessionID, goldenMachineID,
			bad, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
		if err == nil {
			t.Errorf("access level %q was minted, want an error (sig %q)", string(bad), signed.Sig)
		}
		if signed.Sig != "" {
			t.Errorf("access level %q returned a signature %q on the error path", string(bad), signed.Sig)
		}
	}
	// …and both real levels DO mint, so the guard is not simply rejecting everything.
	for _, good := range []SessionAccessLevel{SessionAccessViewOnly, SessionAccessControl} {
		if _, err := iss.MintSessionPolicy(
			goldenTechnicianID, goldenSessionID, goldenMachineID,
			good, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs); err != nil {
			t.Errorf("access level %q should mint, got %v", string(good), err)
		}
	}
}

// Each UUID field is parsed, so a malformed one fails at the mint rather than producing a policy the
// agent cannot bind to a device. Checked per-field so a guard that validates only the first is
// caught.
func TestMintSessionPolicyRejectsAMalformedUUID(t *testing.T) {
	iss := goldenPolicyIssuer(t)
	cases := []struct{ name, tech, sess, mach, want string }{
		{"technician", "nope", goldenSessionID, goldenMachineID, "technician_id"},
		{"session", goldenTechnicianID, "nope", goldenMachineID, "session_id"},
		{"machine", goldenTechnicianID, goldenSessionID, "nope", "machine_id"},
	}
	for _, c := range cases {
		_, err := iss.MintSessionPolicy(c.tech, c.sess, c.mach, SessionAccessViewOnly,
			true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
		if err == nil {
			t.Errorf("%s: malformed uuid was minted, want an error", c.name)
			continue
		}
		// The error must name WHICH field, or a caller cannot tell a bad machine id from a bad
		// technician id.
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not name the field %q", c.name, err, c.want)
		}
	}
}

// The access level reaches the signing bytes: two policies that differ ONLY in their level must
// produce different preimages and different signatures. Without this, a mint that dropped the level
// from the preimage would still pass every other test here while making a `view_only` policy
// forgeable into `control` (its signature would cover the same bytes).
func TestTheAccessLevelIsCoveredByTheSignature(t *testing.T) {
	iss := goldenPolicyIssuer(t)
	view, err := iss.MintSessionPolicy(goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint view_only: %v", err)
	}
	control, err := iss.MintSessionPolicy(goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessControl, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint control: %v", err)
	}
	if view.Sig == control.Sig {
		t.Fatal("view_only and control produced the SAME signature — the level is not signed")
	}
	if view.Access() != SessionAccessViewOnly || control.Access() != SessionAccessControl {
		t.Fatalf("Access() mis-reports: %q / %q", view.Access(), control.Access())
	}
}

// The wire JSON must carry exactly the field names Rust's serde expects. A rename on either side
// silently breaks every install, and the failure would surface only on a live agent.
func TestSignedSessionPolicyJSONWireShape(t *testing.T) {
	iss := goldenPolicyIssuer(t)

	t.Run("non-restrictive has both sig and sig_v1", func(t *testing.T) {
		signed, err := iss.MintSessionPolicy(goldenTechnicianID, goldenSessionID, goldenMachineID,
			SessionAccessViewOnly, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		js, err := signed.JSON()
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		for _, want := range []string{
			`"claims"`, `"policy"`, `"technician_id"`, `"session_id"`, `"machine_id"`,
			`"access":"view_only"`, `"allow_recording":true`, `"require_recording":false`,
			`"max_session_duration_seconds":0`, `"max_idle_seconds":0`,
			`"issued_at_ms":1730000000000`, `"expires_at_ms":1730000900000`,
			`"sig":`, `"sig_v1":`,
		} {
			if !strings.Contains(js, want) {
				t.Errorf("wire JSON missing %s\n got: %s", want, js)
			}
		}
	})

	t.Run("restrictive has sig_v1 only, no sig", func(t *testing.T) {
		signed, err := iss.MintSessionPolicy(goldenTechnicianID, goldenSessionID, goldenMachineID,
			SessionAccessViewOnly, false, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		js, err := signed.JSON()
		if err != nil {
			t.Fatalf("json: %v", err)
		}
		if !strings.Contains(js, `"sig_v1":`) {
			t.Errorf("restrictive JSON missing sig_v1\n got: %s", js)
		}
		// "sig" must be absent (omitempty) — old agents must fail closed on restrictive policies.
		// Check by looking for the key with colon to avoid false-matching inside "sig_v1".
		if strings.Contains(js, `"sig":"`) {
			t.Errorf("restrictive JSON must NOT contain \"sig\" field\n got: %s", js)
		}
	})
}

// The allow_recording=false path pins the encoding of the RESTRICTION byte — the one case that
// actually exercises the ban. The preimage ends with 0x00 instead of 0x01, and the signature
// differs from the allow=true vector, proving the byte IS inside the signed bytes.
const (
	goldenPolicyBannedPreimageHex = "524d5453504f4c763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000009766965775f6f6e6c7900000192cc09140000000192cc16cfa000000000000000000000"
	goldenPolicyBannedSigHex      = "9b59d058e332e732fbb9db4c032a2dc9cfb866dae352b3766242b58cd9a8e95537621b2fb927ec2e560f6323c8ae2f8fe9537ea178e23df19a894da869f4f10d"
)

// The require_recording=true path pins the encoding of the mandatory-recording byte (0x01) that
// follows allow_recording. This vector exists to prove the field is INSIDE the signed preimage: a
// policy that drops require_recording would produce the same preimage as the allow=true vector, and
// any signature over one would pass for the other.
const (
	goldenPolicyRequiredPreimageHex = "524d5453504f4c763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000009766965775f6f6e6c7900000192cc09140000000192cc16cfa001010000000000000000"
	goldenPolicyRequiredSigHex      = "8cac73f680179949d230aed6dd0195e604a6a6fbaba48d111d4e4be474e0d639ca389e33d0c9eda835ae4039c39665f690362847e90727850592c7672da45e0a"
)

func TestSessionPolicyGoldenVectorV1RecordingRequired(t *testing.T) {
	iss := goldenPolicyIssuer(t)

	msg, err := sessionPolicySigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, true, true, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenPolicyRequiredPreimageHex {
		t.Fatalf("required preimage drift:\n got  %s\n want %s", got, goldenPolicyRequiredPreimageHex)
	}
	// Must differ from the allow=true, require=false preimage.
	if got := hex.EncodeToString(msg); got == goldenPolicyPreimageHex {
		t.Fatal("required and optional preimages are IDENTICAL — require_recording is not in the signed bytes")
	}

	signed, err := iss.MintSessionPolicy(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, true, true, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	t.Logf("new required sig = %s", signed.Sig)
	if signed.Sig != goldenPolicyRequiredSigHex {
		t.Fatalf("required signature drift:\n got  %s\n want %s", signed.Sig, goldenPolicyRequiredSigHex)
	}
	// require_recording=true is a NEW RESTRICTION — "sig" must be ABSENT so old agents fail closed.
	if signed.SigCompat != "" {
		t.Fatalf("restrictive policy must have empty SigCompat (no JSON \"sig\"), got %q", signed.SigCompat)
	}
	js, err := signed.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if strings.Contains(js, `"sig":`) {
		t.Fatalf("restrictive policy JSON must NOT contain \"sig\" field, got: %s", js)
	}
	t.Logf("GO_MINTED_REQUIRED_SESSION_POLICY_JSON = %s", js)
}

func TestSessionPolicyGoldenVectorV1RecordingBanned(t *testing.T) {
	iss := goldenPolicyIssuer(t)

	msg, err := sessionPolicySigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, false, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenPolicyBannedPreimageHex {
		t.Fatalf("banned preimage drift:\n got  %s\n want %s", got, goldenPolicyBannedPreimageHex)
	}
	// Must differ from the allow=true preimage — the restriction byte IS covered by the signature.
	if got := hex.EncodeToString(msg); got == goldenPolicyPreimageHex {
		t.Fatal("banned and allowed preimages are IDENTICAL — allow_recording is not in the signed bytes")
	}

	signed, err := iss.MintSessionPolicy(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, false, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	t.Logf("new banned sig = %s", signed.Sig)
	if signed.Sig != goldenPolicyBannedSigHex {
		t.Fatalf("banned signature drift:\n got  %s\n want %s", signed.Sig, goldenPolicyBannedSigHex)
	}
	// allow_recording=false is a NEW RESTRICTION — "sig" must be ABSENT so old agents fail closed.
	if signed.SigCompat != "" {
		t.Fatalf("restrictive policy must have empty SigCompat (no JSON \"sig\"), got %q", signed.SigCompat)
	}
	js, err := signed.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if strings.Contains(js, `"sig":`) {
		t.Fatalf("restrictive policy JSON must NOT contain \"sig\" field, got: %s", js)
	}
	t.Logf("GO_MINTED_BANNED_SESSION_POLICY_JSON = %s", js)
}

// =====================================================================================
// DEPLOYMENT COMPATIBILITY: CROSS-VERSION SIGNING-BYTES FIXTURES
//
// The preimage layout has grown across marathon rounds:
//
//   v0 (deployed base, 735d5a28b3601dc5b87971b912bc61d9dd8ffd35):
//     domain_tag(12) + technician(16) + session(16) + machine(16) + len(4) + access(N) +
//     issued_at(8) + expires_at(8)
//     = 89 bytes for "view_only" (N=9), 87 bytes for "control" (N=7)
//
//   v1 (current; restriction fields added in R55/R57/R58/R60 cumulatively):
//     v0 + allow_recording(1) + require_recording(1) + max_session_duration_seconds(4) +
//     max_idle_seconds(4) = v0 + 10 bytes
//     = 99 bytes for "view_only", 97 bytes for "control"
//
// WIRE COMPATIBILITY (R74 fix — corrects the R72 error that put a v1 sig in "sig"):
//   Non-restrictive policies: JSON carries BOTH "sig" (v0 sig) and "sig_v1" (v1 sig).
//     Old agents read "sig" and verify it against their locally-computed v0 preimage → PASS.
//     New agents read "sig_v1" and verify it against the v1 preimage → PASS.
//     "sig" ≠ "sig_v1" in value — they sign DIFFERENT preimages.
//   Restrictive policies: JSON carries ONLY "sig_v1"; "sig" is OMITTED.
//     Old agents that can only read "sig" fail (missing field) → FAIL CLOSED ✓
//     New agents read "sig_v1" and verify including new enforcement bytes → PASS.
//
// WHY "sig" must be a v0 (6-field) sig, NOT a copy of "sig_v1":
//   Deployed agents (735d5a28) compute only the first 6 fields (ending at expires_at_ms) as
//   their preimage. They verify "sig" against that v0 preimage. Putting a v1-preimage sig in
//   "sig" fails verification on every real deployed agent after a CP upgrade. R72 made this
//   mistake and is corrected here (R74).
//
// TestSessionPolicyDeployedBaseCompatibility proves the six-cell matrix below.
// =====================================================================================

func TestSessionPolicyDeployedBaseCompatibility(t *testing.T) {
	iss := goldenPolicyIssuer(t)
	pub := ed25519.PublicKey(iss.priv[32:])

	// Compute both preimages for this fixture.
	v0Preimage, err := sessionPolicySigningBytesV0(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("v0 signing bytes: %v", err)
	}
	v1Preimage, err := sessionPolicySigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("v1 signing bytes: %v", err)
	}
	if bytes.Equal(v0Preimage, v1Preimage) {
		t.Fatal("v0 and v1 preimages are identical — restriction bytes must differ")
	}
	t.Logf("v0 preimage: %d bytes  v1 preimage: %d bytes", len(v0Preimage), len(v1Preimage))

	// 1. NON-RESTRICTIVE POLICY: MintSessionPolicy emits BOTH "sig" (v0 sig) and "sig_v1" (v1 sig).
	//    Old agents (735d5a28) read "sig" and verify against their v0 preimage → PASS.
	//    New agents read "sig_v1" and verify against v1 preimage → PASS.
	//    The two fields carry DIFFERENT signatures.
	nonRestrictive, err := iss.MintSessionPolicy(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint non-restrictive: %v", err)
	}
	if nonRestrictive.Sig == nonRestrictive.SigCompat {
		t.Fatal("non-restrictive policy: Sig == SigCompat — they MUST carry different sigs " +
			"(v1 vs v0 preimage respectively)")
	}
	// "sig" (SigCompat) is signed with the v0 preimage — old agents verify it that way.
	v0SigBytes, err := hex.DecodeString(nonRestrictive.SigCompat)
	if err != nil {
		t.Fatalf("decode sigcompat: %v", err)
	}
	if !ed25519.Verify(pub, v0Preimage, v0SigBytes) {
		t.Fatal("COMPAT REGRESSION: non-restrictive \"sig\" does not verify against v0 preimage — " +
			"deployed agents (735d5a28) will reject new-CP policies")
	}
	// "sig" must NOT verify against the v1 preimage (confirming it is a v0 sig, not a copy of sig_v1).
	if ed25519.Verify(pub, v1Preimage, v0SigBytes) {
		t.Fatal("\"sig\" (SigCompat) verifies against v1 preimage — it should only verify against v0")
	}
	// "sig_v1" (Sig) is signed with the v1 preimage — new agents verify it that way.
	v1SigBytes, err := hex.DecodeString(nonRestrictive.Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(pub, v1Preimage, v1SigBytes) {
		t.Fatal("non-restrictive \"sig_v1\" does not verify against v1 preimage")
	}
	// Wire JSON: both "sig" and "sig_v1" present.
	nonRestrictiveJSON, err := nonRestrictive.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if !strings.Contains(nonRestrictiveJSON, `"sig":`) {
		t.Fatalf("non-restrictive JSON must contain \"sig\" for old-agent compat, got: %s", nonRestrictiveJSON)
	}
	if !strings.Contains(nonRestrictiveJSON, `"sig_v1":`) {
		t.Fatalf("non-restrictive JSON must contain \"sig_v1\", got: %s", nonRestrictiveJSON)
	}
	t.Logf("non-restrictive wire: %s", nonRestrictiveJSON)

	// 2. RESTRICTIVE POLICY (allow_recording=false): "sig" ABSENT, only "sig_v1" present.
	//    Old agents that only read "sig" find the field missing → fail closed.
	//    New agents read "sig_v1" and verify the v1 preimage including the ban byte.
	restrictive, err := iss.MintSessionPolicy(
		goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessViewOnly, false, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("mint restrictive: %v", err)
	}
	if restrictive.SigCompat != "" {
		t.Fatalf("restrictive policy must have empty SigCompat, got %q", restrictive.SigCompat)
	}
	restrictiveJSON, err := restrictive.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if strings.Contains(restrictiveJSON, `"sig":`) {
		t.Fatalf("restrictive policy JSON must NOT contain \"sig\", got: %s", restrictiveJSON)
	}
	if !strings.Contains(restrictiveJSON, `"sig_v1":`) {
		t.Fatalf("restrictive policy JSON must contain \"sig_v1\", got: %s", restrictiveJSON)
	}
	t.Logf("restrictive (banned) wire: %s", restrictiveJSON)

	// 3. DOWNGRADE ATTACK (RESTRICTIVE): attacker strips "sig_v1" from restrictive JSON.
	//    Result has no sig fields at all → both old and new agents fail → fail closed.
	strippedRestrictiveJSON := strings.Replace(restrictiveJSON,
		`,"sig_v1":"`+restrictive.Sig+`"`, "", 1)
	if strings.Contains(strippedRestrictiveJSON, `"sig`) {
		t.Fatalf("stripping sig_v1 should leave no sig fields, got: %s", strippedRestrictiveJSON)
	}

	// 4. DOWNGRADE ATTACK (NON-RESTRICTIVE): attacker strips "sig_v1", leaves "sig" (v0 sig).
	//    Old agents read "sig" = v0 sig → verify v0 preimage → PASS.
	//    Policy has no new restrictions, so accepting it is correct — attacker gains nothing.
	strippedNonRestrictiveJSON := strings.Replace(nonRestrictiveJSON,
		`,"sig_v1":"`+nonRestrictive.Sig+`"`, "", 1)
	if strings.Contains(strippedNonRestrictiveJSON, `"sig_v1"`) {
		t.Fatalf("stripping sig_v1 should remove it, got: %s", strippedNonRestrictiveJSON)
	}
	if !strings.Contains(strippedNonRestrictiveJSON, `"sig":`) {
		t.Fatalf("stripped non-restrictive JSON must still contain \"sig\", got: %s", strippedNonRestrictiveJSON)
	}

	// ─── COMPATIBILITY MATRIX (R74 fix — corrects R72) ─────────────────────────────────────────────
	//
	//   Old CP (735d5a28, "sig"=v0 sig only)         + Old Agent (reads "sig", verifies v0) → PASS
	//   Old CP (735d5a28, "sig"=v0 sig only)         + New Agent (fallback "sig", v0 verifier) → PASS
	//   New CP (non-restrict: "sig"=v0, "sig_v1"=v1) + Old Agent (reads "sig", verifies v0) → PASS
	//   New CP (non-restrict: "sig"=v0, "sig_v1"=v1) + New Agent (reads "sig_v1", verifies v1) → PASS
	//   New CP (restrict: "sig_v1"=v1 only)           + New Agent (reads "sig_v1", verifies v1) → PASS
	//   New CP (restrict: "sig_v1"=v1 only)           + Old Agent (no "sig" → fail) → FAIL CLOSED ✓
	//
	// ─────────────────────────────────────────────────────────────────────────────────────────────────
}

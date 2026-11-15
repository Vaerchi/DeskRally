package controlplane

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// =====================================================================================
// GOLDEN CROSS-LANGUAGE VECTOR (elevation v1).
//
// The SAME fixed fixture is hardcoded in Rust's agent/src/elevation.rs
// (`elevation::tests::golden_vector_v1`). If either language's canonical encoder or Ed25519 signing
// ever drifts, one side stops matching these constants. DO NOT change a value here without changing
// it identically in the Rust test.
//
// The seed is deliberately the SAME one the backstage-grant and session-policy vectors use, so all
// three share an issuer key. That makes the domain tag the ONLY thing separating their signatures —
// which is exactly the property TestElevationAndSessionPolicyPreimagesAreDomainSeparated relies on,
// and the property that matters most for THIS artifact, since it is the one that grants privilege.
//
// The window is 2 minutes (elevationGrantTTL), not the policy's 15, so the fixture also documents
// the TTL difference.
// =====================================================================================

const (
	goldenElevationID          = "44444444-4444-4444-4444-444444444444"
	goldenElevationExpiresAtMs = int64(1730000120000) // goldenIssuedAtMs + 2 minutes

	goldenElevationPreimageHex = "524d54454c45567631000000111111111111111111111111111111112222222222222222222222222222222233333333333333333333333333333333444444444444444444444444444444440000000f6c696e6b65645f656c65766174656400000192cc09140000000192cc0ae8c0"
	goldenElevationSigHex      = "2553ca0a7026e5d3609f2827b4a862163dafe4cd98e9b25f68bb93825e5e242c1ef5227902e712e372852f6de58c7db628024369bf3444f32832c6c42a91930a"

	// The SAME fixture at token=base — the kind that authorizes NOTHING. Its own vector, because
	// the token kind is the whole point of the artifact: a minter that dropped it from the signed
	// bytes would produce identical preimages for both, and a `base` grant's signature could then be
	// re-read as `linked_elevated` by editing one JSON field.
	goldenElevationBasePreimageHex = "524d54454c4556763100000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333344444444444444444444444444444444000000046261736500000192cc09140000000192cc0ae8c0"

	// The EXACT wire string `agent/src/elevation.rs`'s `verifies_go_minted_elevation` decodes,
	// character for character.
	//
	// The two golden hexes above pin the SIGNING PREIMAGE, which is built from raw field VALUES
	// (see elevationSigningBytes) and never touches a single JSON tag. So renaming any `json:"…"`
	// tag in elevation_mint.go left every Go test green while every agent in the field would stop
	// decoding grants — the drift is invisible on this side and arrives as "the technician's
	// elevated command is refused", which reads like a permissions problem on the guest.
	//
	// Pinning the wire string here is what makes that rename fail in Go. It is the Go→Rust half of
	// the contract; the Rust half is the same constant in `verifies_go_minted_elevation`. If this
	// assertion ever fires, the two constants must be reconciled DELIBERATELY — regenerating this
	// one from the new output is exactly the mistake it exists to catch.
	goldenElevationWireJSON = `{"claims":{"elevation":{"technician_id":"11111111-1111-1111-1111-111111111111","session_id":"22222222-2222-2222-2222-222222222222","machine_id":"33333333-3333-3333-3333-333333333333","elevation_id":"44444444-4444-4444-4444-444444444444","token":"linked_elevated"},"issued_at_ms":1730000000000,"expires_at_ms":1730000120000},"sig":"2553ca0a7026e5d3609f2827b4a862163dafe4cd98e9b25f68bb93825e5e242c1ef5227902e712e372852f6de58c7db628024369bf3444f32832c6c42a91930a"}`
)

func goldenElevationIssuer(t *testing.T) *GrantIssuer {
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
// the agent — which computes the preimage itself — would start rejecting every elevation grant.
// That failure is not loud: the technician's elevated command is simply refused, which reads like a
// permissions problem on the guest rather than like a control-plane drift.
func TestElevationGoldenVectorV1(t *testing.T) {
	iss := goldenElevationIssuer(t)

	if got := iss.PublicKeyHex(); got != goldenPubkeyHex {
		t.Fatalf("pubkey drift:\n got  %s\n want %s", got, goldenPubkeyHex)
	}

	msg, err := elevationSigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID, goldenElevationID,
		ElevationTokenLinkedElevated, goldenIssuedAtMs, goldenElevationExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenElevationPreimageHex {
		t.Fatalf("canonical preimage drift (Rust will reject every elevation grant):\n got  %s\n want %s",
			got, goldenElevationPreimageHex)
	}

	signed, err := iss.MintElevation(
		goldenTechnicianID, goldenSessionID, goldenMachineID, goldenElevationID,
		ElevationTokenLinkedElevated, goldenIssuedAtMs, goldenElevationExpiresAtMs)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if signed.Sig != goldenElevationSigHex {
		t.Fatalf("signature drift:\n got  %s\n want %s", signed.Sig, goldenElevationSigHex)
	}
	if signed.Token() != ElevationTokenLinkedElevated {
		t.Fatalf("Token() = %q, want linked_elevated", signed.Token())
	}
	if signed.ElevationID() != goldenElevationID {
		t.Fatalf("ElevationID() = %q, want %q", signed.ElevationID(), goldenElevationID)
	}

	// THE WIRE, not just the preimage. Everything above is computed from field VALUES, so a JSON
	// struct-tag rename cannot fail any of it — and the agent decodes the JSON, not the preimage.
	js, err := signed.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	// Still logged, so regenerating the pair after a DELIBERATE wire change stays a copy-paste
	// (go test -run TestElevationGoldenVectorV1 -v).
	t.Logf("GO_MINTED_ELEVATION_JSON = %s", js)
	if js != goldenElevationWireJSON {
		t.Fatalf("elevation WIRE drift — every deployed agent would stop decoding grants "+
			"(agent/src/elevation.rs verifies_go_minted_elevation holds the other half):\n got  %s\n want %s",
			js, goldenElevationWireJSON)
	}
}

// The `base` half of the vector. Same fixture, same key, same window — only the token kind differs —
// so this pins that the kind is INSIDE the signed bytes. Without it, the whole artifact reduces to
// "the control plane said something about this session", with the one field that says WHAT it
// authorized left unprotected.
func TestElevationGoldenVectorV1BaseToken(t *testing.T) {
	msg, err := elevationSigningBytes(
		goldenTechnicianID, goldenSessionID, goldenMachineID, goldenElevationID,
		ElevationTokenBase, goldenIssuedAtMs, goldenElevationExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenElevationBasePreimageHex {
		t.Fatalf("canonical preimage drift for token=base:\n got  %s\n want %s",
			got, goldenElevationBasePreimageHex)
	}
	if got := hex.EncodeToString(msg); got == goldenElevationPreimageHex {
		t.Fatal("the base and linked_elevated preimages are IDENTICAL — the token kind is not " +
			"covered by the signature, so a grant that authorizes nothing could be re-read as one " +
			"that hands over the guest's admin token")
	}
}

// The single-use id must be inside the signed bytes too. Without it one signature would cover every
// elevation_id, and a captured grant could be re-keyed to dodge the agent's single-use ledger — the
// exact replay the ledger exists to stop.
func TestElevationIDIsCoveredByTheSignature(t *testing.T) {
	a, err := elevationSigningBytes(goldenTechnicianID, goldenSessionID, goldenMachineID,
		goldenElevationID, ElevationTokenLinkedElevated, goldenIssuedAtMs, goldenElevationExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes a: %v", err)
	}
	b, err := elevationSigningBytes(goldenTechnicianID, goldenSessionID, goldenMachineID,
		"55555555-5555-5555-5555-555555555555", ElevationTokenLinkedElevated,
		goldenIssuedAtMs, goldenElevationExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two different elevation_ids produced the SAME preimage — the single-use id is not " +
			"signed, so a captured grant can be re-keyed past the agent's ledger")
	}
}

// An unknown token kind must be refused AT THE MINT, not signed and shipped. A signed-but-unknown
// kind fails to decode in Rust (serde rejects an unknown variant), so the technician would see an
// unexplained refusal on the guest instead of a loud error here.
func TestMintElevationRejectsAnUnknownTokenKind(t *testing.T) {
	iss := goldenElevationIssuer(t)
	for _, bad := range []ElevationTokenKind{"", "system", "SYSTEM", "linked-elevated", "credential"} {
		if bad.Valid() {
			t.Fatalf("%q must not be Valid()", string(bad))
		}
		signed, err := iss.MintElevation(goldenTechnicianID, goldenSessionID, goldenMachineID,
			goldenElevationID, bad, goldenIssuedAtMs, goldenElevationExpiresAtMs)
		if err == nil {
			t.Fatalf("minted an elevation grant with token kind %q", string(bad))
		}
		if signed.Sig != "" {
			t.Fatalf("a refused mint returned a signature: %q", signed.Sig)
		}
		if !strings.Contains(err.Error(), "unknown kind") {
			t.Fatalf("unhelpful error for %q: %v", string(bad), err)
		}
	}
	// …and both real kinds ARE valid, so the check above is not simply refusing everything.
	if !ElevationTokenBase.Valid() || !ElevationTokenLinkedElevated.Valid() {
		t.Fatal("a real token kind was refused by Valid()")
	}
}

// A malformed UUID must fail the mint rather than silently produce zero bytes. Every id here is a
// binding the agent checks, so a zeroed one would bind the grant to the nil uuid — which is a real
// value that a synthetic/dev machine can hold.
func TestMintElevationRejectsAMalformedUUID(t *testing.T) {
	iss := goldenElevationIssuer(t)
	cases := []struct{ name, tech, sess, mach, elev string }{
		{"technician", "not-a-uuid", goldenSessionID, goldenMachineID, goldenElevationID},
		{"session", goldenTechnicianID, "dev-1", goldenMachineID, goldenElevationID},
		{"machine", goldenTechnicianID, goldenSessionID, "", goldenElevationID},
		{"elevation", goldenTechnicianID, goldenSessionID, goldenMachineID, "44444444"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := iss.MintElevation(c.tech, c.sess, c.mach, c.elev,
				ElevationTokenLinkedElevated, goldenIssuedAtMs, goldenElevationExpiresAtMs); err == nil {
				t.Fatalf("minted with a malformed %s id", c.name)
			} else if !strings.Contains(err.Error(), c.name+"_id") {
				t.Fatalf("the error does not name the bad field: %v", err)
			}
		})
	}
}

// EVERY domain-separation tag in this deployment, pairwise distinct.
//
// Loop 87 widened this from three tags to five. The previous version covered grant/audit/session
// policy only, while `ticketDomainTag` and `mgmtAuditDomainTag` were pinned (partially) by a
// different test in a different file — so no single test ever asserted the whole set, and a new tag
// could collide with either of the two nobody was watching. All are 12 bytes, and for the six
// signed by the same Ed25519 identity this is the only thing keeping their preimage spaces disjoint.
//
// `update` (loop 98) is the seventh and the one exception to that sentence: an update manifest is
// signed by a key that never touches the control plane (update_manifest.go's header says why), so a
// collision involving it is not immediately exploitable — it becomes exploitable the moment anyone
// unifies the keys, which is exactly the mistake this table is cheap insurance against. Included
// for that reason, not because it shares an issuer.
func TestDomainTagsArePairwiseDistinct(t *testing.T) {
	tags := map[string][]byte{
		"grant":          grantDomainTag,
		"audit":          auditDomainTag,
		"session policy": sessionPolicyDomainTag,
		"elevation":      elevationDomainTag,
		"ticket":         ticketDomainTag,
		"mgmt audit":     mgmtAuditDomainTag,
		"update":         updateDomainTag,
		"update v2":      updateDomainTagV2,
	}
	for aName, a := range tags {
		if len(a) != 12 {
			t.Errorf("%s tag is %d bytes, want 12", aName, len(a))
		}
		for bName, b := range tags {
			if aName >= bName {
				continue
			}
			if bytes.Equal(a, b) {
				t.Errorf("%s and %s share a domain tag %q — preimages could collide", aName, bName, a)
			}
		}
	}
}

// An elevation preimage and a session-policy preimage built from the SAME (technician, session,
// machine) and the SAME window must diverge at byte 0. This is the concrete version of the
// pairwise-distinctness test: it is not enough that the tags differ as constants, the ENCODERS have
// to actually put them at the front. A session policy is minted for practically every enforcing
// session; if its signature could be replayed as an elevation, the most common artifact in the
// system would be an escalation primitive.
func TestElevationAndSessionPolicyPreimagesAreDomainSeparated(t *testing.T) {
	elev, err := elevationSigningBytes(goldenTechnicianID, goldenSessionID, goldenMachineID,
		goldenElevationID, ElevationTokenLinkedElevated, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("elevation signing bytes: %v", err)
	}
	pol, err := sessionPolicySigningBytes(goldenTechnicianID, goldenSessionID, goldenMachineID,
		SessionAccessControl, true, false, 0, 0, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("policy signing bytes: %v", err)
	}
	if bytes.Equal(elev[:12], pol[:12]) {
		t.Fatalf("the two preimages open with the SAME 12 bytes %q — one signature is usable as the other",
			elev[:12])
	}
	if !bytes.HasPrefix(elev, elevationDomainTag) {
		t.Fatalf("the elevation preimage does not open with the elevation tag: %x", elev[:12])
	}
}

// The TTL is a security parameter, so it gets an assertion rather than only a comment: it must be
// tighter than the two GRANT-shaped artifacts. An elevation grant is minted on an already-open
// Control channel and used in the same tick; widening it to the session policy's 15 minutes would
// hand a captured grant a useful lifetime without anything in the tree noticing.
//
// It is no longer the tightest artifact in the system, and the name is kept only so the test's
// history stays greppable: docs/25 F03 made sessionPolicyLeaseTTL (30 s) tighter still. That is not
// a contradiction — the lease is short because its length IS the revocation window for an unattended
// session, whereas an elevation grant is short because it hands over privilege. Different reasons,
// and the lease is deliberately NOT asserted against this constant: they are free to cross.
func TestElevationGrantTTLIsTheTightestOfTheThree(t *testing.T) {
	if elevationGrantTTL >= backstageGrantTTL {
		t.Errorf("elevationGrantTTL %v is not tighter than backstageGrantTTL %v",
			elevationGrantTTL, backstageGrantTTL)
	}
	if elevationGrantTTL >= sessionPolicyTTL {
		t.Errorf("elevationGrantTTL %v is not tighter than sessionPolicyTTL %v",
			elevationGrantTTL, sessionPolicyTTL)
	}
	if elevationGrantTTL <= 0 {
		t.Errorf("elevationGrantTTL %v must be positive", elevationGrantTTL)
	}
}

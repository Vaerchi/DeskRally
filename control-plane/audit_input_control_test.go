package controlplane

// Cross-language golden vectors for the docs/61 input_control_handed audit kind. Without the Go arm
// in encodeAuditAction, ingest turns the event into a ContentTamperError and the session's whole
// trail wedges (see audit_recording_test.go for why that is permanent). These vectors pin the arm
// byte-for-byte against Rust.
//
// The Rust twin is agent/src/backstage/audit.rs :: audit_golden_input_control_vector_v1. DO NOT
// change a constant here without changing it identically there.

import (
	"encoding/json"
	"testing"
)

const (
	goldenH1PreimageHex = "524d54415544495476310000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc09140000000014696e7075745f636f6e74726f6c5f68616e646564444444444444444444444444444444442222222222222222222222222222222255555555555555555555555555555555666666666666666666666666666666660000000000000003000000026f6b00000000"
	goldenH1Hash        = "4e25a93e06cbe1993f6e4e9647f6e26f1d8c58bd8d1bef484b554f8c6b539f09"
	goldenH2PreimageHex = "524d54415544495476310000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000000000000111111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc09893000000014696e7075745f636f6e74726f6c5f68616e646564555555555555555555555555555555556666666666666666666666666666666655555555555555555555555555555555666666666666666666666666666666660000000000000005000000026f6b0000004034653235613933653036636265313939336636653465393634376636653236663164386335386264386431626566343834623535346638633662353339663039"
	goldenH3PreimageHex = "524d544155444954763100000f1e2d3c4b5a69788796a5b4c3d2e1f0000000000000000211111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0a739000000014696e7075745f636f6e74726f6c5f68616e646564000000000000000000000000000000000000000000000000000000000000000000112233445566778899aabbccddeefff0e1d2c3b4a5968778695a4b3c2d1e0f0102030405060708000000026f6b0000004064313764396662363732353132613361303736366631303337666332323562653761396231393238623164326563323533343536333166633937613130613233"
	goldenH3Hash        = "578425e7d59255e7cafd81f8857d3e6696a7d26326792558f1d3ffa9e77c8b32"
	goldenH2Hash        = "d17d9fb672512a3a0766f1037fc225be7a9b1928b1d2ec25345631fc97a10a23"
)

func TestAuditGoldenInputControlV1(t *testing.T) {
	// H1 - a hand between four DISTINCT ids, so a mirror that swapped two fields cannot pass.
	h1 := goldenAuditEvent(
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 0, 1730000000000,
		json.RawMessage(`{"kind":"input_control_handed",`+
			`"from_session":"44444444-4444-4444-4444-444444444444",`+
			`"from_technician":"22222222-2222-2222-2222-222222222222",`+
			`"to_session":"55555555-5555-5555-5555-555555555555",`+
			`"to_technician":"66666666-6666-6666-6666-666666666666","epoch":3}`),
		json.RawMessage(`{"result":"ok"}`), "")
	assertGolden(t, "H1", h1, goldenH1PreimageHex, goldenH1Hash)

	// H2 - a claim after the owner left (from == to), chained onto H1.
	h2 := goldenAuditEvent(
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", 1, 1730000030000,
		json.RawMessage(`{"kind":"input_control_handed",`+
			`"from_session":"55555555-5555-5555-5555-555555555555",`+
			`"from_technician":"66666666-6666-6666-6666-666666666666",`+
			`"to_session":"55555555-5555-5555-5555-555555555555",`+
			`"to_technician":"66666666-6666-6666-6666-666666666666","epoch":5}`),
		json.RawMessage(`{"result":"ok"}`), goldenH1Hash)
	assertGolden(t, "H2", h2, goldenH2PreimageHex, goldenH2Hash)

	// H3 - the handing session already LEFT (nil from-ids); non-uniform uuid bytes and epoch
	// 0x0102030405060708 (= 72623859790382856), so a byte-order slip in either language cannot pass.
	h3 := goldenAuditEvent(
		"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", 2, 1730000090000,
		json.RawMessage(`{"kind":"input_control_handed",`+
			`"from_session":"00000000-0000-0000-0000-000000000000",`+
			`"from_technician":"00000000-0000-0000-0000-000000000000",`+
			`"to_session":"00112233-4455-6677-8899-aabbccddeeff",`+
			`"to_technician":"f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f","epoch":72623859790382856}`),
		json.RawMessage(`{"result":"ok"}`), goldenH2Hash)
	assertGolden(t, "H3", h3, goldenH3PreimageHex, goldenH3Hash)
}

// An input_control_handed whose epoch is ABSENT is refused, not hashed as epoch 0: a stripped field
// must not be able to make a different statement than the agent sealed.
func TestAuditInputControlMissingEpochIsRefused(t *testing.T) {
	w := &canonicalWriter{}
	err := encodeAuditAction(w, json.RawMessage(`{"kind":"input_control_handed",`+
		`"from_session":"44444444-4444-4444-4444-444444444444",`+
		`"from_technician":"22222222-2222-2222-2222-222222222222",`+
		`"to_session":"55555555-5555-5555-5555-555555555555",`+
		`"to_technician":"66666666-6666-6666-6666-666666666666"}`))
	if err == nil {
		t.Fatal("an input_control_handed with no epoch was canonicalized")
	}
}

package controlplane

// Cross-language golden vectors for the docs/58 file-management audit kinds (file_create_dir,
// file_rename, file_place). A Rust kind with no Go arm wedges a session's whole audit trail at
// ingest (see audit_recording_test.go), so these are pinned in BOTH languages.
//
// The Rust twin is agent/src/backstage/audit.rs :: audit_golden_file_manage_vector_v1. DO NOT change
// a constant here without changing it identically there.

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	goldenF1PreimageHex = "524d5441554449547631000055555555555555555555555555555555000000000000000011111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0914000000000f66696c655f6372656174655f64697200000007443a5c776f726b000000026f6b00000000"
	goldenF1Hash        = "d502005b67b320a1577b8e12d91b625677a27f2f12fb145f47ab6bb0b32f7271"
	goldenF2PreimageHex = "524d5441554449547631000066666666666666666666666666666666000000000000000111111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc0917e80000000b66696c655f72656e616d6500000007443a5c776f726b00000008443a5c776f726b32000000026f6b0000004064353032303035623637623332306131353737623865313264393162363235363737613237663266313266623134356634376162366262306233326637323731"
	goldenF2Hash        = "e08bd021adb3d34950fe9aed77a0b92db1ec9e986aee05cd1ec6da3986c28b1e"
	goldenF3PreimageHex = "524d5441554449547631000099999999999999999999999999999999000000000000000211111111111111111111111111111111222222222222222222222222222222223333333333333333333333333333333300000192cc091bd00000000a66696c655f706c616365aaaaaaaabbbbccccddddeeeeeeeeeeee000000406364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636463646364636400000011443a5c776f726b325c746f6f6c2e6578650000000664656e6965640000000d73657373696f6e20656e6465640000004065303862643032316164623364333439353066653961656437376130623932646231656339653938366165653035636431656336646133393836633238623165"
	goldenF3Hash        = "1d528b5fda2e5961ac6e8a5d56d9441980d6c37bd43aa1fb2f4453d77d43f0c9"
)

func TestAuditGoldenFileManageV1(t *testing.T) {
	bs := string(rune(92))
	js := func(s string) string {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	dir, renamed, placed := "D:"+bs+"work", "D:"+bs+"work2", "D:"+bs+"work2"+bs+"tool.exe"

	// F1 - file_create_dir, genesis.
	f1 := goldenAuditEvent("55555555-5555-5555-5555-555555555555", 0, 1730000000000,
		json.RawMessage(`{"kind":"file_create_dir","path":`+js(dir)+`}`),
		json.RawMessage(`{"result":"ok"}`), "")
	assertGolden(t, "F1", f1, goldenF1PreimageHex, goldenF1Hash)

	// F2 - file_rename, chained: two length-prefixed strings in from/to order.
	f2 := goldenAuditEvent("66666666-6666-6666-6666-666666666666", 1, 1730000001000,
		json.RawMessage(`{"kind":"file_rename","from":`+js(dir)+`,"to":`+js(renamed)+`}`),
		json.RawMessage(`{"result":"ok"}`), goldenF1Hash)
	assertGolden(t, "F2", f2, goldenF2PreimageHex, goldenF2Hash)

	// F3 - file_place with a DENIED outcome: the raw 16-byte transfer id, the digest, the target,
	// and the outcome's reason string all reach the preimage.
	f3 := goldenAuditEvent("99999999-9999-9999-9999-999999999999", 2, 1730000002000,
		json.RawMessage(`{"kind":"file_place","transfer_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","sha256":"`+
			strings.Repeat("cd", 32)+`","to":`+js(placed)+`}`),
		json.RawMessage(`{"result":"denied","reason":"session ended"}`), goldenF2Hash)
	assertGolden(t, "F3", f3, goldenF3PreimageHex, goldenF3Hash)
}

// A file_place whose transfer_id is not a uuid is refused, not hashed: the Rust side can only ever
// emit a real uuid, so anything else reaching ingest is not an agent's record.
func TestFilePlaceRefusesANonUUIDTransferID(t *testing.T) {
	e := goldenAuditEvent("99999999-9999-9999-9999-999999999999", 0, 1730000002000,
		json.RawMessage(`{"kind":"file_place","transfer_id":"not-a-uuid","sha256":"","to":""}`),
		json.RawMessage(`{"result":"ok"}`), "")
	if _, err := auditPreimage(e); err == nil {
		t.Fatal("a non-uuid transfer_id must be refused")
	}
}

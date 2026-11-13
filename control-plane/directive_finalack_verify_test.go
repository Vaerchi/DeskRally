package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// Every pre-authentication path through finalAckVerify does exactly ONE ed25519 verification (Codex §2b r2:
// a wrong signature on a known directive used to cost a real verify PLUS a dummy one, an unknown id only the
// dummy, so timing separated them). Only a valid signature by the stored key is accepted.
func TestFinalAckVerifyDoesOneVerificationOnEveryPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubHex := hex.EncodeToString(pub)
	const tenant, device, dirID = "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-8999-aaaaaaaaaaaa", "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	fp := fingerprintOf(pubHex)
	good, err := SignDirectiveAck(priv, tenant, device, dirID, fp, "executing", "complete", 1800000000000, "ok")
	if err != nil {
		t.Fatal(err)
	}
	tgt := func(keyHex, keyFP string) *DirectiveFinalAckTarget {
		return &DirectiveFinalAckTarget{TenantID: tenant, DeviceID: device, KeyFP: keyFP, MachinePubkey: keyHex}
	}
	wrongSig := good
	wrongSig.Sig = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	badHex := good
	badHex.Sig = "zz"
	cases := []struct {
		name string
		tgt  *DirectiveFinalAckTarget
		ack  DirectiveAck
		want bool
	}{
		{"valid", tgt(pubHex, fp), good, true},
		{"unknown id", nil, good, false},
		{"wrong signature", tgt(pubHex, fp), wrongSig, false},
		{"undecodable signature", tgt(pubHex, fp), badHex, false},
		{"key no longer matches fingerprint", tgt(hex.EncodeToString(otherPub), fp), good, false},
		{"undecodable stored key", tgt("not-hex", fp), good, false},
	}
	real := finalAckEd25519Verify
	t.Cleanup(func() { finalAckEd25519Verify = real })
	for _, c := range cases {
		calls := 0
		finalAckEd25519Verify = func(k ed25519.PublicKey, m, s []byte) bool { calls++; return real(k, m, s) }
		if got := finalAckVerify(c.tgt, dirID, c.ack); got != c.want {
			t.Errorf("%s: accepted = %v, want %v", c.name, got, c.want)
		}
		if calls != 1 {
			t.Errorf("%s: %d ed25519 verifications, want exactly 1 (timing must not separate the paths)", c.name, calls)
		}
	}
}

package controlplane

// Golden vectors for RMTDIRECTIVEv1 and RMTDIRACKv1 (docs/65 D-C3 / D-C8): ONE JSON fixture, positive AND
// negative, that the future Rust verifier loads (crates/protocol/testdata/directive-vectors.json). The Go
// reference verifier in directive_sign.go must produce exactly the recorded outcome for every vector, and the
// fixture on disk must equal what the generator produces (so it cannot drift from the implementation).
//
// Regenerate with:  UPDATE_DIRECTIVE_VECTORS=1 go test -run TestDirectiveGoldenVectors .

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const directiveVectorsPath = "../crates/protocol/testdata/directive-vectors.json"

type vectorExpectation struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id"`
	KeyFP    string `json:"key_fp"`
	NowMs    int64  `json:"now_ms"`
}

type directiveVector struct {
	Name         string            `json:"name"`
	Artifact     string            `json:"artifact"`
	PinnedKeyHex string            `json:"pinned_public_key_hex"` // "" = the agent has NO pinned directive key
	Expectation  vectorExpectation `json:"expectation"`
	Expect       string            `json:"expect"` // "ok" or the refusal code
	PreimageHex  string            `json:"preimage_hex,omitempty"`
}

type ackVector struct {
	Name            string       `json:"name"`
	TenantID        string       `json:"tenant_id"`
	DeviceID        string       `json:"device_id"`
	DirectiveID     string       `json:"directive_id"`
	KeyFP           string       `json:"key_fp"`
	DevicePublicKey string       `json:"device_public_key_hex"`
	Ack             DirectiveAck `json:"ack"`
	Expect          string       `json:"expect"` // "ok" | "bad_signature"
	PreimageHex     string       `json:"preimage_hex,omitempty"`
}

type directiveVectorFile struct {
	Comment        string            `json:"comment"`
	DirectiveKey   map[string]string `json:"directive_key"`
	DeviceKey      map[string]string `json:"device_key"`
	DirectiveTests []directiveVector `json:"directive_vectors"`
	AckTests       []ackVector       `json:"ack_vectors"`
}

func seedBytes(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func buildDirectiveVectors(t *testing.T) []byte {
	t.Helper()
	dirKey := ed25519.NewKeyFromSeed(seedBytes(0x11))
	devKey := ed25519.NewKeyFromSeed(seedBytes(0x22))
	otherKey := ed25519.NewKeyFromSeed(seedBytes(0x33))
	iss, err := NewDirectiveIssuer(seedBytes(0x11))
	if err != nil {
		t.Fatal(err)
	}
	devPub := hex.EncodeToString(devKey.Public().(ed25519.PublicKey))
	fp, _ := KeyFingerprint(devPub)
	dirPub := iss.PublicKeyHex()

	const (
		tenant = "11111111-2222-4333-8444-555555555555"
		device = "66666666-7777-4888-8999-aaaaaaaaaaaa"
		dirID  = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
		nonce  = "000102030405060708090a0b0c0d0e0f"
		issued = int64(1_800_000_000_000)
	)
	base := DirectiveClaims{TenantID: tenant, DeviceID: device, DirectiveID: dirID, Kind: "uninstall",
		KeyFP: fp, Nonce: nonce, IssuedAtMs: issued, ExpiresAtMs: issued + 3_600_000}
	exp := vectorExpectation{DeviceID: device, TenantID: tenant, KeyFP: fp, NowMs: issued + 1_000}
	sign := func(c DirectiveClaims) string {
		s, err := iss.Sign(c)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	preimage := func(c DirectiveClaims) string {
		b, err := directiveSigningBytes(c)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b)
	}
	flipSig := func(artifact string) string {
		var sd SignedDirective
		_ = json.Unmarshal([]byte(artifact), &sd)
		b := []byte(sd.Sig)
		if b[0] == '0' {
			b[0] = '1'
		} else {
			b[0] = '0'
		}
		sd.Sig = string(b)
		out, _ := json.Marshal(sd)
		return string(out)
	}
	with := func(f func(*DirectiveClaims)) DirectiveClaims { c := base; f(&c); return c }
	expWith := func(f func(*vectorExpectation)) vectorExpectation { e := exp; f(&e); return e }

	reinstall := with(func(c *DirectiveClaims) { c.Kind = "reinstall"; c.ExpiresAtMs = issued + 86_400_000 })
	tampered := sign(base)
	tampered = strings.Replace(tampered, `"kind":"uninstall"`, `"kind":"reinstall"`, 1)

	vs := []directiveVector{
		{Name: "valid uninstall", Artifact: sign(base), PinnedKeyHex: dirPub, Expectation: exp, Expect: "ok", PreimageHex: preimage(base)},
		{Name: "valid reinstall (24h)", Artifact: sign(reinstall), PinnedKeyHex: dirPub, Expectation: exp, Expect: "ok", PreimageHex: preimage(reinstall)},
		{Name: "no pinned directive key refuses everything", Artifact: sign(base), PinnedKeyHex: "", Expectation: exp, Expect: DirectiveRefusedNoKey},
		{Name: "not JSON", Artifact: "not json", PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedMalformed},
		{Name: "unknown claim field", Artifact: strings.Replace(sign(base), `"claims":{`, `"claims":{"extra":1,`, 1), PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedMalformed},
		{Name: "signature of the wrong length", Artifact: strings.Replace(sign(base), `"sig":"`, `"sig":"00`, 1), PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedMalformed},
		{Name: "unknown kind", Artifact: strings.Replace(sign(base), `"kind":"uninstall"`, `"kind":"format"`, 1), PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedKind},
		{Name: "one signature bit flipped", Artifact: flipSig(sign(base)), PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedSignature},
		{Name: "claim edited after signing (kind)", Artifact: tampered, PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedSignature},
		{Name: "signed by a different key (the grant issuer, say)", Artifact: func() string {
			other, _ := NewDirectiveIssuer(seedBytes(0x33))
			s, _ := other.Sign(base)
			return s
		}(), PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedSignature},
		{Name: "wrong device", Artifact: sign(base), PinnedKeyHex: dirPub, Expectation: expWith(func(e *vectorExpectation) { e.DeviceID = "77777777-7777-4777-8777-777777777777" }), Expect: DirectiveRefusedDevice},
		{Name: "wrong tenant", Artifact: sign(base), PinnedKeyHex: dirPub, Expectation: expWith(func(e *vectorExpectation) { e.TenantID = "99999999-9999-4999-8999-999999999999" }), Expect: DirectiveRefusedTenant},
		{Name: "wrong enrollment generation (key fingerprint)", Artifact: sign(base), PinnedKeyHex: dirPub, Expectation: expWith(func(e *vectorExpectation) { e.KeyFP = strings.Repeat("ab", 32) }), Expect: DirectiveRefusedKeyFP},
		{Name: "expired", Artifact: sign(base), PinnedKeyHex: dirPub, Expectation: expWith(func(e *vectorExpectation) { e.NowMs = issued + 3_600_001 }), Expect: DirectiveRefusedExpired},
		{Name: "issued more than 2 minutes in the future", Artifact: sign(base), PinnedKeyHex: dirPub, Expectation: expWith(func(e *vectorExpectation) { e.NowMs = issued - 120_001 }), Expect: DirectiveRefusedNotYetValid},
		{Name: "issued within the 2 minute skew is fine", Artifact: sign(base), PinnedKeyHex: dirPub, Expectation: expWith(func(e *vectorExpectation) { e.NowMs = issued - 119_000 }), Expect: "ok"},
		{Name: "uninstall lifetime beyond the 1h maximum", Artifact: sign(with(func(c *DirectiveClaims) { c.ExpiresAtMs = issued + 3_600_001 })), PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedLifetimeTooLong},
		{Name: "reinstall lifetime beyond the 24h maximum", Artifact: sign(with(func(c *DirectiveClaims) { *c = reinstall; c.ExpiresAtMs = issued + 86_400_001 })), PinnedKeyHex: dirPub, Expectation: exp, Expect: DirectiveRefusedLifetimeTooLong},
	}
	_ = dirKey
	_ = otherKey

	ackBase := DirectiveAck{DirectiveID: dirID, From: "issued", To: "accepted", TsMs: issued + 5_000, Detail: "ok"}
	signAck := func(tenantID, deviceID, directiveID, keyFP, from, to string, ts int64, detail string) DirectiveAck {
		a, err := SignDirectiveAck(devKey, tenantID, deviceID, directiveID, keyFP, from, to, ts, detail)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	good := signAck(tenant, device, dirID, fp, "issued", "accepted", ackBase.TsMs, "ok")
	ackPre := func(tn, dv, di, f, from, to string, ts int64, detail string) string {
		b, err := directiveAckSigningBytes(tn, dv, di, f, from, to, ts, detail)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b)
	}
	mk := func(name, expect string, a DirectiveAck, tn, dv, di, f string, pre string) ackVector {
		return ackVector{Name: name, TenantID: tn, DeviceID: dv, DirectiveID: di, KeyFP: f, DevicePublicKey: devPub, Ack: a, Expect: expect, PreimageHex: pre}
	}
	tamper := func(f func(*DirectiveAck)) DirectiveAck { a := good; f(&a); return a }
	acks := []ackVector{
		mk("valid ack issued->accepted", "ok", good, tenant, device, dirID, fp, ackPre(tenant, device, dirID, fp, "issued", "accepted", ackBase.TsMs, "ok")),
		mk("transition target edited", "bad_signature", tamper(func(a *DirectiveAck) { a.To = "complete" }), tenant, device, dirID, fp, ""),
		mk("transition source edited", "bad_signature", tamper(func(a *DirectiveAck) { a.From = "accepted" }), tenant, device, dirID, fp, ""),
		mk("timestamp edited", "bad_signature", tamper(func(a *DirectiveAck) { a.TsMs++ }), tenant, device, dirID, fp, ""),
		mk("detail edited", "bad_signature", tamper(func(a *DirectiveAck) { a.Detail = "nope" }), tenant, device, dirID, fp, ""),
		mk("verified against another directive id", "bad_signature", good, tenant, device, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", fp, ""),
		mk("verified against another tenant", "bad_signature", good, "22222222-2222-4222-8222-222222222222", device, dirID, fp, ""),
		mk("verified against another device", "bad_signature", good, tenant, "88888888-8888-4888-8888-888888888888", dirID, fp, ""),
		mk("verified against another key generation", "bad_signature", good, tenant, device, dirID, strings.Repeat("cd", 32), ""),
		func() ackVector {
			v := mk("signed by a key that is not the device key", "bad_signature", good, tenant, device, dirID, fp, "")
			v.DevicePublicKey = hex.EncodeToString(otherKey.Public().(ed25519.PublicKey))
			return v
		}(),
	}

	file := directiveVectorFile{
		Comment: "RMTDIRECTIVEv1 / RMTDIRACKv1 golden vectors (docs/65). Generated by control-plane/directive_vectors_test.go; " +
			"do not edit by hand. A verifier must return exactly 'expect' for every vector, checking in the documented order " +
			"(key, envelope, kind, signature, device, tenant, key_fp, not_yet_valid, expired, lifetime_too_long).",
		DirectiveKey:   map[string]string{"seed_hex": hex.EncodeToString(seedBytes(0x11)), "public_key_hex": dirPub},
		DeviceKey:      map[string]string{"seed_hex": hex.EncodeToString(seedBytes(0x22)), "public_key_hex": devPub, "key_fp": fp},
		DirectiveTests: vs,
		AckTests:       acks,
	}
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func TestDirectiveGoldenVectors(t *testing.T) {
	want := buildDirectiveVectors(t)
	if os.Getenv("UPDATE_DIRECTIVE_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(directiveVectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(directiveVectorsPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(directiveVectorsPath)
	if err != nil {
		t.Fatalf("read fixture (regenerate with UPDATE_DIRECTIVE_VECTORS=1): %v", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")), want) {
		t.Fatal("the fixture on disk differs from what the generator produces; regenerate with UPDATE_DIRECTIVE_VECTORS=1")
	}

	// Verify every vector from the FILE, independently of the generator's variables.
	var f directiveVectorFile
	if err := json.Unmarshal(got, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.DirectiveTests) < 15 || len(f.AckTests) < 8 {
		t.Fatalf("fixture is suspiciously small: %d + %d", len(f.DirectiveTests), len(f.AckTests))
	}
	for _, v := range f.DirectiveTests {
		var pub ed25519.PublicKey
		if v.PinnedKeyHex != "" {
			raw, _ := hex.DecodeString(v.PinnedKeyHex)
			pub = ed25519.PublicKey(raw)
		}
		_, err := VerifyDirective(pub, v.Artifact, DirectiveExpectation{
			DeviceID: v.Expectation.DeviceID, TenantID: v.Expectation.TenantID, KeyFP: v.Expectation.KeyFP, NowMs: v.Expectation.NowMs})
		gotCode := "ok"
		if err != nil {
			gotCode = verifyCode(err)
		}
		if gotCode != v.Expect {
			t.Errorf("directive vector %q: got %q, want %q", v.Name, gotCode, v.Expect)
		}
	}
	for _, v := range f.AckTests {
		raw, _ := hex.DecodeString(v.DevicePublicKey)
		ok := VerifyDirectiveAck(ed25519.PublicKey(raw), v.TenantID, v.DeviceID, v.DirectiveID, v.KeyFP, v.Ack)
		gotCode := "bad_signature"
		if ok {
			gotCode = "ok"
		}
		if gotCode != v.Expect {
			t.Errorf("ack vector %q: got %q, want %q", v.Name, gotCode, v.Expect)
		}
	}
}

// TestDirectiveSignatureCoversEveryField: changing ANY single claim after signing breaks the signature (each
// field is in the preimage), so no field an agent acts on can be altered in transit.
func TestDirectiveSignatureCoversEveryField(t *testing.T) {
	iss, _ := NewDirectiveIssuer(seedBytes(0x44))
	pub, _ := hex.DecodeString(iss.PublicKeyHex())
	c := DirectiveClaims{
		TenantID: "11111111-2222-4333-8444-555555555555", DeviceID: "dev-1", DirectiveID: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
		Kind: "reinstall", KeyFP: strings.Repeat("ab", 32), Nonce: strings.Repeat("00", 16), IssuedAtMs: 1_800_000_000_000, ExpiresAtMs: 1_800_000_060_000}
	artifact, err := iss.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	exp := DirectiveExpectation{DeviceID: c.DeviceID, TenantID: c.TenantID, KeyFP: c.KeyFP, NowMs: c.IssuedAtMs + 1}
	if _, err := VerifyDirective(ed25519.PublicKey(pub), artifact, exp); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	mutations := map[string]func(*DirectiveClaims){
		"tenant_id":     func(x *DirectiveClaims) { x.TenantID = "21111111-2222-4333-8444-555555555555" },
		"device_id":     func(x *DirectiveClaims) { x.DeviceID = "dev-2" },
		"directive_id":  func(x *DirectiveClaims) { x.DirectiveID = "cbbbbbbb-cccc-4ddd-8eee-ffffffffffff" },
		"kind":          func(x *DirectiveClaims) { x.Kind = "uninstall" },
		"key_fp":        func(x *DirectiveClaims) { x.KeyFP = strings.Repeat("ac", 32) },
		"nonce":         func(x *DirectiveClaims) { x.Nonce = strings.Repeat("01", 16) },
		"issued_at_ms":  func(x *DirectiveClaims) { x.IssuedAtMs++ },
		"expires_at_ms": func(x *DirectiveClaims) { x.ExpiresAtMs++ },
	}
	for name, mutate := range mutations {
		var sd SignedDirective
		_ = json.Unmarshal([]byte(artifact), &sd)
		mutate(&sd.Claims)
		raw, _ := json.Marshal(sd)
		e := exp
		// Bind the expectation to the MUTATED claims so only the signature can catch it.
		e.DeviceID, e.TenantID, e.KeyFP = sd.Claims.DeviceID, sd.Claims.TenantID, sd.Claims.KeyFP
		if _, err := VerifyDirective(ed25519.PublicKey(pub), string(raw), e); verifyCode(err) != DirectiveRefusedSignature {
			t.Errorf("editing %s after signing was not caught by the signature: %v", name, err)
		}
	}
}

func TestDirectiveTagsAreDistinct(t *testing.T) {
	tags := map[string][]byte{
		"directive": directiveDomainTag, "directive ack": directiveAckDomainTag,
		"grant": grantDomainTag, "audit": auditDomainTag, "elevation": elevationDomainTag, "session policy": sessionPolicyDomainTag,
		"ticket": ticketDomainTag, "update": updateDomainTag, "update v2": updateDomainTagV2, "mgmt audit": mgmtAuditDomainTag,
	}
	for _, n := range []string{"directive", "directive ack"} {
		if len(tags[n]) != 16 {
			t.Errorf("%s tag is %d bytes, want 16", n, len(tags[n]))
		}
	}
	for an, a := range tags {
		for bn, b := range tags {
			if an == bn {
				continue
			}
			if bytes.HasPrefix(a, b) || bytes.HasPrefix(b, a) {
				t.Errorf("tags %q and %q are prefixes of one another", an, bn)
			}
		}
	}
}

func TestDirectiveIssuerRefusesAPlaceholderSeed(t *testing.T) {
	if _, err := NewDirectiveIssuerFromHex(strings.Repeat("00", 32)); err == nil {
		t.Fatal("all-zero seed accepted")
	}
	if _, err := NewDirectiveIssuerFromHex("abcd"); err == nil {
		t.Fatal("short seed accepted")
	}
	if _, err := NewDirectiveIssuerFromHex("zz"); err == nil {
		t.Fatal("non-hex seed accepted")
	}
}

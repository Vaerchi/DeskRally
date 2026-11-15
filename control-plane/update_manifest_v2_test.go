package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// =====================================================================================
// GOLDEN CROSS-LANGUAGE VECTOR (update v2).
//
// The SAME fixed fixture is hardcoded in Rust's agent/src/update.rs
// (`update::tests_v2::golden_vector_v2`). If either language's canonical encoder or Ed25519
// signing ever drifts, one side stops matching these constants. DO NOT change a value here without
// changing it identically in the Rust test, and never regenerate one side from its own output.
//
// The seed is the v1 golden seed (goldenUpdateSeedHex): the update key is one key whichever format
// it signs, and the v1/v2 separation is the domain tag, asserted by
// TestUpdateV2PreimageIsDomainSeparatedFromV1.
// =====================================================================================

const (
	goldenUpdateV2Ring           = "canary"
	goldenUpdateV2Version        = "0.1.0"
	goldenUpdateV2MSISHA256      = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	goldenUpdateV2MSIURL         = "https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi"
	goldenUpdateV2ProductVersion = "1.3.0"
	goldenUpdateV2ProductCode    = "{11111111-2222-3333-4444-555555555555}"
	goldenUpdateV2UpgradeCode    = "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}"
	goldenUpdateV2MinUpgradable  = "0.1.0"

	goldenUpdateV2PreimageHex = "524d545550444154457632000000000663616e61727900000005302e312e3000000040653362306334343239386663316331343961666266346338393936666239323432376165343165343634396239333463613439353939316237383532623835350000004b68747470733a2f2f6d61696e2e6465736b72616c6c792e636f6d2f646f776e6c6f61642f6167656e742f72656c65617365732f302e312e302f4465736b52616c6c794167656e742e6d736900000005312e332e30000000267b31313131313131312d323232322d333333332d343434342d3535353535353535353535357d000000267b37423345394332412d344631442d344538422d394136432d3244354538463141334237437d00000005302e312e3000000192cc091400000001936687dc00"
	goldenUpdateV2SigHex      = "04acc38e01d47f077213de5c19b87bd47dd2aac58759f43d372f1d60d634108d5b04c59ce47b246cbbeff9d96d1058884c647b5aa97af9e46e6541ad5690600b"

	// The EXACT wire string `update::tests_v2::verifies_go_signed_manifest_v2` decodes in Rust.
	// Pinned here so a `json:"…"` tag rename, which no preimage test can see, fails in Go too; see
	// goldenUpdateWireJSON for the long version of that argument.
	goldenUpdateV2WireJSON = `{"format":2,"claims":{"release":{"ring":"canary","version":"0.1.0","msi_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","msi_url":"https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi","product_version":"1.3.0","product_code":"{11111111-2222-3333-4444-555555555555}","upgrade_code":"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}","min_upgradable_from":"0.1.0"},"issued_at_ms":1730000000000,"expires_at_ms":1732592000000},"sig":"04acc38e01d47f077213de5c19b87bd47dd2aac58759f43d372f1d60d634108d5b04c59ce47b246cbbeff9d96d1058884c647b5aa97af9e46e6541ad5690600b"}`
)

func goldenUpdateReleaseV2() ReleaseBodyV2 {
	return ReleaseBodyV2{
		Ring:              goldenUpdateV2Ring,
		Version:           goldenUpdateV2Version,
		MSISHA256:         goldenUpdateV2MSISHA256,
		MSIURL:            goldenUpdateV2MSIURL,
		ProductVersion:    goldenUpdateV2ProductVersion,
		ProductCode:       goldenUpdateV2ProductCode,
		UpgradeCode:       goldenUpdateV2UpgradeCode,
		MinUpgradableFrom: goldenUpdateV2MinUpgradable,
	}
}

func goldenSignedV2(t *testing.T, r ReleaseBodyV2) SignedUpdateManifestV2 {
	t.Helper()
	msg, err := UpdateManifestV2SigningBytes(r, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	return NewSignedUpdateManifestV2(r, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs,
		ed25519.Sign(goldenUpdateKey(t), msg))
}

// The preimage, the signature AND the wire string must match Rust byte-for-byte; see
// TestUpdateManifestGoldenVectorV1 for why each is asserted separately.
func TestUpdateManifestGoldenVectorV2(t *testing.T) {
	priv := goldenUpdateKey(t)
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != goldenUpdatePubkeyHex {
		t.Fatalf("pubkey drift:\n got  %s\n want %s", got, goldenUpdatePubkeyHex)
	}
	msg, err := UpdateManifestV2SigningBytes(goldenUpdateReleaseV2(), goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenUpdateV2PreimageHex {
		t.Fatalf("canonical v2 preimage drift (Rust will reject every v2 manifest):\n got  %s\n want %s",
			got, goldenUpdateV2PreimageHex)
	}
	sig := ed25519.Sign(priv, msg)
	if got := hex.EncodeToString(sig); got != goldenUpdateV2SigHex {
		t.Fatalf("signature drift:\n got  %s\n want %s", got, goldenUpdateV2SigHex)
	}
	js, err := goldenSignedV2(t, goldenUpdateReleaseV2()).JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	t.Logf("GO_SIGNED_UPDATE_V2_JSON = %s", js)
	if js != goldenUpdateV2WireJSON {
		t.Fatalf("update manifest v2 WIRE drift (agent/src/update.rs verifies_go_signed_manifest_v2 holds "+
			"the other half):\n got  %s\n want %s", js, goldenUpdateV2WireJSON)
	}
}

func TestVerifyUpdateManifestV2WindowAndSignature(t *testing.T) {
	pub := goldenUpdateKey(t).Public().(ed25519.PublicKey)
	m := goldenSignedV2(t, goldenUpdateReleaseV2())

	if r, err := VerifyUpdateManifestV2(pub, m, goldenUpdateIssuedAtMs+1000); err != nil || r != goldenUpdateReleaseV2() {
		t.Fatalf("a genuine manifest must verify and return its release: %v", err)
	}
	// Expiry is EXACT.
	if _, err := VerifyUpdateManifestV2(pub, m, goldenUpdateExpiresAtMs); err == nil {
		t.Fatalf("a manifest at exactly expires_at_ms must be refused")
	}
	if _, err := VerifyUpdateManifestV2(pub, m, goldenUpdateExpiresAtMs-1); err != nil {
		t.Fatalf("one millisecond before expiry must still verify: %v", err)
	}
	// Not-yet-valid tolerates 30 s of skew, one-sided.
	if _, err := VerifyUpdateManifestV2(pub, m, goldenUpdateIssuedAtMs-30_000); err != nil {
		t.Fatalf("within the skew allowance must verify: %v", err)
	}
	if _, err := VerifyUpdateManifestV2(pub, m, goldenUpdateIssuedAtMs-30_001); err == nil {
		t.Fatalf("beyond the skew allowance must be refused")
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	if _, err := VerifyUpdateManifestV2(other.Public().(ed25519.PublicKey), m, goldenUpdateIssuedAtMs+1000); err == nil {
		t.Fatalf("a manifest must not verify against another key")
	}

	// Tampering with any signed field breaks the signature; the URL and the ring matter most.
	for name, mutate := range map[string]func(*SignedUpdateManifestV2){
		"msi_url":  func(x *SignedUpdateManifestV2) { x.Claims.Release.MSIURL = "https://evil.example/x.msi" },
		"ring":     func(x *SignedUpdateManifestV2) { x.Claims.Release.Ring = "general" },
		"issued":   func(x *SignedUpdateManifestV2) { x.Claims.IssuedAtMs++ },
		"expires":  func(x *SignedUpdateManifestV2) { x.Claims.ExpiresAtMs++ },
		"sig flip": func(x *SignedUpdateManifestV2) { x.Sig = "ff" + x.Sig[2:] },
	} {
		tampered := m
		mutate(&tampered)
		if _, err := VerifyUpdateManifestV2(pub, tampered, goldenUpdateIssuedAtMs+1000); err == nil {
			t.Errorf("tampering with %s must be refused", name)
		}
	}
	// A truncated or non-hex signature is an encoding refusal, not a panic.
	for _, bad := range []string{"", "ab", strings.Repeat("zz", 64)} {
		broken := m
		broken.Sig = bad
		if _, err := VerifyUpdateManifestV2(pub, broken, goldenUpdateIssuedAtMs+1000); err == nil {
			t.Errorf("signature %q must be refused", bad)
		}
	}
	// Only format 2 verifies here.
	for _, f := range []int{0, 1, 3} {
		wrong := m
		wrong.Format = f
		if _, err := VerifyUpdateManifestV2(pub, wrong, goldenUpdateIssuedAtMs+1000); err == nil {
			t.Errorf("format %d must be refused", f)
		}
	}
}

// Every field of the v2 release is inside the preimage, proven ONE AT A TIME against the baseline.
func TestEveryUpdateV2FieldChangesThePreimage(t *testing.T) {
	base, err := UpdateManifestV2SigningBytes(goldenUpdateReleaseV2(), goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	again, err := UpdateManifestV2SigningBytes(goldenUpdateReleaseV2(), goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil || !bytes.Equal(again, base) {
		t.Fatalf("the encoder is not deterministic")
	}

	cases := []struct {
		name            string
		mutate          func(*ReleaseBodyV2)
		issued, expires int64
	}{
		{"ring", func(r *ReleaseBodyV2) { r.Ring = "early" }, 0, 0},
		{"version", func(r *ReleaseBodyV2) { r.Version = "0.1.1" }, 0, 0},
		{"msi_sha256", func(r *ReleaseBodyV2) { r.MSISHA256 = strings.Repeat("0", 64) }, 0, 0},
		{"msi_url", func(r *ReleaseBodyV2) { r.MSIURL = "https://evil.example/x.msi" }, 0, 0},
		{"product_version", func(r *ReleaseBodyV2) { r.ProductVersion = "1.3.1" }, 0, 0},
		{"product_code", func(r *ReleaseBodyV2) { r.ProductCode = "{11111111-2222-3333-4444-555555555556}" }, 0, 0},
		{"upgrade_code", func(r *ReleaseBodyV2) { r.UpgradeCode = "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7D}" }, 0, 0},
		{"min_upgradable_from", func(r *ReleaseBodyV2) { r.MinUpgradableFrom = "0.1.1" }, 0, 0},
		{"issued_at_ms", func(*ReleaseBodyV2) {}, 1, 0},
		{"expires_at_ms", func(*ReleaseBodyV2) {}, 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := goldenUpdateReleaseV2()
			c.mutate(&r)
			got, err := UpdateManifestV2SigningBytes(r, goldenUpdateIssuedAtMs+c.issued, goldenUpdateExpiresAtMs+c.expires)
			if err != nil {
				t.Fatalf("signing bytes: %v", err)
			}
			if bytes.Equal(got, base) {
				t.Fatalf("changing %s did not change the signing bytes — the field is not signed", c.name)
			}
		})
	}

	// Transposing the two GUIDs must change the preimage too: the order binds value to meaning.
	swapped := goldenUpdateReleaseV2()
	swapped.ProductCode, swapped.UpgradeCode = swapped.UpgradeCode, swapped.ProductCode
	got, err := UpdateManifestV2SigningBytes(swapped, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("swapped: %v", err)
	}
	if bytes.Equal(got, base) {
		t.Fatalf("swapping product_code and upgrade_code did not change the preimage")
	}
}

// The signer refuses a manifest the agent would reject, and names the field.
func TestUpdateManifestV2SigningBytesRefusesMalformedFields(t *testing.T) {
	lower := strings.ToLower(goldenUpdateV2UpgradeCode)
	cases := []struct {
		name   string
		mutate func(*ReleaseBodyV2)
		wantIn string
	}{
		{"ring empty", func(r *ReleaseBodyV2) { r.Ring = "" }, "ring"},
		{"ring uppercase", func(r *ReleaseBodyV2) { r.Ring = "Canary" }, "ring"},
		{"ring unknown", func(r *ReleaseBodyV2) { r.Ring = "nightly" }, "ring"},
		{"ring padded", func(r *ReleaseBodyV2) { r.Ring = "canary " }, "ring"},
		{"bad version", func(r *ReleaseBodyV2) { r.Version = "0.1" }, "version"},
		{"prerelease version", func(r *ReleaseBodyV2) { r.Version = "0.1.0-rc1" }, "version"},
		{"short sha", func(r *ReleaseBodyV2) { r.MSISHA256 = "e3b0" }, "msi_sha256"},
		{"uppercase sha", func(r *ReleaseBodyV2) { r.MSISHA256 = strings.ToUpper(goldenUpdateV2MSISHA256) }, "msi_sha256"},
		{"http url", func(r *ReleaseBodyV2) { r.MSIURL = "http://main.deskrally.com/a.msi" }, "msi_url"},
		{"scheme only url", func(r *ReleaseBodyV2) { r.MSIURL = "https://" }, "msi_url"},
		{"control char url", func(r *ReleaseBodyV2) { r.MSIURL = "https://x/a\n.msi" }, "msi_url"},
		{"product_version major 256", func(r *ReleaseBodyV2) { r.ProductVersion = "256.0.0" }, "product_version"},
		{"product_version minor 256", func(r *ReleaseBodyV2) { r.ProductVersion = "0.256.0" }, "product_version"},
		{"product_version build 65536", func(r *ReleaseBodyV2) { r.ProductVersion = "1.3.65536" }, "product_version"},
		{"product_version leading zero", func(r *ReleaseBodyV2) { r.ProductVersion = "01.3.0" }, "product_version"},
		{"product_version leading zero build", func(r *ReleaseBodyV2) { r.ProductVersion = "1.3.00" }, "product_version"},
		{"product_version four fields", func(r *ReleaseBodyV2) { r.ProductVersion = "1.3.0.0" }, "product_version"},
		{"product_version two fields", func(r *ReleaseBodyV2) { r.ProductVersion = "1.3" }, "product_version"},
		{"product_version build metadata", func(r *ReleaseBodyV2) { r.ProductVersion = "1.3.0+abc" }, "product_version"},
		{"product_version signed", func(r *ReleaseBodyV2) { r.ProductVersion = "+1.3.0" }, "product_version"},
		{"product_code lowercase", func(r *ReleaseBodyV2) { r.ProductCode = "{aaaaaaaa-2222-3333-4444-555555555555}" }, "product_code"},
		{"product_code unbraced", func(r *ReleaseBodyV2) { r.ProductCode = "11111111-2222-3333-4444-555555555555" }, "product_code"},
		{"upgrade_code lowercase", func(r *ReleaseBodyV2) { r.UpgradeCode = lower }, "upgrade_code"},
		{"upgrade_code non-hex", func(r *ReleaseBodyV2) { r.UpgradeCode = "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7G}" }, "upgrade_code"},
		{"upgrade_code short", func(r *ReleaseBodyV2) { r.UpgradeCode = "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7}" }, "upgrade_code"},
		{"bad min", func(r *ReleaseBodyV2) { r.MinUpgradableFrom = "banana" }, "min_upgradable_from"},
	}
	// Positive control: the unmutated fixture signs, so each refusal below is the mutation.
	if _, err := UpdateManifestV2SigningBytes(goldenUpdateReleaseV2(), goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs); err != nil {
		t.Fatalf("the good case must encode: %v", err)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := goldenUpdateReleaseV2()
			c.mutate(&r)
			_, err := UpdateManifestV2SigningBytes(r, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
			if err == nil {
				t.Fatalf("signed a malformed %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Fatalf("the error does not name the bad field (%q): %v", c.wantIn, err)
			}
		})
	}
	for _, ring := range UpdateRings {
		r := goldenUpdateReleaseV2()
		r.Ring = ring
		if _, err := UpdateManifestV2SigningBytes(r, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs); err != nil {
			t.Errorf("ring %q must be accepted: %v", ring, err)
		}
	}
}

func TestUpdateProductVersionAndGUIDTables(t *testing.T) {
	for _, s := range []string{"0.0.0", "1.3.0", "255.255.65535", "0.0.1", "10.20.30"} {
		if err := checkUpdateProductVersion(s); err != nil {
			t.Errorf("product_version %q must be accepted: %v", s, err)
		}
	}
	for _, s := range []string{"", "1", "1.2", "1.2.3.4", "1..3", ".1.2", "1.2.", "256.0.0", "0.256.0",
		"1.3.65536", "1.3.99999", "1.3.100000", "1.3.999999999999", "01.3.0", "1.03.0", "1.3.00", "1.3.01",
		"-1.0.0", "+1.0.0", "1.3.0+abc", "1.3.0-rc1", " 1.3.0", "1.3.0 ", "1.3.x", "١.٣.٠"} {
		if err := checkUpdateProductVersion(s); err == nil {
			t.Errorf("product_version %q must be refused", s)
		}
	}
	for _, s := range []string{"{11111111-2222-3333-4444-555555555555}", "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}",
		"{00000000-0000-0000-0000-000000000000}", "{ABCDEF00-ABCD-EF00-ABCD-EF0000000000}"} {
		if err := checkUpdateBracedGUID(s); err != nil {
			t.Errorf("guid %q must be accepted: %v", s, err)
		}
	}
	for _, s := range []string{"", "11111111-2222-3333-4444-555555555555", "{11111111-2222-3333-4444-555555555555",
		"11111111-2222-3333-4444-555555555555}", "(11111111-2222-3333-4444-555555555555)",
		"{7b3e9c2a-4f1d-4e8b-9a6c-2d5e8f1a3b7c}", "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7c}",
		"{7B3E9C2A4F1D4E8B9A6C2D5E8F1A3B7C0000}", "{7B3E9C2A-4F1D-4E8B-9A6C2-D5E8F1A3B7C}",
		"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7G}", "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C }",
		" {7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}", "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7}",
		"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7CC}", "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7é}"} {
		if err := checkUpdateBracedGUID(s); err == nil {
			t.Errorf("guid %q must be refused", s)
		}
	}
}

// A v2 preimage and a v1 preimage for analogous content diverge at the tag, and a v1 signature is
// useless as a v2 one. TestDomainTagsArePairwiseDistinct covers the constants; this proves the
// ENCODERS put the right tag first.
func TestUpdateV2PreimageIsDomainSeparatedFromV1(t *testing.T) {
	v2, err := UpdateManifestV2SigningBytes(goldenUpdateReleaseV2(), goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("v2 signing bytes: %v", err)
	}
	v1, err := UpdateManifestSigningBytes(goldenUpdateV2Version, goldenUpdateV2MSISHA256, goldenUpdateV2MSIURL,
		goldenUpdateV2MinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("v1 signing bytes: %v", err)
	}
	if !bytes.HasPrefix(v2, updateDomainTagV2) || !bytes.HasPrefix(v1, updateDomainTag) {
		t.Fatalf("a preimage does not start with its own tag")
	}
	if bytes.Equal(v1[:12], v2[:12]) || bytes.Equal(v1, v2) {
		t.Fatalf("v1 and v2 preimages are not separated")
	}
	if string(updateDomainTagV2) != "RMTUPDATEv2\x00" || len(updateDomainTagV2) != 12 {
		t.Fatalf("updateDomainTagV2 is %q (%d bytes)", updateDomainTagV2, len(updateDomainTagV2))
	}

	// A v1 signature re-presented as a v2 one is refused.
	pub := goldenUpdateKey(t).Public().(ed25519.PublicKey)
	forged := goldenSignedV2(t, goldenUpdateReleaseV2())
	forged.Sig = hex.EncodeToString(ed25519.Sign(goldenUpdateKey(t), v1))
	if _, err := VerifyUpdateManifestV2(pub, forged, goldenUpdateIssuedAtMs+1000); err == nil {
		t.Fatalf("a v1 signature verified as a v2 manifest")
	}
}

// The two wire formats refuse each other when decoded strictly (the way the signer's verify
// subcommand and the Rust agent decode): v1 has no `format`, v2 has `format` and different
// release keys.
func TestUpdateV1AndV2WireFormatsRefuseEachOther(t *testing.T) {
	strict := func(raw string, into any) error {
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		return dec.Decode(into)
	}
	var v1 SignedUpdateManifest
	var v2 SignedUpdateManifestV2
	// Positive controls.
	if err := strict(goldenUpdateWireJSON, &v1); err != nil {
		t.Fatalf("v1 JSON must decode as v1: %v", err)
	}
	if err := strict(goldenUpdateV2WireJSON, &v2); err != nil {
		t.Fatalf("v2 JSON must decode as v2: %v", err)
	}
	var wrong1 SignedUpdateManifest
	if err := strict(goldenUpdateV2WireJSON, &wrong1); err == nil {
		t.Fatalf("a v1 strict decoder accepted v2 JSON")
	}
	var wrong2 SignedUpdateManifestV2
	if err := strict(goldenUpdateWireJSON, &wrong2); err == nil {
		t.Fatalf("a v2 strict decoder accepted v1 JSON")
	}
	// Even if a lax decoder let v1 JSON through, it carries no format, so verification refuses it.
	var lax SignedUpdateManifestV2
	if err := json.Unmarshal([]byte(goldenUpdateWireJSON), &lax); err != nil {
		t.Fatalf("lax decode: %v", err)
	}
	pub := goldenUpdateKey(t).Public().(ed25519.PublicKey)
	if _, err := VerifyUpdateManifestV2(pub, lax, goldenUpdateIssuedAtMs+1000); err == nil {
		t.Fatalf("v1 content verified as a v2 manifest")
	}
}

// Verification order is signature, then window, then shapes, exactly as Rust's verify(). Ed25519
// signs any preimage, so a malformed ring CAN carry a valid signature; the tests sign the raw
// preimage to build exactly that.
func TestVerifyUpdateManifestV2ErrorOrdering(t *testing.T) {
	pub := goldenUpdateKey(t).Public().(ed25519.PublicKey)
	badRing := goldenUpdateReleaseV2()
	badRing.Ring = "nightly"
	if _, err := UpdateManifestV2SigningBytes(badRing, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs); err == nil {
		t.Fatalf("the signing path must still refuse a malformed ring")
	}
	signRaw := func(r ReleaseBodyV2) SignedUpdateManifestV2 {
		sig := ed25519.Sign(goldenUpdateKey(t), updateManifestV2Preimage(r, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs))
		return NewSignedUpdateManifestV2(r, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs, sig)
	}
	inWindow := goldenUpdateIssuedAtMs + 1000
	mustSay := func(err error, want string, others ...string) {
		t.Helper()
		if err == nil {
			t.Fatalf("expected an error containing %q", want)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("want %q, got: %v", want, err)
		}
		for _, o := range others {
			if strings.Contains(err.Error(), o) {
				t.Fatalf("error %q must not mention %q", err, o)
			}
		}
	}

	// Invalid signature + malformed ring: the signature is what is reported, not the shape.
	bad := goldenSignedV2(t, goldenUpdateReleaseV2())
	bad.Claims.Release.Ring = "nightly"
	_, err := VerifyUpdateManifestV2(pub, bad, inWindow)
	mustSay(err, "signature is invalid", "ring")

	// Invalid signature + malformed ring + expired window: still the signature.
	_, err = VerifyUpdateManifestV2(pub, bad, goldenUpdateExpiresAtMs+1)
	mustSay(err, "signature is invalid", "ring", "expired")

	// Valid signature over a malformed ring + expired window: the window, not the shape.
	raw := signRaw(badRing)
	_, err = VerifyUpdateManifestV2(pub, raw, goldenUpdateExpiresAtMs)
	mustSay(err, "expired", "ring")

	// ... and not yet valid.
	_, err = VerifyUpdateManifestV2(pub, raw, goldenUpdateIssuedAtMs-30_001)
	mustSay(err, "not yet valid", "ring")

	// Valid signature + valid window + malformed ring: finally the shape, naming the field.
	_, err = VerifyUpdateManifestV2(pub, raw, inWindow)
	mustSay(err, "ring")

	// Shapes are checked in field order after the window: ring before a later bad field.
	both := goldenUpdateReleaseV2()
	both.Ring, both.MinUpgradableFrom = "nightly", "banana"
	_, err = VerifyUpdateManifestV2(pub, signRaw(both), inWindow)
	mustSay(err, "ring", "min_upgradable_from")

	// Positive control: the same helper with a well-formed release verifies.
	if _, err := VerifyUpdateManifestV2(pub, signRaw(goldenUpdateReleaseV2()), inWindow); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

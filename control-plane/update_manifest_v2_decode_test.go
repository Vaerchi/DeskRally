package controlplane

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// The strict decoder must refuse every variant of the golden wire JSON that the Rust decoder
// refuses (agent/src/update.rs `tests_v2::the_rust_decoder_refuses_the_same_wire_variants` runs the
// SAME list of variants). encoding/json accepted several of these.

// wireVariantsV2 are (name, mutated golden JSON) pairs that no agent will decode.
func wireVariantsV2(t *testing.T) [][2]string {
	t.Helper()
	g := goldenUpdateV2WireJSON
	rep := func(old, new string) string {
		t.Helper()
		if strings.Count(g, old) != 1 {
			t.Fatalf("fixture needle %q must occur exactly once", old)
		}
		return strings.Replace(g, old, new, 1)
	}
	var v [][2]string
	add := func(name, js string) {
		if js == g {
			t.Fatalf("%s: the variant equals the golden JSON", name)
		}
		v = append(v, [2]string{name, js})
	}

	// Case variants of every key at every level.
	for _, k := range []string{"format", "claims", "sig", "release", "issued_at_ms", "expires_at_ms",
		"ring", "version", "msi_sha256", "msi_url", "product_version", "product_code", "upgrade_code",
		"min_upgradable_from"} {
		add("case "+k, rep(`"`+k+`":`, `"`+strings.ToUpper(k[:1])+k[1:]+`":`))
		add("upper "+k, rep(`"`+k+`":`, `"`+strings.ToUpper(k)+`":`))
	}

	// Duplicate keys at every level (the duplicate repeats the unchanged value).
	add("dup format", rep(`"format":2,`, `"format":2,"format":2,`))
	add("dup expires_at_ms", rep(`,"expires_at_ms":1732592000000`, `,"expires_at_ms":1732592000000,"expires_at_ms":1732592000000`))
	add("dup sig", strings.TrimSuffix(g, `}`)+`,"sig":"`+strings.Repeat("00", 64)+`"}`)
	add("dup issued_at_ms", rep(`"issued_at_ms":1730000000000,`, `"issued_at_ms":1730000000000,"issued_at_ms":1730000000000,`))
	add("dup ring", rep(`"ring":"canary",`, `"ring":"canary","ring":"canary",`))
	add("dup min_upgradable_from", rep(`"min_upgradable_from":"0.1.0"`, `"min_upgradable_from":"0.1.0","min_upgradable_from":"0.1.0"`))

	// Missing fields, one at a time, at every level.
	add("missing format", rep(`"format":2,`, ``))
	add("missing claims", `{"format":2,"sig":"`+strings.Repeat("00", 64)+`"}`)
	add("missing sig", rep(`,"sig":"04acc38e01d47f077213de5c19b87bd47dd2aac58759f43d372f1d60d634108d5b04c59ce47b246cbbeff9d96d1058884c647b5aa97af9e46e6541ad5690600b"`, ``))
	add("missing release", rep(`"release":{"ring":"canary","version":"0.1.0","msi_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","msi_url":"https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi","product_version":"1.3.0","product_code":"{11111111-2222-3333-4444-555555555555}","upgrade_code":"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}","min_upgradable_from":"0.1.0"},`, ``))
	add("missing issued_at_ms", rep(`"issued_at_ms":1730000000000,`, ``))
	add("missing expires_at_ms", rep(`,"expires_at_ms":1732592000000`, ``))
	for _, f := range []struct{ key, val string }{
		{"ring", `"canary"`}, {"version", `"0.1.0"`},
		{"msi_sha256", `"` + goldenUpdateV2MSISHA256 + `"`}, {"msi_url", `"` + goldenUpdateV2MSIURL + `"`},
		{"product_version", `"1.3.0"`}, {"product_code", `"` + goldenUpdateV2ProductCode + `"`},
		{"upgrade_code", `"` + goldenUpdateV2UpgradeCode + `"`},
	} {
		add("missing "+f.key, rep(`"`+f.key+`":`+f.val+`,`, ``))
		add("null "+f.key, rep(`"`+f.key+`":`+f.val, `"`+f.key+`":null`))
		add("number "+f.key, rep(`"`+f.key+`":`+f.val, `"`+f.key+`":1`))
	}
	add("missing min_upgradable_from", rep(`,"min_upgradable_from":"0.1.0"`, ``))
	add("null min_upgradable_from", rep(`"min_upgradable_from":"0.1.0"`, `"min_upgradable_from":null`))

	// Null (or the wrong type) for every non-string field too.
	add("null format", rep(`"format":2`, `"format":null`))
	add("null claims", rep(`"claims":{`, `"claims":null,"x":{`))
	add("null release", rep(`"release":{"ring"`, `"release":null,"x":{"ring"`))
	add("null issued_at_ms", rep(`"issued_at_ms":1730000000000`, `"issued_at_ms":null`))
	add("null expires_at_ms", rep(`"expires_at_ms":1732592000000`, `"expires_at_ms":null`))
	add("null sig", rep(`"sig":"`+goldenUpdateV2SigHex+`"`, `"sig":null`))
	add("string issued_at_ms", rep(`"issued_at_ms":1730000000000`, `"issued_at_ms":"1730000000000"`))
	add("float issued_at_ms", rep(`"issued_at_ms":1730000000000`, `"issued_at_ms":1730000000000.0`))
	add("exponent expires_at_ms", rep(`"expires_at_ms":1732592000000`, `"expires_at_ms":1.732592e12`))
	add("overflow expires_at_ms", rep(`"expires_at_ms":1732592000000`, `"expires_at_ms":9223372036854775808`))
	add("leading zero issued_at_ms", rep(`"issued_at_ms":1730000000000`, `"issued_at_ms":01730000000000`))
	add("negative zero issued_at_ms", rep(`"issued_at_ms":1730000000000`, `"issued_at_ms":-0`))
	add("negative zero expires_at_ms", rep(`"expires_at_ms":1732592000000`, `"expires_at_ms":-0`))
	add("null document", `null`)
	add("array document", `[]`)

	// A format other than 2, or not a plain integer.
	for _, f := range []string{`0`, `1`, `3`, `4294967295`, `-2`, `"2"`, `2.0`, `2.5`, `2e0`, `true`} {
		add("format "+f, rep(`"format":2`, `"format":`+f))
	}

	// Unknown keys at every level.
	add("unknown top", rep(`{"format"`, `{"rollback":true,"format"`))
	add("unknown claims", rep(`"issued_at_ms"`, `"x":1,"issued_at_ms"`))
	add("unknown release", rep(`"ring"`, `"exec":"cmd.exe","ring"`))

	// Anything after the top-level value.
	for _, tail := range []string{`x`, `{}`, `,`, `}`, "\n{}", ` null`, "\x00"} {
		add("trailing "+strings.TrimSpace(strings.ReplaceAll(tail, "\x00", "NUL")), g+tail)
	}

	// Structural damage.
	add("empty", ``)
	add("truncated", g[:len(g)-1])
	add("trailing comma", rep(`"min_upgradable_from":"0.1.0"`, `"min_upgradable_from":"0.1.0",`))
	add("bare value", rep(`"ring":"canary"`, `"ring":canary`))
	add("control char in string", rep(`"ring":"canary"`, "\"ring\":\"can\nary\""))
	add("lone surrogate", rep(`"ring":"canary"`, `"ring":"can\ud800ary"`))
	add("lone low surrogate", rep(`"ring":"canary"`, `"ring":"can\udc00ary"`))
	add("bad escape", rep(`"ring":"canary"`, `"ring":"can\qary"`))
	add("invalid utf-8", rep(`"ring":"canary"`, "\"ring\":\"can\xffary\""))
	return v
}

func TestDecodeSignedUpdateManifestV2AcceptsTheGoldenWire(t *testing.T) {
	m, err := DecodeSignedUpdateManifestV2([]byte(goldenUpdateV2WireJSON))
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	want := goldenSignedV2(t, goldenUpdateReleaseV2())
	if m != want {
		t.Fatalf("decoded value drifted:\n got  %+v\n want %+v", m, want)
	}
	// The decoded value verifies, so the decoder and the verifier agree end to end.
	pub := goldenUpdateKey(t).Public().(ed25519.PublicKey)
	if _, err := VerifyUpdateManifestV2(pub, m, goldenUpdateIssuedAtMs+1000); err != nil {
		t.Fatalf("decoded golden manifest does not verify: %v", err)
	}

	// Insignificant whitespace, field ORDER and JSON escapes are all things serde accepts.
	spaced := " \t\r\n" + strings.NewReplacer(`,"`, ",\n  \"", `:`, ` : `).Replace(goldenUpdateV2WireJSON) + "\n \r\t"
	if _, err := DecodeSignedUpdateManifestV2([]byte(spaced)); err != nil {
		t.Errorf("whitespace must be accepted: %v", err)
	}
	reordered := `{"sig":"` + goldenUpdateV2SigHex + `","claims":{"expires_at_ms":1732592000000,"issued_at_ms":1730000000000,"release":` +
		goldenUpdateV2WireJSON[strings.Index(goldenUpdateV2WireJSON, `{"ring"`):strings.Index(goldenUpdateV2WireJSON, `,"issued_at_ms"`)] + `},"format":2}`
	if r, err := DecodeSignedUpdateManifestV2([]byte(reordered)); err != nil || r != want {
		t.Errorf("a reordered but exact document must decode to the same value: %v", err)
	}
	escaped := strings.Replace(goldenUpdateV2WireJSON, `"canary"`, `"canary\/"`, 1)
	if r, err := DecodeSignedUpdateManifestV2([]byte(escaped)); err != nil || r.Claims.Release.Ring != "canary/" {
		t.Errorf("escapes must decode: ring=%q err=%v", r.Claims.Release.Ring, err)
	}
	pair := strings.Replace(goldenUpdateV2WireJSON, `"canary"`, `"😀"`, 1)
	if r, err := DecodeSignedUpdateManifestV2([]byte(pair)); err != nil || r.Claims.Release.Ring != "\U0001F600" {
		t.Errorf("a surrogate pair must decode: ring=%q err=%v", r.Claims.Release.Ring, err)
	}
}

func TestDecodeSignedUpdateManifestV2RefusesEveryWireVariant(t *testing.T) {
	variants := wireVariantsV2(t)
	if len(variants) < 100 {
		t.Fatalf("only %d variants: the generator has lost cases", len(variants))
	}
	for _, v := range variants {
		name, js := v[0], v[1]
		t.Run(name, func(t *testing.T) {
			if m, err := DecodeSignedUpdateManifestV2([]byte(js)); err == nil {
				t.Fatalf("accepted %q as %+v", js, m)
			}
		})
	}
}

// Negative control for the claim in the decoder's header: encoding/json with DisallowUnknownFields
// (the previous decoder) accepted these, so the cases above are not vacuous.
func TestStdlibStrictModeWouldHaveAcceptedCaseAndDuplicateKeys(t *testing.T) {
	for name, js := range map[string]string{
		"case":      strings.Replace(goldenUpdateV2WireJSON, `"ring":`, `"Ring":`, 1),
		"duplicate": strings.Replace(goldenUpdateV2WireJSON, `"ring":"canary",`, `"ring":"canary","ring":"canary",`, 1),
	} {
		if err := stdlibStrictDecode(js); err != nil {
			t.Fatalf("%s: premise broke, the stdlib decoder now refuses it: %v", name, err)
		}
		if _, err := DecodeSignedUpdateManifestV2([]byte(js)); err == nil {
			t.Errorf("%s: the strict decoder accepted it", name)
		}
	}
}

// stdlibStrictDecode is the previous v2 decoder, kept only to prove the negative control above.
func stdlibStrictDecode(js string) error {
	var m SignedUpdateManifestV2
	dec := json.NewDecoder(bytes.NewReader([]byte(js)))
	dec.DisallowUnknownFields()
	return dec.Decode(&m)
}

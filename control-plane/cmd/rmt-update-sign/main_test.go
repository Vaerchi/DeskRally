package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	controlplane "rmt/controlplane"
)

// The golden fixture, restated here rather than shared.
//
// These constants duplicate `goldenUpdate*` in control-plane/update_manifest_test.go on purpose:
// Go test files are not importable across packages, and copying them is the point anyway — this
// binary is the one that actually signs, so it has to be proven to produce the SAME wire string the
// shared package's vector pins and the Rust agent decodes. Three independent restatements of one
// fixture is what makes a drift in any of them visible.
const (
	goldenSeedHex = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	goldenVersion = "0.4.0"
	goldenSHA256  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	goldenURL     = "https://updates.deskrally.com/rmt-agent-0.4.0.exe"
	goldenMinFrom = "0.2.0"
	goldenIssued  = int64(1730000000000)
	goldenExpires = int64(1732592000000)

	goldenWireJSON = `{"claims":{"release":{"version":"0.4.0","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","url":"https://updates.deskrally.com/rmt-agent-0.4.0.exe","min_upgradable_from":"0.2.0"},"issued_at_ms":1730000000000,"expires_at_ms":1732592000000},"sig":"eb7c68776b438a8879d948213149fbac431927aba493dc9f823e3349d5ccf481c322e90b85bd32e04aab33dd786b4a0f75bdafe02f4c58c46a878d517149350d"}`
)

func goldenPriv(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(goldenSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// The signer's output is byte-for-byte the manifest the shared package's golden vector pins and the
// Rust agent's `verifies_go_signed_manifest` decodes. This is the assertion that makes the
// three-binary split safe: moving signing out of the server is only worth doing if the thing it
// moved to produces exactly the same artifact.
func TestBuildSignedMatchesTheGoldenVector(t *testing.T) {
	js, err := buildSigned(goldenPriv(t), goldenVersion, goldenSHA256, goldenURL, goldenMinFrom,
		goldenIssued, goldenExpires)
	if err != nil {
		t.Fatalf("buildSigned: %v", err)
	}
	if js != goldenWireJSON {
		t.Fatalf("signer output drift — the agent decodes this string:\n got  %s\n want %s", js, goldenWireJSON)
	}
}

// The signer refuses to emit a manifest no agent would act on. A release engineer must find out
// here, in front of the tool, rather than from a fleet that quietly stops updating.
func TestBuildSignedRefusesWhatTheAgentWouldRefuse(t *testing.T) {
	priv := goldenPriv(t)
	cases := []struct{ name, version, sha, url, min string }{
		{"uppercase sha", goldenVersion, strings.ToUpper(goldenSHA256), goldenURL, goldenMinFrom},
		{"short sha", goldenVersion, "abc", goldenURL, goldenMinFrom},
		{"http url", goldenVersion, goldenSHA256, "http://updates.example/a.exe", goldenMinFrom},
		{"bad version", "0.4", goldenSHA256, goldenURL, goldenMinFrom},
		{"prerelease", "0.4.0-rc1", goldenSHA256, goldenURL, goldenMinFrom},
		{"bad min", goldenVersion, goldenSHA256, goldenURL, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildSigned(priv, c.version, c.sha, c.url, c.min, goldenIssued, goldenExpires); err == nil {
				t.Fatalf("signed a manifest with a bad %s", c.name)
			}
		})
	}
	// The positive control: the same call with good values must succeed, or this test would pass
	// against a buildSigned that refused everything.
	if _, err := buildSigned(priv, goldenVersion, goldenSHA256, goldenURL, goldenMinFrom, goldenIssued, goldenExpires); err != nil {
		t.Fatalf("the good case must sign: %v", err)
	}
}

// A seed file with anything but exactly 64 hex characters is refused rather than coerced. A
// truncated or partly-overwritten seed that produced a DIFFERENT valid key would strand every agent
// pinned to the old public half, with no remote way back (docs/21 §3).
func TestReadSeedIsStrict(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	if _, err := readSeed(""); err == nil {
		t.Errorf("an empty -seed must be refused")
	}
	if _, err := readSeed(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Errorf("a missing seed file must be refused")
	}
	for name, body := range map[string]string{
		"short.key":   goldenSeedHex[:60],
		"long.key":    goldenSeedHex + "aa",
		"nonhex.key":  strings.Repeat("z", 64),
		"empty.key":   "",
		"garbage.key": "this is not a key",
	} {
		if _, err := readSeed(write(name, body)); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	// Trailing whitespace IS tolerated — `gen-key` writes a newline, and every editor adds one.
	priv, err := readSeed(write("good.key", goldenSeedHex+"\n"))
	if err != nil {
		t.Fatalf("a well-formed seed with a trailing newline must load: %v", err)
	}
	if hex.EncodeToString(priv.Public().(ed25519.PublicKey)) != "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0" {
		t.Fatalf("the loaded seed produced the wrong public key")
	}
}

// Exactly one of -sha256 / -binary. Neither is a mistake; both is ambiguous, and the digest decides
// which bytes step 3 will accept as the release.
func TestResolveDigestRequiresExactlyOne(t *testing.T) {
	if _, err := resolveDigest("", ""); err == nil {
		t.Errorf("neither -sha256 nor -binary must be refused")
	}
	if _, err := resolveDigest(goldenSHA256, "somefile"); err == nil {
		t.Errorf("both -sha256 and -binary must be refused")
	}
	got, err := resolveDigest(goldenSHA256, "")
	if err != nil || got != goldenSHA256 {
		t.Errorf("-sha256 passthrough: got %q, %v", got, err)
	}
	// -binary hashes locally. The empty file's SHA-256 is the golden fixture's digest, which is why
	// that value was chosen: it is checkable by hand.
	p := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err = resolveDigest("", p)
	if err != nil {
		t.Fatalf("hash -binary: %v", err)
	}
	if got != goldenSHA256 {
		t.Fatalf("SHA-256 of the empty file = %s, want %s", got, goldenSHA256)
	}
}

// An unknown field is refused, matching the Rust agent's `deny_unknown_fields`. A tool that printed
// OK on a manifest no agent will read hands out exactly the wrong reassurance.
func TestDecodeManifestRejectsUnknownFields(t *testing.T) {
	if _, err := decodeManifest([]byte(goldenWireJSON)); err != nil {
		t.Fatalf("positive control: the genuine manifest must decode: %v", err)
	}
	injected := strings.Replace(goldenWireJSON, `{"claims"`, `{"ring":"canary","claims"`, 1)
	if injected == goldenWireJSON {
		t.Fatalf("the fixture did not actually change")
	}
	if _, err := decodeManifest([]byte(injected)); err == nil {
		t.Fatalf("an unknown top-level field must be refused")
	}
}

// gen-key must never overwrite an existing signing key. Replacing one silently strands every agent
// that pinned its public half.
func TestGenKeyRefusesToOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "release.key")
	if err := cmdGenKey([]string{"-seed", p}); err != nil {
		t.Fatalf("gen-key: %v", err)
	}
	first, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := cmdGenKey([]string{"-seed", p}); err == nil {
		t.Fatalf("gen-key overwrote an existing key")
	}
	second, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("the existing key was modified by the refused gen-key")
	}
	// And what it wrote is loadable — otherwise "refuses to overwrite" could be true of a tool that
	// never wrote anything usable in the first place.
	if _, err := readSeed(p); err != nil {
		t.Fatalf("gen-key wrote a seed readSeed cannot load: %v", err)
	}
}

// ---------------------------------------------------------------------------------------
// Format 2 (MSI) manifests
// ---------------------------------------------------------------------------------------

// The format-2 golden fixture, restated here for the same reason as the v1 one above: this binary is
// the one that signs, so it must be proven to emit exactly the wire string that
// control-plane/update_manifest_v2_test.go pins and the Rust agent's
// `update::tests_v2::verifies_go_signed_manifest_v2` decodes. The digest is the empty input's, so
// `-msi` on an empty file reproduces it.
const (
	goldenV2Ring           = "canary"
	goldenV2Version        = "0.1.0"
	goldenV2MSIURL         = "https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi"
	goldenV2ProductVersion = "1.3.0"
	goldenV2ProductCode    = "{11111111-2222-3333-4444-555555555555}"
	goldenV2UpgradeCode    = "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}"
	goldenV2MinFrom        = "0.1.0"

	goldenV2WireJSON = `{"format":2,"claims":{"release":{"ring":"canary","version":"0.1.0","msi_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","msi_url":"https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi","product_version":"1.3.0","product_code":"{11111111-2222-3333-4444-555555555555}","upgrade_code":"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}","min_upgradable_from":"0.1.0"},"issued_at_ms":1730000000000,"expires_at_ms":1732592000000},"sig":"04acc38e01d47f077213de5c19b87bd47dd2aac58759f43d372f1d60d634108d5b04c59ce47b246cbbeff9d96d1058884c647b5aa97af9e46e6541ad5690600b"}`
)

func goldenReleaseV2() controlplane.ReleaseBodyV2 {
	return controlplane.ReleaseBodyV2{
		Ring:              goldenV2Ring,
		Version:           goldenV2Version,
		MSISHA256:         goldenSHA256,
		MSIURL:            goldenV2MSIURL,
		ProductVersion:    goldenV2ProductVersion,
		ProductCode:       goldenV2ProductCode,
		UpgradeCode:       goldenV2UpgradeCode,
		MinUpgradableFrom: goldenV2MinFrom,
	}
}

func TestBuildSignedV2MatchesTheGoldenVector(t *testing.T) {
	js, err := buildSignedV2(goldenPriv(t), goldenReleaseV2(), goldenIssued, goldenExpires)
	if err != nil {
		t.Fatalf("buildSignedV2: %v", err)
	}
	if js != goldenV2WireJSON {
		t.Fatalf("v2 signer output drift — the agent decodes this string:\n got  %s\n want %s", js, goldenV2WireJSON)
	}
}

func TestBuildSignedV2RefusesWhatTheAgentWouldRefuse(t *testing.T) {
	priv := goldenPriv(t)
	cases := []struct {
		name   string
		mutate func(*controlplane.ReleaseBodyV2)
	}{
		{"bad ring", func(r *controlplane.ReleaseBodyV2) { r.Ring = "nightly" }},
		{"uppercase sha", func(r *controlplane.ReleaseBodyV2) { r.MSISHA256 = strings.ToUpper(goldenSHA256) }},
		{"http url", func(r *controlplane.ReleaseBodyV2) { r.MSIURL = "http://x.example/a.msi" }},
		{"product_version 256.0.0", func(r *controlplane.ReleaseBodyV2) { r.ProductVersion = "256.0.0" }},
		{"product_version 1.3.65536", func(r *controlplane.ReleaseBodyV2) { r.ProductVersion = "1.3.65536" }},
		{"product_version leading zero", func(r *controlplane.ReleaseBodyV2) { r.ProductVersion = "1.03.0" }},
		{"lowercase upgrade code", func(r *controlplane.ReleaseBodyV2) { r.UpgradeCode = strings.ToLower(goldenV2UpgradeCode) }},
		{"unbraced product code", func(r *controlplane.ReleaseBodyV2) { r.ProductCode = "11111111-2222-3333-4444-555555555555" }},
		{"bad min", func(r *controlplane.ReleaseBodyV2) { r.MinUpgradableFrom = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := goldenReleaseV2()
			c.mutate(&r)
			if _, err := buildSignedV2(priv, r, goldenIssued, goldenExpires); err == nil {
				t.Fatalf("signed a v2 manifest with a bad %s", c.name)
			}
		})
	}
}

// The whole `sign -format 2` path through argv: it loads the seed from a FILE, hashes the MSI
// locally, and emits the golden wire string; then `verify` (which routes on `format`) accepts it.
// Also proves `-format` defaults to 1, so existing v1 invocations are untouched.
func TestSignFormat2EndToEndAndVerifyRoutesOnFormat(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "release.key")
	if err := os.WriteFile(seed, []byte(goldenSeedHex+"\n"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	empty := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	out := filepath.Join(dir, "update-manifest.json")
	window := []string{"-seed", seed, "-valid-days", "30", "-issued-at-ms", "1730000000000", "-out", out}

	v2Args := append([]string{"-format", "2", "-ring", goldenV2Ring, "-version", goldenV2Version,
		"-msi", empty, "-msi-url", goldenV2MSIURL, "-product-version", goldenV2ProductVersion,
		"-product-code", goldenV2ProductCode, "-upgrade-code", goldenV2UpgradeCode,
		"-min-upgradable-from", goldenV2MinFrom}, window...)
	if err := cmdSign(v2Args); err != nil {
		t.Fatalf("sign -format 2: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(raw)) != goldenV2WireJSON {
		t.Fatalf("sign -format 2 output drift:\n got  %s\n want %s", raw, goldenV2WireJSON)
	}
	if manifestFormat(raw) != 2 {
		t.Fatalf("manifestFormat did not see format 2")
	}
	pub := hex.EncodeToString(goldenPriv(t).Public().(ed25519.PublicKey))
	if err := cmdVerify([]string{"-in", out, "-pubkey", pub, "-at-ms", "1730000060000"}); err != nil {
		t.Fatalf("verify of a v2 manifest: %v", err)
	}
	if err := cmdVerify([]string{"-in", out, "-pubkey", pub, "-at-ms", "1732592000000"}); err == nil {
		t.Fatalf("verify accepted an expired v2 manifest")
	}

	// v1 through the same entry point with no -format: unchanged, and verify routes it to v1.
	v1Args := append([]string{"-version", goldenVersion, "-binary", empty, "-url", goldenURL,
		"-min-upgradable-from", goldenMinFrom}, window...)
	if err := cmdSign(v1Args); err != nil {
		t.Fatalf("sign (v1, no -format): %v", err)
	}
	raw1, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(raw1)) != goldenWireJSON {
		t.Fatalf("v1 signing changed:\n got  %s\n want %s", raw1, goldenWireJSON)
	}
	if manifestFormat(raw1) == 2 {
		t.Fatalf("manifestFormat saw format 2 in a v1 manifest")
	}
	if err := cmdVerify([]string{"-in", out, "-pubkey", pub, "-at-ms", "1730000060000"}); err != nil {
		t.Fatalf("verify of a v1 manifest: %v", err)
	}
}

// A flag belonging to the other format is refused, not ignored: silently dropping -url from a
// format-2 invocation (or -ring from a format-1 one) would sign something other than what was typed.
func TestSignRefusesFlagsOfTheOtherFormat(t *testing.T) {
	seed := filepath.Join(t.TempDir(), "release.key")
	if err := os.WriteFile(seed, []byte(goldenSeedHex), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	for name, args := range map[string][]string{
		"v1 with -ring":       {"-seed", seed, "-ring", "canary"},
		"v1 with -msi-url":    {"-seed", seed, "-msi-url", goldenV2MSIURL},
		"v2 with -url":        {"-format", "2", "-seed", seed, "-url", goldenURL},
		"v2 with -sha256":     {"-format", "2", "-seed", seed, "-sha256", goldenSHA256},
		"v2 with -binary":     {"-format", "2", "-seed", seed, "-binary", "x"},
		"format 3":            {"-format", "3", "-seed", seed},
		"v2 without a digest": {"-format", "2", "-seed", seed},
	} {
		if err := cmdSign(args); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// Strict decoding refuses the other format's JSON in both directions, as the Rust parsers do.
func TestDecodeManifestFormatsRefuseEachOther(t *testing.T) {
	if _, err := decodeManifestV2([]byte(goldenV2WireJSON)); err != nil {
		t.Fatalf("positive control: v2 JSON must decode as v2: %v", err)
	}
	if _, err := decodeManifest([]byte(goldenV2WireJSON)); err == nil {
		t.Errorf("the v1 decoder accepted v2 JSON")
	}
	if _, err := decodeManifestV2([]byte(goldenWireJSON)); err == nil {
		t.Errorf("the v2 decoder accepted v1 JSON")
	}
	injected := strings.Replace(goldenV2WireJSON, `{"format"`, `{"rollback":true,"format"`, 1)
	if _, err := decodeManifestV2([]byte(injected)); err == nil {
		t.Errorf("an unknown top-level field must be refused in v2")
	}
}

// `verify` must not print OK for a file the agent's serde decoder would refuse. The exhaustive list
// lives with the decoder (controlplane TestDecodeSignedUpdateManifestV2RefusesEveryWireVariant);
// this proves the signer's own path goes through it, with the variants encoding/json let through.
func TestVerifyRefusesWhatSerdeWouldRefuse(t *testing.T) {
	dir := t.TempDir()
	pub := hex.EncodeToString(goldenPriv(t).Public().(ed25519.PublicKey))
	verify := func(js string) error {
		path := filepath.Join(dir, "m.json")
		if err := os.WriteFile(path, []byte(js), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return cmdVerify([]string{"-in", path, "-pubkey", pub, "-at-ms", "1730000060000"})
	}
	if err := verify(goldenV2WireJSON); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for name, js := range map[string]string{
		"case variant": strings.Replace(goldenV2WireJSON, `"ring":`, `"Ring":`, 1),
		"duplicate":    strings.Replace(goldenV2WireJSON, `"ring":"canary",`, `"ring":"canary","ring":"canary",`, 1),
		"missing":      strings.Replace(goldenV2WireJSON, `"upgrade_code":"{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}",`, ``, 1),
		"null":         strings.Replace(goldenV2WireJSON, `"version":"0.1.0"`, `"version":null`, 1),
		"trailing":     goldenV2WireJSON + `{}`,
	} {
		if js == goldenV2WireJSON {
			t.Fatalf("%s: fixture did not change", name)
		}
		if err := verify(js); err == nil {
			t.Errorf("verify accepted a %s manifest", name)
		}
	}
}

// A correctly signed manifest whose issued_at_ms is 0, re-spelled on the wire as -0, must be
// refused: serde_json reads -0 as a float and every agent would refuse it (Codex manifest review).
func TestVerifyRefusesNegativeZeroTimestamp(t *testing.T) {
	priv := goldenPriv(t)
	r := controlplane.ReleaseBodyV2{
		Ring: "canary", Version: "0.1.0",
		MSISHA256:         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		MSIURL:            "https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi",
		ProductVersion:    "1.3.0",
		ProductCode:       "{11111111-2222-3333-4444-555555555555}",
		UpgradeCode:       "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}",
		MinUpgradableFrom: "0.1.0",
	}
	pre, err := controlplane.UpdateManifestV2SigningBytes(r, 0, 1732592000000)
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	js, err := controlplane.NewSignedUpdateManifestV2(r, 0, 1732592000000, ed25519.Sign(priv, pre)).JSON()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	dir := t.TempDir()
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	verify := func(body string) error {
		path := filepath.Join(dir, "m.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return cmdVerify([]string{"-in", path, "-pubkey", pub, "-at-ms", "1730000060000"})
	}
	if err := verify(js); err != nil {
		t.Fatalf("positive control (issued_at_ms 0): %v", err)
	}
	mutated := strings.Replace(js, `"issued_at_ms":0,`, `"issued_at_ms":-0,`, 1)
	if mutated == js {
		t.Fatalf("fixture did not change: %s", js)
	}
	if err := verify(mutated); err == nil {
		t.Errorf("verify accepted issued_at_ms -0")
	}
}

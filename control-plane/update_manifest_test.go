package controlplane

import (
	"crypto/ed25519"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// =====================================================================================
// GOLDEN CROSS-LANGUAGE VECTOR (update v1).
//
// The SAME fixed fixture is hardcoded in Rust's agent/src/update.rs
// (`update::tests::golden_vector_v1`). If either language's canonical encoder or Ed25519 signing
// ever drifts, one side stops matching these constants. DO NOT change a value here without changing
// it identically in the Rust test.
//
// NOTE THE SEED, WHICH IS NOT goldenSeedHex. The grant, session-policy and elevation vectors all
// deliberately share ONE seed, because for those three the domain tag is the only thing separating
// the signatures and the vectors exist partly to prove it. This vector uses a DIFFERENT seed on
// purpose: the update signing key IS a different key in reality (docs/21 §3), the fixture should
// look like reality, and a shared seed would quietly model the exact configuration the agent's
// `UpdateTrust::from_config` refuses to run under. Domain separation is still asserted — by
// TestUpdatePreimageIsDomainSeparated, which needs no key at all.
//
// The window is 30 days, not the elevation grant's 2 minutes, so the fixture also documents that an
// update manifest expires on a release cadence rather than a session one.
// =====================================================================================

const (
	goldenUpdateSeedHex       = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	goldenUpdatePubkeyHex     = "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0"
	goldenUpdateVersion       = "0.4.0"
	goldenUpdateSHA256        = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	goldenUpdateURL           = "https://updates.deskrally.com/rmt-agent-0.4.0.exe"
	goldenUpdateMinUpgradable = "0.2.0"
	goldenUpdateIssuedAtMs    = int64(1730000000000)
	goldenUpdateExpiresAtMs   = int64(1732592000000) // issued + 30 days

	goldenUpdatePreimageHex = "524d5455504441544576310000000005302e342e3000000040653362306334343239386663316331343961666266346338393936666239323432376165343165343634396239333463613439353939316237383532623835350000003168747470733a2f2f757064617465732e6465736b72616c6c792e636f6d2f726d742d6167656e742d302e342e302e65786500000005302e322e3000000192cc091400000001936687dc00"
	goldenUpdateSigHex      = "eb7c68776b438a8879d948213149fbac431927aba493dc9f823e3349d5ccf481c322e90b85bd32e04aab33dd786b4a0f75bdafe02f4c58c46a878d517149350d"

	// The EXACT wire string `agent/src/update.rs`'s `verifies_go_signed_manifest` decodes,
	// character for character.
	//
	// The two golden hexes above pin the SIGNING PREIMAGE, which is built from raw field VALUES
	// (see UpdateManifestSigningBytes) and never touches a single JSON tag. So renaming any
	// `json:"…"` tag in update_manifest.go would leave every Go test green while every agent in the
	// field stopped decoding manifests — the drift is invisible on this side and arrives as
	// "updates silently stopped happening", which is the failure mode docs/21 §0 warns is
	// unrecoverable by this channel.
	//
	// Pinning the wire string here is what makes that rename fail in Go. It is the Go→Rust half of
	// the contract; the Rust half is the same constant in `verifies_go_signed_manifest`. If this
	// assertion ever fires, the two constants must be reconciled DELIBERATELY — regenerating this
	// one from the new output is exactly the mistake it exists to catch.
	goldenUpdateWireJSON = `{"claims":{"release":{"version":"0.4.0","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","url":"https://updates.deskrally.com/rmt-agent-0.4.0.exe","min_upgradable_from":"0.2.0"},"issued_at_ms":1730000000000,"expires_at_ms":1732592000000},"sig":"eb7c68776b438a8879d948213149fbac431927aba493dc9f823e3349d5ccf481c322e90b85bd32e04aab33dd786b4a0f75bdafe02f4c58c46a878d517149350d"}`
)

func goldenUpdateRelease() ReleaseBody {
	return ReleaseBody{
		Version:           goldenUpdateVersion,
		SHA256:            goldenUpdateSHA256,
		URL:               goldenUpdateURL,
		MinUpgradableFrom: goldenUpdateMinUpgradable,
	}
}

// goldenUpdateKey reconstructs the fixture's signing key.
//
// It calls ed25519.NewKeyFromSeed HERE, in a _test.go file, and that is the whole point: test files
// are not linked into the shipped `cmd/controlplane` binary, so the package can compute a golden
// signature while the SERVER still has no code path that produces one. See TestServerPackageCannotSign.
func goldenUpdateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(goldenUpdateSeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// The preimage AND the signature must match Rust byte-for-byte. Asserting the preimage separately
// from the signature matters: if only the signature were checked, a change that altered the
// preimage and the expected signature together (e.g. a regenerated constant) would still pass, and
// the agent — which computes the preimage itself — would start rejecting every manifest. That
// failure is silent. There is no error anywhere; updates simply never land, which is indisputably
// the worst way for this particular feature to break.
func TestUpdateManifestGoldenVectorV1(t *testing.T) {
	priv := goldenUpdateKey(t)
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != goldenUpdatePubkeyHex {
		t.Fatalf("pubkey drift:\n got  %s\n want %s", got, goldenUpdatePubkeyHex)
	}

	msg, err := UpdateManifestSigningBytes(goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL,
		goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	if got := hex.EncodeToString(msg); got != goldenUpdatePreimageHex {
		t.Fatalf("canonical preimage drift (Rust will reject every update manifest):\n got  %s\n want %s",
			got, goldenUpdatePreimageHex)
	}

	sig := ed25519.Sign(priv, msg)
	if got := hex.EncodeToString(sig); got != goldenUpdateSigHex {
		t.Fatalf("signature drift:\n got  %s\n want %s", got, goldenUpdateSigHex)
	}

	// THE WIRE, not just the preimage. Everything above is computed from field VALUES, so a JSON
	// struct-tag rename cannot fail any of it — and the agent decodes the JSON, not the preimage.
	signed := NewSignedUpdateManifest(goldenUpdateRelease(), goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs, sig)
	js, err := signed.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	// Still logged, so regenerating the pair after a DELIBERATE wire change stays a copy-paste
	// (go test -run TestUpdateManifestGoldenVectorV1 -v).
	t.Logf("GO_SIGNED_UPDATE_JSON = %s", js)
	if js != goldenUpdateWireJSON {
		t.Fatalf("update manifest WIRE drift — every deployed agent would stop decoding manifests "+
			"(agent/src/update.rs verifies_go_signed_manifest holds the other half):\n got  %s\n want %s",
			js, goldenUpdateWireJSON)
	}
}

// Round-trip: the manifest this package assembles verifies against the fixture's public key inside
// its window, and is refused outside it. Verification is the half of the contract the SERVER binary
// is allowed to hold; signing is not.
func TestVerifyUpdateManifestWindowAndSignature(t *testing.T) {
	priv := goldenUpdateKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	msg, err := UpdateManifestSigningBytes(goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL,
		goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("signing bytes: %v", err)
	}
	m := NewSignedUpdateManifest(goldenUpdateRelease(), goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs, ed25519.Sign(priv, msg))

	if _, err := VerifyUpdateManifest(pub, m, goldenUpdateIssuedAtMs+1000); err != nil {
		t.Fatalf("a genuine manifest must verify: %v", err)
	}
	// Expiry is EXACT.
	if _, err := VerifyUpdateManifest(pub, m, goldenUpdateExpiresAtMs); err == nil {
		t.Fatalf("a manifest at exactly expires_at_ms must be refused")
	}
	if _, err := VerifyUpdateManifest(pub, m, goldenUpdateExpiresAtMs-1); err != nil {
		t.Fatalf("one millisecond before expiry must still verify: %v", err)
	}
	// Not-yet-valid tolerates 30 s of skew, one-sided.
	if _, err := VerifyUpdateManifest(pub, m, goldenUpdateIssuedAtMs-30_000); err != nil {
		t.Fatalf("within the skew allowance must verify: %v", err)
	}
	if _, err := VerifyUpdateManifest(pub, m, goldenUpdateIssuedAtMs-30_001); err == nil {
		t.Fatalf("beyond the skew allowance must be refused")
	}
	// A different key must be refused, and the URL — the field naming what gets executed — must not
	// survive tampering.
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	if _, err := VerifyUpdateManifest(other.Public().(ed25519.PublicKey), m, goldenUpdateIssuedAtMs+1000); err == nil {
		t.Fatalf("a manifest must not verify against another key")
	}
	tampered := m
	tampered.Claims.Release.URL = "https://evil.example/backdoor.exe"
	if _, err := VerifyUpdateManifest(pub, tampered, goldenUpdateIssuedAtMs+1000); err == nil {
		t.Fatalf("a re-pointed url must break the signature")
	}
}

// Every field of the release must be inside the preimage, proven ONE AT A TIME against the
// unmodified baseline. Changing them all together would pass even if only one were signed.
func TestEveryUpdateFieldChangesThePreimage(t *testing.T) {
	base, err := UpdateManifestSigningBytes(goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL,
		goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	// The premise, established rather than assumed: the SAME inputs must produce the SAME bytes, or
	// every assertion below would pass against an encoder that emitted a random nonce.
	again, err := UpdateManifestSigningBytes(goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL,
		goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil || hex.EncodeToString(again) != hex.EncodeToString(base) {
		t.Fatalf("the encoder is not deterministic")
	}

	cases := []struct {
		name                   string
		version, sha, url, min string
		issued, expires        int64
	}{
		{"version", "0.4.1", goldenUpdateSHA256, goldenUpdateURL, goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs},
		{"sha256", goldenUpdateVersion, "0000000000000000000000000000000000000000000000000000000000000000", goldenUpdateURL, goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs},
		{"url", goldenUpdateVersion, goldenUpdateSHA256, "https://evil.example/backdoor.exe", goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs},
		{"min_upgradable_from", goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL, "0.3.0", goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs},
		{"issued_at_ms", goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL, goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs + 1, goldenUpdateExpiresAtMs},
		{"expires_at_ms", goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL, goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := UpdateManifestSigningBytes(c.version, c.sha, c.url, c.min, c.issued, c.expires)
			if err != nil {
				t.Fatalf("signing bytes: %v", err)
			}
			if hex.EncodeToString(got) == hex.EncodeToString(base) {
				t.Fatalf("changing %s did not change the signing bytes — the field is not signed", c.name)
			}
		})
	}
}

// The signer refuses a manifest the agent would reject. A cryptographically perfect manifest that
// no agent will act on is worse than a loud failure at release time: it looks like a successful
// release.
func TestUpdateManifestSigningBytesRefusesMalformedFields(t *testing.T) {
	cases := []struct{ name, version, sha, url, min, wantIn string }{
		{"short sha", goldenUpdateVersion, "e3b0c442", goldenUpdateURL, goldenUpdateMinUpgradable, "sha256"},
		{"uppercase sha", goldenUpdateVersion, strings.ToUpper(goldenUpdateSHA256), goldenUpdateURL, goldenUpdateMinUpgradable, "sha256"},
		{"non-hex sha", goldenUpdateVersion, strings.Repeat("z", 64), goldenUpdateURL, goldenUpdateMinUpgradable, "sha256"},
		{"http url", goldenUpdateVersion, goldenUpdateSHA256, "http://updates.example/a.exe", goldenUpdateMinUpgradable, "url"},
		{"file url", goldenUpdateVersion, goldenUpdateSHA256, "file:///C:/a.exe", goldenUpdateMinUpgradable, "url"},
		{"scheme only", goldenUpdateVersion, goldenUpdateSHA256, "https://", goldenUpdateMinUpgradable, "url"},
		{"bad version", "0.4", goldenUpdateSHA256, goldenUpdateURL, goldenUpdateMinUpgradable, "version"},
		{"prerelease version", "0.4.0-rc1", goldenUpdateSHA256, goldenUpdateURL, goldenUpdateMinUpgradable, "version"},
		{"bad min", goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL, "banana", "min_upgradable_from"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := UpdateManifestSigningBytes(c.version, c.sha, c.url, c.min,
				goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
			if err == nil {
				t.Fatalf("signed a malformed %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Fatalf("the error does not name the bad field (%q): %v", c.wantIn, err)
			}
		})
	}
}

// An update preimage and an elevation preimage must diverge at byte 0. It is not enough that the
// tags differ as constants (TestDomainTagsArePairwiseDistinct covers that) — the ENCODER has to
// actually put the right one at the front, which is the property that breaks when someone copies a
// signingBytes function and forgets the one changed line.
func TestUpdatePreimageIsDomainSeparated(t *testing.T) {
	upd, err := UpdateManifestSigningBytes(goldenUpdateVersion, goldenUpdateSHA256, goldenUpdateURL,
		goldenUpdateMinUpgradable, goldenUpdateIssuedAtMs, goldenUpdateExpiresAtMs)
	if err != nil {
		t.Fatalf("update signing bytes: %v", err)
	}
	elev, err := elevationSigningBytes(goldenTechnicianID, goldenSessionID, goldenMachineID,
		goldenElevationID, ElevationTokenLinkedElevated, goldenIssuedAtMs, goldenExpiresAtMs)
	if err != nil {
		t.Fatalf("elevation signing bytes: %v", err)
	}
	if string(upd[:12]) == string(elev[:12]) {
		t.Fatalf("the two preimages open with the SAME 12 bytes %q", upd[:12])
	}
	if !strings.HasPrefix(string(upd), string(updateDomainTag)) {
		t.Fatalf("the update preimage does not start with updateDomainTag")
	}
}

// The version comparator, pinned against the SAME table as Rust's
// `update::tests::unparseable_versions_are_refused_not_guessed` and
// `components_are_ordered_numerically_not_lexically`. Both sides must agree, because the offline
// signer refuses on this side what the agent would refuse on that one.
func TestUpdateVersionParsingMatchesRust(t *testing.T) {
	bad := []string{"", "   ", "+abc", "1.2", "1.2.3.4", "1..3", "1.2.x", "1.02.3", "1.0.0-rc1",
		strings.Repeat("9", 65), "1.2.99999999999999999999"}
	for _, s := range bad {
		if _, err := ParseUpdateVersion(s); err == nil {
			t.Errorf("%q parsed but must be refused", s)
		}
	}
	if _, err := ParseUpdateVersion("0.0.0"); err != nil {
		t.Errorf("0.0.0 must parse: %v", err)
	}

	// Build metadata is IGNORED for precedence (semver §10) — the property AGENT_VERSION depends
	// on, and the reason a rebuild of the running version is not an update.
	ord := []struct {
		a, b string
		want int
	}{
		{"0.0.1+abc", "0.0.1+def", 0},
		{"0.0.1+abc", "0.0.1", 0},
		{"0.10.0", "0.9.0", 1},
		{"2.0.0", "10.0.0", -1},
		{"1.0.10", "1.0.9", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.0.0", "0.0.0", 0},
	}
	for _, c := range ord {
		got, err := CompareUpdateVersions(c.a, c.b)
		if err != nil {
			t.Fatalf("compare(%q,%q): %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if _, err := CompareUpdateVersions("1.0.0", "banana"); err == nil {
		t.Errorf("an unparseable side must be an error, never a string fallback")
	}
}

// THE STRUCTURAL GUARD behind docs/21 §3's claim that "the control plane … cannot mint" an update
// manifest.
//
// That claim has to be true of the SHIPPED BINARY, not merely of its call graph, so this asserts
// the split by reading the package's own source:
//
//  1. update_manifest.go — the only file here that knows the update preimage — contains no
//     ed25519.Sign at all;
//  2. no other NON-TEST file in package controlplane so much as names UpdateManifestSigningBytes,
//     so nothing linked into cmd/controlplane can compose the preimage with a signature.
//
// _test.go files are exempt because they are not linked into the server binary, and the golden
// vector genuinely needs to sign. If someone later wires minting into a handler "just for the
// canary ring", this fails and the reviewer gets the file header to read.
//
// It reads the AST rather than the text, and that is not fastidiousness: the first version used
// strings.Contains and failed immediately — on update_manifest.go's own header comment, which spells
// out where ed25519.Sign is allowed to live. A guard that fires on prose describing the rule is a
// guard nobody keeps, and it would have been "fixed" by rewording the comment rather than by
// meaning anything. Parsing without ParseComments makes the check see code and only code.
func TestServerPackageCannotSign(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) < 10 {
		t.Fatalf("glob found only %d .go files — the guard is not reading the package", len(files))
	}
	sawUpdateFile, sawUpdateV2File := false, false
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		// No parser.ParseComments: comments must be invisible to this check. See the doc comment.
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		// Both manifest formats' files may know their preimage; neither may sign.
		isUpdateFile := f == "update_manifest.go" || f == "update_manifest_v2.go"
		if f == "update_manifest.go" {
			sawUpdateFile = true
		}
		if f == "update_manifest_v2.go" {
			sawUpdateV2File = true
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				// ed25519.Sign(...) — the half of minting this package must never hold.
				if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "ed25519" && v.Sel.Name == "Sign" && isUpdateFile {
					t.Errorf("%s calls ed25519.Sign at %s — the update signing key must never be "+
						"reachable from the server binary (docs/21 §3); signing belongs in "+
						"cmd/rmt-update-sign", f, fset.Position(v.Pos()))
				}
			case *ast.Ident:
				// The other half: nothing linked into cmd/controlplane may even build the preimage.
				if (v.Name == "UpdateManifestSigningBytes" || v.Name == "UpdateManifestV2SigningBytes") && !isUpdateFile {
					t.Errorf("%s (linked into cmd/controlplane) references %s "+
						"at %s — the control plane must be able to SERVE a signed manifest and not "+
						"to MINT one", f, v.Name, fset.Position(v.Pos()))
				}
			}
			return true
		})
	}
	if !sawUpdateFile || !sawUpdateV2File {
		t.Fatalf("update_manifest.go / update_manifest_v2.go were not both scanned — the guard is checking the wrong directory")
	}
}

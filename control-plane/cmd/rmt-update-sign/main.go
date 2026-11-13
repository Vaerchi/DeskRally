// Command rmt-update-sign is the OFFLINE signer for agent update manifests (docs/21 §3).
//
// ===========================================================================================
// WHY THIS IS A SEPARATE BINARY, AND NOT A CONTROL-PLANE ROUTE
// ===========================================================================================
//
// docs/21 §0 opens by calling agent auto-update the most dangerous feature in the product, for one
// reason: "whoever can sign an update owns every machine, forever." Not "can start a session" —
// owns, permanently, as SYSTEM, with no audit trail that survives, because the attacker controls
// the thing that writes it.
//
// §3 draws the only defence that actually holds: the update signing key never lives on the control
// plane. The control plane is the internet-facing component and therefore the one most likely to be
// compromised; if it never holds this key, then compromising it yields the ability to SERVE a
// manifest but not to SIGN one — and the agent refuses an unsigned or unverifiable manifest. That
// turns a server compromise from "fleet-wide remote code execution" into "denial of updates", which
// is a category of problem a deployment survives.
//
// A route on the control plane, or a `MintUpdateManifest` method on `GrantIssuer` next to the four
// artifacts it already mints, would put the key in a `.env` file on that box and delete the whole
// argument. So the split is structural rather than stylistic:
//
//   - package `controlplane` (linked into cmd/controlplane) holds the canonical PREIMAGE and the
//     VERIFIER, and `TestServerPackageCannotSign` fails the build if any non-test file there so
//     much as names `UpdateManifestSigningBytes`;
//   - `ed25519.Sign` over an update preimage exists ONLY here, in a binary the server never
//     imports, run by a human on a machine that is not the server.
//
// That makes §3's claim — "the control plane stores and serves an already-signed manifest and
// cannot mint one" — literally true of the shipped binary, not merely true of its call graph.
//
// ===========================================================================================
// OPERATING IT
// ===========================================================================================
//
//	rmt-update-sign gen-key   -seed release-signing.key
//	     Generate a fresh 32-byte Ed25519 seed and print the PUBLIC key. That public hex is what
//	     goes into every agent's config.json as `update_signer_pubkey`
//	     (install-agent.ps1 -UpdateSignerPubkey). Treat the seed file the way you would treat a
//	     code-signing certificate: offline, backed up, and never copied to the control plane.
//
//	rmt-update-sign pubkey    -seed release-signing.key
//	     Print the public key for an existing seed, for provisioning a new machine.
//
//	rmt-update-sign sign      -seed release-signing.key -version 0.4.0 \
//	                          -binary dist/agent/agent_host.exe \
//	                          -url https://updates.example/rmt-agent-0.4.0.exe \
//	                          -min-upgradable-from 0.2.0 -valid-days 30 \
//	                          -out update-manifest.json
//	     Produce the signed manifest. `-binary` hashes the release locally; `-sha256` takes a digest
//	     you computed yourself. One or the other, never neither.
//
//	rmt-update-sign sign      -format 2 -seed release-signing.key -ring canary -version 0.1.0 \
//	                          -msi dist/DeskRallyAgent.msi \
//	                          -msi-url https://main.deskrally.com/download/agent/releases/0.1.0/DeskRallyAgent.msi \
//	                          -product-version 1.3.0 \
//	                          -product-code {11111111-2222-3333-4444-555555555555} \
//	                          -upgrade-code {7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C} \
//	                          -min-upgradable-from 0.1.0 -valid-days 30 -out update-manifest.json
//	     Produce a FORMAT 2 (MSI) manifest. `-format` defaults to 1, so every v1 invocation above is
//	     unchanged. `-msi` hashes the package locally; `-msi-sha256` takes a digest. Flags belonging
//	     to the other format are refused rather than silently ignored. The GUIDs must be braced and
//	     UPPERCASE (quote them in PowerShell/bash); the signer refuses anything the agent would.
//
//	rmt-update-sign verify    -in update-manifest.json -pubkey <64 hex>
//	     Check a manifest the way an agent would, against the key an agent has pinned. Works on
//	     both formats: a `"format":2` manifest is verified as v2, anything else as v1.
//
// ROTATION IS EXPENSIVE — read docs/21 §3 before doing it. A changed key means every enrolled agent
// refuses every update, silently, until someone edits config.json on each machine. There is no
// remote fix, because the mechanism you would use is the one that just stopped working.
//
// THE SEED IS NEVER TAKEN FROM A FLAG OR AN ENVIRONMENT VARIABLE, only from a file. A hex seed on a
// command line lands in shell history, in the process table where every local user can read it
// (`ps`, Task Manager's command-line column), and in any CI log that echoes its commands. For a key
// whose compromise is permanent ownership of the fleet, that is not a trade worth the convenience.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	controlplane "rmt/controlplane"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen-key":
		err = cmdGenKey(os.Args[2:])
	case "pubkey":
		err = cmdPubkey(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "rmt-update-sign: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `rmt-update-sign — offline signer for agent update manifests (docs/21 §3)

  gen-key -seed FILE
  pubkey  -seed FILE
  sign    -seed FILE -version V (-binary FILE | -sha256 HEX) -url URL
          -min-upgradable-from V [-valid-days N] [-issued-at-ms MS] [-out FILE]
  sign    -format 2 -seed FILE -ring canary|early|general -version V
          (-msi FILE | -msi-sha256 HEX) -msi-url URL -product-version A.B.C
          -product-code {GUID} -upgrade-code {GUID}
          -min-upgradable-from V [-valid-days N] [-issued-at-ms MS] [-out FILE]
  verify  -in FILE -pubkey HEX [-at-ms MS]

The signing key must NEVER be copied to the control plane. See the header of
control-plane/cmd/rmt-update-sign/main.go and docs/21 §3 for why.
`)
}

// -------------------------------------------------------------------------------------
// Seed handling
// -------------------------------------------------------------------------------------

// seedFileMode is what a fresh seed file is created with. On Windows the mode bits are largely
// advisory (the inherited ACL is what actually governs), so this is a floor rather than the
// control: the real instruction is the one in the header — keep the file off the server.
const seedFileMode os.FileMode = 0o600

// readSeed loads a 32-byte Ed25519 seed from a file containing its 64 hex characters.
//
// Strict about the shape on purpose. A seed file that silently tolerated stray content would let a
// truncated or partially-overwritten file produce a DIFFERENT valid key, and the first symptom
// would be a fleet that refuses every manifest — the failure docs/21 §3 says has no remote fix.
func readSeed(path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("-seed is required (the seed is never read from a flag or the environment)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read seed file: %w", err)
	}
	text := strings.TrimSpace(string(raw))
	if len(text) != 2*ed25519.SeedSize {
		return nil, fmt.Errorf("seed file %s holds %d characters, want %d hex characters",
			path, len(text), 2*ed25519.SeedSize)
	}
	seed, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("seed file %s is not hex: %w", path, err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func cmdGenKey(args []string) error {
	fs := flag.NewFlagSet("gen-key", flag.ExitOnError)
	path := fs.String("seed", "", "path to WRITE the new seed to (must not already exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*path) == "" {
		return errors.New("-seed is required")
	}
	// Refuse to overwrite. Silently replacing a release signing key would strand every agent that
	// pinned the old public half, with no remote way back.
	if _, err := os.Stat(*path); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite a signing key", *path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", *path, err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("generate seed: %w", err)
	}
	if err := os.WriteFile(*path, []byte(hex.EncodeToString(seed)+"\n"), seedFileMode); err != nil {
		return fmt.Errorf("write seed: %w", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	fmt.Printf("wrote %s (keep it OFFLINE — never copy it to the control plane)\n", *path)
	fmt.Printf("update_signer_pubkey = %s\n", hex.EncodeToString(pub))
	return nil
}

func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	path := fs.String("seed", "", "path to the seed file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := readSeed(*path)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return nil
}

// -------------------------------------------------------------------------------------
// sign
// -------------------------------------------------------------------------------------

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	format := fs.Int("format", 1, "manifest format: 1 (agent binary) or 2 (MSI)")
	seedPath := fs.String("seed", "", "path to the seed file")
	version := fs.String("version", "", "the version this release publishes, e.g. 0.4.0")
	shaHex := fs.String("sha256", "", "lowercase hex SHA-256 of the release binary (or use -binary)")
	binary := fs.String("binary", "", "path to the release binary, hashed locally (or use -sha256)")
	url := fs.String("url", "", "https:// URL the release binary will be served from")
	minFrom := fs.String("min-upgradable-from", "", "oldest running version permitted to take this upgrade")
	validDays := fs.Int("valid-days", 30, "how long the manifest stays valid, in days")
	issuedAtMs := fs.Int64("issued-at-ms", 0, "issue time in Unix milliseconds (default: now)")
	out := fs.String("out", "", "write the manifest here (default: stdout)")
	// Format 2 only.
	ring := fs.String("ring", "", "format 2: rollout ring (canary, early or general)")
	msi := fs.String("msi", "", "format 2: path to the MSI, hashed locally (or use -msi-sha256)")
	msiSHA := fs.String("msi-sha256", "", "format 2: lowercase hex SHA-256 of the MSI (or use -msi)")
	msiURL := fs.String("msi-url", "", "format 2: https:// URL the MSI will be served from")
	productVersion := fs.String("product-version", "", "format 2: MSI ProductVersion, A.B.C (A,B <= 255, C <= 65535)")
	productCode := fs.String("product-code", "", "format 2: MSI ProductCode, braced UPPERCASE GUID")
	upgradeCode := fs.String("upgrade-code", "", "format 2: MSI UpgradeCode, braced UPPERCASE GUID")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Each format's flags are refused under the other format. A flag that is silently ignored is a
	// release engineer signing something other than what they typed, so say so instead.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	v1Only := []string{"sha256", "binary", "url"}
	v2Only := []string{"ring", "msi", "msi-sha256", "msi-url", "product-version", "product-code", "upgrade-code"}
	switch *format {
	case 1:
		for _, n := range v2Only {
			if set[n] {
				return fmt.Errorf("-%s belongs to -format 2; this is a format 1 manifest", n)
			}
		}
	case 2:
		for _, n := range v1Only {
			if set[n] {
				return fmt.Errorf("-%s belongs to format 1; a format 2 manifest takes -msi, -msi-sha256 and -msi-url", n)
			}
		}
	default:
		return fmt.Errorf("-format must be 1 or 2, got %d", *format)
	}

	priv, err := readSeed(*seedPath)
	if err != nil {
		return err
	}
	var digest string
	if *format == 1 {
		digest, err = resolveDigest(*shaHex, *binary)
	} else {
		digest, err = resolveDigestNamed("msi-sha256", "msi", *msiSHA, *msi)
	}
	if err != nil {
		return err
	}
	if *validDays <= 0 {
		return errors.New("-valid-days must be positive: a manifest that is already expired is a manifest no agent will ever act on")
	}
	issued := *issuedAtMs
	if issued == 0 {
		issued = time.Now().UnixMilli()
	}
	expires := issued + int64(*validDays)*24*60*60*1000

	var js string
	if *format == 2 {
		js, err = buildSignedV2(priv, controlplane.ReleaseBodyV2{
			Ring:              *ring,
			Version:           *version,
			MSISHA256:         digest,
			MSIURL:            *msiURL,
			ProductVersion:    *productVersion,
			ProductCode:       *productCode,
			UpgradeCode:       *upgradeCode,
			MinUpgradableFrom: *minFrom,
		}, issued, expires)
	} else {
		js, err = buildSigned(priv, *version, digest, *url, *minFrom, issued, expires)
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(*out) == "" {
		fmt.Println(js)
		return nil
	}
	if err := os.WriteFile(*out, []byte(js+"\n"), 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (version %s, valid for %d day(s))\n", *out, *version, *validDays)
	fmt.Fprintf(os.Stderr, "place it at C:\\rmt-agent\\update-manifest.json on an agent whose "+
		"update_signer_pubkey is %s\n", hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
	return nil
}

// resolveDigest turns exactly one of -sha256 / -binary into the digest string.
//
// "Exactly one" is enforced rather than one silently winning. The digest is what step 3 will use to
// decide a downloaded file is the file that was signed for; a release engineer who passed both and
// got the one they did not mean would produce a manifest that fails on every machine at once.
func resolveDigest(shaHex, binaryPath string) (string, error) {
	return resolveDigestNamed("sha256", "binary", shaHex, binaryPath)
}

// resolveDigestNamed is resolveDigest with the flag names its errors quote, so format 2 can say
// -msi-sha256 / -msi instead of sending the operator to flags that do not apply.
func resolveDigestNamed(shaFlag, pathFlag, shaHex, binaryPath string) (string, error) {
	shaHex = strings.TrimSpace(shaHex)
	binaryPath = strings.TrimSpace(binaryPath)
	switch {
	case shaHex == "" && binaryPath == "":
		return "", fmt.Errorf("one of -%s or -%s is required", shaFlag, pathFlag)
	case shaHex != "" && binaryPath != "":
		return "", fmt.Errorf("pass -%s or -%s, not both", shaFlag, pathFlag)
	case shaHex != "":
		return shaHex, nil
	}
	f, err := os.Open(binaryPath)
	if err != nil {
		return "", fmt.Errorf("open -%s: %w", pathFlag, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash -%s: %w", pathFlag, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// buildSignedV2 is the format-2 twin of buildSigned, and the only other place in this repository
// that produces an Ed25519 signature over an update preimage. Same discipline: it refuses what the
// agent would refuse (UpdateManifestV2SigningBytes validates every field) and verifies its own
// output before returning it.
func buildSignedV2(priv ed25519.PrivateKey, r controlplane.ReleaseBodyV2, issuedAtMs, expiresAtMs int64) (string, error) {
	msg, err := controlplane.UpdateManifestV2SigningBytes(r, issuedAtMs, expiresAtMs)
	if err != nil {
		return "", err
	}
	m := controlplane.NewSignedUpdateManifestV2(r, issuedAtMs, expiresAtMs, ed25519.Sign(priv, msg))

	pub := priv.Public().(ed25519.PublicKey)
	if _, err := controlplane.VerifyUpdateManifestV2(pub, m, issuedAtMs); err != nil {
		return "", fmt.Errorf("the manifest just signed does not verify (%w) — refusing to emit it", err)
	}
	return m.JSON()
}

// buildSigned is the ONLY place in this repository that produces an Ed25519 signature over an
// update preimage. Kept as a plain function so a test can pin it against the cross-language golden
// vector without going through argv.
//
// It VERIFIES ITS OWN OUTPUT before returning. A signer that cannot check what it just produced is
// how a release goes out, gets published, and is discovered to be unusable when a fleet quietly
// stops updating — the failure docs/21 §0 calls unrecoverable by this channel. The check costs
// microseconds and uses the same verifier the agent's Rust twin mirrors.
func buildSigned(priv ed25519.PrivateKey, version, sha256Hex, url, minUpgradableFrom string, issuedAtMs, expiresAtMs int64) (string, error) {
	msg, err := controlplane.UpdateManifestSigningBytes(version, sha256Hex, url, minUpgradableFrom, issuedAtMs, expiresAtMs)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	m := controlplane.NewSignedUpdateManifest(controlplane.ReleaseBody{
		Version:           version,
		SHA256:            sha256Hex,
		URL:               url,
		MinUpgradableFrom: minUpgradableFrom,
	}, issuedAtMs, expiresAtMs, sig)

	pub := priv.Public().(ed25519.PublicKey)
	if _, err := controlplane.VerifyUpdateManifest(pub, m, issuedAtMs); err != nil {
		return "", fmt.Errorf("the manifest just signed does not verify (%w) — refusing to emit it", err)
	}
	return m.JSON()
}

// -------------------------------------------------------------------------------------
// verify
// -------------------------------------------------------------------------------------

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	in := fs.String("in", "", "path to a signed manifest")
	pubHex := fs.String("pubkey", "", "the update_signer_pubkey an agent has pinned (64 hex chars)")
	atMs := fs.Int64("at-ms", 0, "evaluate the validity window at this Unix millisecond (default: now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*in) == "" {
		return errors.New("-in is required")
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(*pubHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("-pubkey must be %d hex characters", 2*ed25519.PublicKeySize)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	now := *atMs
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	if manifestFormat(raw) == 2 {
		m2, err := decodeManifestV2(raw)
		if err != nil {
			return err
		}
		r2, err := controlplane.VerifyUpdateManifestV2(ed25519.PublicKey(pubBytes), m2, now)
		if err != nil {
			return err
		}
		fmt.Printf("OK  format=2 ring=%s version=%s product_version=%s min_upgradable_from=%s\n"+
			"    msi_sha256=%s\n    product_code=%s upgrade_code=%s\n    msi_url=%s\n",
			r2.Ring, r2.Version, r2.ProductVersion, r2.MinUpgradableFrom,
			r2.MSISHA256, r2.ProductCode, r2.UpgradeCode, r2.MSIURL)
		return nil
	}
	m, err := decodeManifest(raw)
	if err != nil {
		return err
	}
	r, err := controlplane.VerifyUpdateManifest(ed25519.PublicKey(pubBytes), m, now)
	if err != nil {
		return err
	}
	fmt.Printf("OK  version=%s sha256=%s min_upgradable_from=%s\n    url=%s\n",
		r.Version, r.SHA256, r.MinUpgradableFrom, r.URL)
	return nil
}

// decodeManifest is deliberately strict: an unknown field is an error rather than being ignored.
//
// The agent's Rust decoder is `#[serde(deny_unknown_fields)]` for the same reason, so a tool that
// accepted an unknown field here would print OK on a file no agent will read. "It verified on my
// laptop" is exactly the reassurance this feature must not hand out falsely. The underlying rule is
// fail-closed: every field of this artifact is signed and load-bearing, so a field the reader does
// not recognise means "this manifest asserts something I do not understand" — which is never a
// reason to proceed.
func decodeManifest(raw []byte) (controlplane.SignedUpdateManifest, error) {
	var m controlplane.SignedUpdateManifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("decode manifest: %w", err)
	}
	return m, nil
}

// manifestFormat peeks at the top-level `format` key without judging anything else: 2 means "decode
// and verify as format 2", anything else (absent, 1, garbage) falls through to the v1 path, whose
// strict decoder then refuses whatever is not a v1 manifest. Lax on purpose: it only routes.
func manifestFormat(raw []byte) int {
	var peek struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(raw, &peek); err != nil {
		return 0
	}
	return peek.Format
}

// decodeManifestV2 is decodeManifest's format-2 twin, strict for the same reason. DisallowUnknownFields
// is not enough here (it still accepts case-variant and duplicate keys, nulls, missing fields and
// trailing data, all of which serde refuses), so the package's exact-key decoder does the work.
func decodeManifestV2(raw []byte) (controlplane.SignedUpdateManifestV2, error) {
	m, err := controlplane.DecodeSignedUpdateManifestV2(raw)
	if err != nil {
		return m, fmt.Errorf("decode manifest: %w", err)
	}
	return m, nil
}

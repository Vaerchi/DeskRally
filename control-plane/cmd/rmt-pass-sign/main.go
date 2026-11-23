// Command rmt-pass-sign issues DeskRally deployment passes and agent release attestations
// (docs/48 C). It runs ONLY on DeskRally's signing workstation, by a person, never as a service.
//
// A pass lets DeskRally's signed generic Setup and Support work against one customer server for at
// most 31 days. Issuing one is a security boundary (docs/48 "Issuance policy"): the signed tools
// will then install agents and run support sessions for that origin. So:
//
//   - the root key lives in a DPAPI (current user) file with an owner-only DACL, created
//     exclusively by gen-key, and is never read from a flag or the environment;
//   - issue performs the domain-control check itself: the customer's server must serve, at
//     https://<origin>/.well-known/deskrally-pass-challenge, a nonce that `challenge` recorded on
//     this workstation for that origin, unexpired (72 h) and never used before. The only way round
//     it is -lab-skip-domain-check, which is refused for any host outside the reserved lab names
//     (localhost, *.localhost, *.test), so it cannot mint a pass for a real domain;
//   - every issue is appended to an issuance log beside the key, so who holds a pass is recorded;
//   - every command verifies its own output with the same verifier the control plane uses, before
//     writing it.
//
// The format, field rules and verifier live in package controlplane (deployment_pass.go); signing
// lives only here (TestDeploymentPassPackageCannotSign).
//
//	rmt-pass-sign gen-key   -key root.key
//	rmt-pass-sign pubkey    -key root.key
//	rmt-pass-sign challenge -key root.key -origin https://remote.example.com
//	rmt-pass-sign issue     -key root.key -to "Example MSP" -origin https://remote.example.com \
//	                        -grant-issuer-pubkey <64 hex> -min-agent-version 1.3.5 \
//	                        -challenge <nonce> [-days 31] [-uses setup,support] -out deployment-pass.json
//	rmt-pass-sign attest    -key root.key -msi DeskRallyAgent.msi -product-version 1.3.5 \
//	                        -product-code {GUID} -upgrade-code {GUID} [-days 365] -out agent-release.json
//	rmt-pass-sign verify    -kind pass|release -in FILE -pubkey <130 hex> [-at 2026-10-19T00:00:00Z]
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	args := os.Args[2:]
	switch os.Args[1] {
	case "gen-key":
		err = cmdGenKey(args)
	case "pubkey":
		err = cmdPubkey(args)
	case "challenge":
		err = cmdChallenge(args)
	case "issue":
		err = cmdIssue(args)
	case "attest":
		err = cmdAttest(args)
	case "export-key":
		err = cmdExportKey(args)
	case "import-key":
		err = cmdImportKey(args)
	case "verify":
		err = cmdVerify(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "rmt-pass-sign: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `rmt-pass-sign: deployment passes and agent release attestations (docs/48 C)

  gen-key   -key FILE
  pubkey    -key FILE
  challenge -key FILE -origin https://HOST[:PORT]
  issue     -key FILE -to NAME -origin https://HOST[:PORT] -grant-issuer-pubkey HEX
            -min-agent-version A.B.C (-challenge NONCE | -lab-skip-domain-check)
            [-days N<=31] [-uses setup,support] [-log FILE] -out FILE
  attest    -key FILE -msi FILE -product-version A.B.C -product-code {GUID} -upgrade-code {GUID}
            [-days N<=396] -out FILE
  verify    -kind pass|release -in FILE -pubkey HEX [-at YYYY-MM-DDTHH:MM:SSZ]
  export-key -key FILE -out BACKUP     passphrase-encrypted offline backup (asks twice, no echo)
  import-key -backup BACKUP -key FILE  restore a backup into a new DPAPI key file

The root key file never leaves the signing workstation; see the header of
control-plane/cmd/rmt-pass-sign/main.go and docs/48 "Key custody".
`)
}

// now is the issue time; tests pin it.
var now = func() time.Time { return time.Now().UTC().Truncate(time.Second) }

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("-key is required (the root key is only ever read from its file)")
	}
	scalar, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		return nil, fmt.Errorf("%s does not hold a valid P-256 key: %w", path, err)
	}
	return k, nil
}

func cmdGenKey(args []string) error {
	fs := flag.NewFlagSet("gen-key", flag.ExitOnError)
	path := fs.String("key", "", "path to CREATE the root key file at (must not exist)")
	fs.Parse(args)
	if strings.TrimSpace(*path) == "" {
		return errors.New("-key is required")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	scalar, err := k.Bytes()
	if err != nil {
		return err
	}
	if err := writeKeyFile(*path, scalar); err != nil {
		return err
	}
	// Prove the file reads back as the same key before anyone pins its public half.
	back, err := loadKey(*path)
	if err != nil || !back.PublicKey.Equal(&k.PublicKey) {
		return fmt.Errorf("the key file just written does not read back (%v); delete it and retry", err)
	}
	pub, _ := controlplane.DeploymentRootKeyHex(&k.PublicKey)
	fmt.Printf("wrote %s (DPAPI, this Windows account only; never copy it to a server)\n", *path)
	fmt.Printf("pass_root_pubkey = %s\n", pub)
	return nil
}

func cmdPubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	path := fs.String("key", "", "root key file")
	fs.Parse(args)
	k, err := loadKey(*path)
	if err != nil {
		return err
	}
	pub, _ := controlplane.DeploymentRootKeyHex(&k.PublicKey)
	fmt.Println(pub)
	return nil
}

// ---------------------------------------------------------------------------------------------
// Domain control
// ---------------------------------------------------------------------------------------------

const challengePath = "/.well-known/deskrally-pass-challenge"

func newNonce() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// A nonce proves domain control only if THIS workstation minted it, for THIS origin, recently, and
// it has not been used before. So challenge records each nonce in pass-challenges.jsonl beside the
// key (bound to its origin, with an expiry), and issue accepts only a recorded, unexpired, unused
// nonce for the same origin, then records it as consumed before signing.
const challengeTTL = 72 * time.Hour

type challengeEvent struct {
	Event     string `json:"event"` // "issued" or "consumed"
	Nonce     string `json:"nonce"`
	Origin    string `json:"origin,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func challengeStatePath(keyPath string) string {
	return filepath.Join(filepath.Dir(keyPath), "pass-challenges.jsonl")
}

// appendSynced appends one JSON line and flushes it to disk before returning.
func appendSynced(path string, v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func createChallenge(statePath, origin string) (string, error) {
	if err := controlplane.CheckDeploymentOrigin(origin); err != nil {
		return "", fmt.Errorf("-origin: %v", err)
	}
	n := newNonce()
	ev := challengeEvent{Event: "issued", Nonce: n, Origin: origin, ExpiresAt: now().Add(challengeTTL).Format(controlplane.PassTimeLayout)}
	if err := appendSynced(statePath, ev); err != nil {
		return "", fmt.Errorf("record challenge: %w", err)
	}
	return n, nil
}

// pendingChallenge checks that nonce was issued here for origin, is unexpired and is unused.
func pendingChallenge(statePath, origin, nonce string) error {
	if len(nonce) != 64 || strings.Trim(nonce, "0123456789abcdef") != "" {
		return errors.New("-challenge must be the 64-hex nonce printed by `rmt-pass-sign challenge`")
	}
	raw, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no challenge has been issued on this workstation: run `rmt-pass-sign challenge` first")
	} else if err != nil {
		return err
	}
	var issued *challengeEvent
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev challengeEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return fmt.Errorf("%s is damaged: %v", statePath, err)
		}
		if ev.Nonce != nonce {
			continue
		}
		switch ev.Event {
		case "issued":
			e := ev
			issued = &e
		case "consumed":
			return errors.New("this challenge was already used for a pass: run `rmt-pass-sign challenge` again")
		}
	}
	if issued == nil {
		return errors.New("this nonce was not issued by `rmt-pass-sign challenge` on this workstation")
	}
	if issued.Origin != origin {
		return fmt.Errorf("this challenge was issued for %s, not %s", issued.Origin, origin)
	}
	exp, err := time.Parse(controlplane.PassTimeLayout, issued.ExpiresAt)
	if err != nil || !now().Before(exp) {
		return errors.New("this challenge has expired: run `rmt-pass-sign challenge` again")
	}
	return nil
}

func cmdChallenge(args []string) error {
	fs := flag.NewFlagSet("challenge", flag.ExitOnError)
	keyPath := fs.String("key", "", "root key file (the challenge record is kept beside it)")
	origin := fs.String("origin", "", "the customer's server, exactly https://host[:port]")
	fs.Parse(args)
	if strings.TrimSpace(*keyPath) == "" {
		return errors.New("-key is required")
	}
	n, err := createChallenge(challengeStatePath(*keyPath), *origin)
	if err != nil {
		return err
	}
	fmt.Printf("nonce: %s\n\nAsk the customer to serve exactly this text (a trailing newline is fine) at\n"+
		"  %s%s\nwithin %s, then run issue with -origin %s -challenge %s\n", n, *origin, challengePath, challengeTTL, *origin, n)
	return nil
}

// challengeClient is the HTTP client for the domain check: normal TLS verification, no redirects
// (a redirect could hand the check to a host the customer does not control). Tests replace it.
var challengeClient = func() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not followed for the domain check")
		},
	}
}

// checkDomain fetches the challenge from origin. The caller has already checked, with
// pendingChallenge, that nonce is a fresh one this workstation issued for origin.
func checkDomain(ctx context.Context, origin, nonce string) error {
	if len(nonce) != 64 || strings.Trim(nonce, "0123456789abcdef") != "" {
		return errors.New("-challenge must be the 64-hex nonce printed by `rmt-pass-sign challenge`")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+challengePath, nil)
	if err != nil {
		return err
	}
	resp, err := challengeClient().Do(req)
	if err != nil {
		return fmt.Errorf("domain check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("domain check: %s%s answered %s", origin, challengePath, resp.Status)
	}
	got, err := io.ReadAll(io.LimitReader(resp.Body, 1025))
	if err != nil {
		return fmt.Errorf("domain check: %w", err)
	}
	text := strings.TrimSuffix(strings.TrimSuffix(string(got), "\n"), "\r")
	if text != nonce {
		return fmt.Errorf("domain check: %s%s does not serve this nonce, so control of the origin is not shown", origin, challengePath)
	}
	return nil
}

// labHost reports whether origin's host is a reserved name no customer can own (RFC 6761). It is
// the control plane's rule, so the signer's lab skip and the server's test-root limit cannot drift.
func labHost(origin string) bool { return controlplane.IsLabOrigin(origin) }

// ---------------------------------------------------------------------------------------------
// issue / attest
// ---------------------------------------------------------------------------------------------

func sign(k *ecdsa.PrivateKey, domain string, body []byte) ([]byte, error) {
	d := controlplane.SignedObjectDigest(domain, body)
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	if err != nil {
		return nil, err
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return controlplane.EncodeSignedObject(body, sig), nil
}

func mustNotExist(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists: refusing to overwrite it", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// writeNew writes exactly data to an output file that must not already exist, and syncs it.
func writeNew(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("-out is required")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// fileBytes is the exact content written for a signed object: the envelope plus one newline,
// which the envelope grammar allows. Verification, hashing and writing all use these bytes.
func fileBytes(env []byte) []byte { return append(append([]byte{}, env...), '\n') }

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	keyPath := fs.String("key", "", "root key file")
	to := fs.String("to", "", "the accountable customer's name (1-64 of A-Z a-z 0-9 space . , & ' ( ) -)")
	origin := fs.String("origin", "", "the customer's server, exactly https://host[:port]")
	grant := fs.String("grant-issuer-pubkey", "", "the customer's grant issuer public key (64 hex)")
	minVer := fs.String("min-agent-version", "", "the oldest agent MSI ProductVersion Setup may install (A.B.C)")
	uses := fs.String("uses", "setup,support", "comma list: setup, support")
	days := fs.Int("days", 31, "lifetime in days (at most 31)")
	nonce := fs.String("challenge", "", "the nonce from `rmt-pass-sign challenge`, served by the customer")
	labSkip := fs.Bool("lab-skip-domain-check", false, "skip the domain check; only for localhost, *.localhost and *.test")
	logPath := fs.String("log", "", "issuance log (default: pass-issuance-log.jsonl beside the key file)")
	out := fs.String("out", "", "write the pass here (must not exist)")
	fs.Parse(args)

	if *days < 1 || *days > 31 {
		return errors.New("-days must be 1-31: revoking a pass means not renewing it")
	}
	// Refuse an existing -out before the domain check, signing and logging, so the issuance log
	// never records a pass that was then not written. writeNew still creates it exclusively.
	if err := mustNotExist(*out); err != nil {
		return err
	}
	p := controlplane.DeploymentPassClaims{
		PassID: newUUID(), IssuedTo: *to, Origin: *origin, GrantIssuerPubkey: *grant,
		MinAgentVersion: *minVer, IssuedAt: now(),
	}
	p.ExpiresAt = p.IssuedAt.Add(time.Duration(*days) * 24 * time.Hour)
	for _, u := range strings.Split(*uses, ",") {
		switch strings.TrimSpace(u) {
		case "setup":
			p.ForSetup = true
		case "support":
			p.ForSupport = true
		default:
			return fmt.Errorf("-uses: %q is not setup or support", u)
		}
	}
	body, err := controlplane.EncodeDeploymentPassBody(p)
	if err != nil {
		return err
	}
	if *labSkip {
		if !labHost(p.Origin) {
			return fmt.Errorf("-lab-skip-domain-check is only for localhost, *.localhost and *.test; %s needs the domain check", p.Origin)
		}
		if *nonce != "" {
			return errors.New("pass -challenge or -lab-skip-domain-check, not both")
		}
		fmt.Fprintln(os.Stderr, "WARNING: domain check skipped for a reserved lab host")
	} else {
		if strings.TrimSpace(*keyPath) == "" {
			return errors.New("-key is required")
		}
		state := challengeStatePath(*keyPath)
		// One issue at a time holds the challenge record from the pending check to durable
		// consumption, so two concurrent issues can never both spend one nonce.
		unlock, err := lockFile(state + ".lock")
		if err != nil {
			return fmt.Errorf("lock the challenge record: %w", err)
		}
		defer unlock()
		if err := pendingChallenge(state, p.Origin, *nonce); err != nil {
			return err
		}
		if err := checkDomain(context.Background(), p.Origin, *nonce); err != nil {
			return err
		}
		// Re-check after the network round trip (the challenge may have expired meanwhile), then
		// consume it before signing: a nonce proves control for one issue only.
		if err := pendingChallenge(state, p.Origin, *nonce); err != nil {
			return err
		}
		if err := appendSynced(state, challengeEvent{Event: "consumed", Nonce: *nonce}); err != nil {
			return fmt.Errorf("record challenge use: %w", err)
		}
	}
	k, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	env, err := sign(k, controlplane.DeploymentPassDomain, body)
	if err != nil {
		return err
	}
	final := fileBytes(env)
	back, err := controlplane.VerifyDeploymentPass(&k.PublicKey, final, p.IssuedAt)
	if err != nil || back.Claims() != p {
		return fmt.Errorf("the pass just signed does not verify (%v): refusing to write it", err)
	}
	if *logPath == "" {
		*logPath = filepath.Join(filepath.Dir(*keyPath), "pass-issuance-log.jsonl")
	}
	sum := sha256.Sum256(final)
	// Log, synced, before writing the pass, so no pass exists that the log does not record.
	if err := appendSynced(*logPath, map[string]any{
		"pass_id": p.PassID, "issued_to": p.IssuedTo, "origin": p.Origin, "uses": *uses,
		"min_agent_version": p.MinAgentVersion, "issued_at": p.IssuedAt.Format(controlplane.PassTimeLayout),
		"expires_at": p.ExpiresAt.Format(controlplane.PassTimeLayout), "domain_check": !*labSkip,
		"pass_sha256": hex.EncodeToString(sum[:]),
	}); err != nil {
		return fmt.Errorf("issuance log: %w", err)
	}
	if err := writeNew(*out, final); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n  pass_id   %s\n  issued_to %s\n  origin    %s\n  expires   %s\n",
		*out, p.PassID, p.IssuedTo, p.Origin, p.ExpiresAt.Format(controlplane.PassTimeLayout))
	return nil
}

func cmdAttest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ExitOnError)
	keyPath := fs.String("key", "", "root key file")
	msi := fs.String("msi", "", "the published DeskRallyAgent.msi, hashed and sized locally")
	pv := fs.String("product-version", "", "its MSI ProductVersion (A.B.C)")
	pc := fs.String("product-code", "", "its ProductCode, braced UPPERCASE GUID")
	uc := fs.String("upgrade-code", "", "its UpgradeCode, braced UPPERCASE GUID")
	days := fs.Int("days", 365, "lifetime in days (at most 396)")
	out := fs.String("out", "", "write the attestation here (must not exist)")
	fs.Parse(args)

	if *days < 1 || *days > 396 {
		return errors.New("-days must be 1-396")
	}
	f, err := os.Open(*msi)
	if err != nil {
		return fmt.Errorf("-msi: %w", err)
	}
	h := sha256.New()
	size, err := io.Copy(h, f)
	f.Close()
	if err != nil {
		return fmt.Errorf("hash -msi: %w", err)
	}
	if err := mustNotExist(*out); err != nil {
		return err
	}
	r := controlplane.AgentReleaseClaims{
		MSISHA256: hex.EncodeToString(h.Sum(nil)), MSISize: size, ProductVersion: *pv,
		ProductCode: *pc, UpgradeCode: *uc, Arch: "x64", IssuedAt: now(),
	}
	r.ExpiresAt = r.IssuedAt.Add(time.Duration(*days) * 24 * time.Hour)
	body, err := controlplane.EncodeAgentReleaseBody(r)
	if err != nil {
		return err
	}
	k, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	env, err := sign(k, controlplane.AgentReleaseDomain, body)
	if err != nil {
		return err
	}
	final := fileBytes(env)
	back, err := controlplane.VerifyAgentRelease(&k.PublicKey, final, r.IssuedAt)
	if err != nil || back.Claims() != r {
		return fmt.Errorf("the attestation just signed does not verify (%v): refusing to write it", err)
	}
	if err := writeNew(*out, final); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n  msi_sha256 %s\n  msi_size   %d\n  version    %s\n  expires    %s\n",
		*out, r.MSISHA256, r.MSISize, r.ProductVersion, r.ExpiresAt.Format(controlplane.PassTimeLayout))
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	kind := fs.String("kind", "", "pass or release")
	in := fs.String("in", "", "the signed file")
	pubHex := fs.String("pubkey", "", "the pass root public key (130 hex)")
	at := fs.String("at", "", "evaluate validity at this time (default: now)")
	fs.Parse(args)
	pub, err := controlplane.ParseDeploymentRootKey(strings.TrimSpace(*pubHex))
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	// No trimming: the envelope grammar already allows whitespace (the signer's trailing newline),
	// and this must read the file exactly as Setup, Support and the control plane will.
	t := time.Now().UTC()
	if *at != "" {
		if t, err = time.Parse(controlplane.PassTimeLayout, *at); err != nil {
			return fmt.Errorf("-at: %w", err)
		}
	}
	switch *kind {
	case "pass":
		p, err := controlplane.VerifyDeploymentPass(pub, raw, t)
		if err != nil {
			return err
		}
		fmt.Printf("OK  pass %s\n  issued_to %s\n  server    %s (control plane %s, signaling %s)\n  uses      setup=%v support=%v\n  min agent %s\n  valid     %s .. %s\n",
			p.Claims().PassID, p.Claims().IssuedTo, p.HostPort(), p.ControlPlaneURL(), p.SignalingURL(), p.Claims().ForSetup, p.Claims().ForSupport,
			p.Claims().MinAgentVersion, p.Claims().IssuedAt.Format(controlplane.PassTimeLayout), p.Claims().ExpiresAt.Format(controlplane.PassTimeLayout))
	case "release":
		r, err := controlplane.VerifyAgentRelease(pub, raw, t)
		if err != nil {
			return err
		}
		fmt.Printf("OK  agent release %s\n  msi_sha256 %s (%d bytes)\n  codes      %s %s\n  valid      %s .. %s\n",
			r.Claims().ProductVersion, r.Claims().MSISHA256, r.Claims().MSISize, r.Claims().ProductCode, r.Claims().UpgradeCode,
			r.Claims().IssuedAt.Format(controlplane.PassTimeLayout), r.Claims().ExpiresAt.Format(controlplane.PassTimeLayout))
	default:
		return errors.New("-kind must be pass or release")
	}
	return nil
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

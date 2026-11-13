package controlplane

// Deployment-pass mode for the managed installer (docs/48 C, "The customer's server"; slice 3).
//
// In pass mode the installer directory holds DeskRally's GENERIC signed Setup (and Support), which
// carry no server values. What binds them to this server is a deployment pass signed by DeskRally's
// root key, and what binds the agent MSI is a release attestation from the same key. The control
// plane serves both files inside its bundles. Before that, at startup, it checks that they describe
// THIS server and THIS MSI, so a misconfigured server fails loudly instead of handing guests a pass
// for another origin or an MSI that Setup will refuse.
//
// What is fatal at startup, and what is not:
//   - fatal: a bad signature, the wrong root key, an origin, signaling URL or grant key that is not
//     this server's, an MSI whose hash or size differs from the attestation, a release older than
//     the pass's min_agent_version, a pass that does not cover what the directory serves, and any
//     mixing of baked and pass configuration;
//   - NOT fatal: an expired (or not yet valid) pass or attestation. Lapsing is how a pass is
//     revoked, and docs/48 scopes that to new installs and support launches. If an expired pass
//     stopped the control plane from starting, the next restart would take every enrolled agent
//     and live session down with it. So the server starts, logs the lapse, shows it to admins, and
//     refuses every bundle with a 503 until the pass is renewed.
//
// The control plane's own checks are consistency checks, not the security boundary: Setup and
// Support verify the pass themselves against the root key compiled into THEM.

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// deploymentPassProductionRootKey is DeskRally's pass root public key (SEC1 uncompressed P-256,
// 130 lowercase hex). EMPTY until the root key ceremony (docs/48 "Key custody"); until then pass
// mode starts only with an explicit test root key, which may only authorize lab origins.
const deploymentPassProductionRootKey = ""

// DeploymentPassRootKey returns the compiled-in production root key.
func DeploymentPassRootKey() (*ecdsa.PublicKey, error) {
	if deploymentPassProductionRootKey == "" {
		return nil, errors.New("this build has no production deployment-pass root key yet; pass mode needs CP_DEPLOYMENT_PASS_TEST_ROOT_KEY (lab origins only)")
	}
	return ParseDeploymentRootKey(deploymentPassProductionRootKey)
}

// IsLabOrigin reports whether origin's host is a reserved name no customer can own (RFC 6761):
// localhost, *.localhost or *.test. A test root key may only authorize such origins, and the
// signer's -lab-skip-domain-check uses the same rule.
func IsLabOrigin(origin string) bool {
	host := strings.TrimPrefix(origin, "https://")
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".test")
}

// ManagedInstallerConfig is everything LoadManagedInstallerConfig needs. The pass fields are empty
// for a baked deployment.
type ManagedInstallerConfig struct {
	Dir               string
	ControlPlaneURL   string // CP_MANAGED_INSTALL_CONTROL_PLANE_URL: https://host[:port]/cp
	SignalingURL      string // CP_SIGNALING_URL: wss://host[:port]/ws
	GrantIssuerPubkey string

	DeploymentPassFile string           // CP_DEPLOYMENT_PASS_FILE
	AgentReleaseFile   string           // CP_AGENT_RELEASE_ATTESTATION_FILE
	PassRoot           *ecdsa.PublicKey // the root key passes must verify under
	TestRoot           bool             // PassRoot came from CP_DEPLOYMENT_PASS_TEST_ROOT_KEY
	Now                func() time.Time // nil = time.Now
}

// PassModeError is a pass-mode startup refusal. Unlike the deliberately opaque baked-mode error,
// it says which check failed: none of these details is secret, and an operator who renewed a pass
// needs to know what is wrong with it.
type PassModeError struct{ msg string }

func (e *PassModeError) Error() string { return "deployment pass mode: " + e.msg }

func passErr(format string, a ...any) error { return &PassModeError{msg: fmt.Sprintf(format, a...)} }

// readSignedFile reads a pass or attestation: a regular file of at most MaxSignedObjectBytes.
func readSignedFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > MaxSignedObjectBytes {
		return nil, fmt.Errorf("not a regular file of at most %d bytes", MaxSignedObjectBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSignedObjectBytes+1))
	if err != nil || len(b) > MaxSignedObjectBytes {
		return nil, fmt.Errorf("not a regular file of at most %d bytes", MaxSignedObjectBytes)
	}
	return b, nil
}

// verifySignedIgnoringClock runs every check except the clock (check 5). The window is applied
// later, at startup for a warning and at every bundle issuance for a refusal.
func verifyPassIgnoringClock(root *ecdsa.PublicKey, raw []byte) (DeploymentPass, error) {
	body, err := openSignedObject(root, DeploymentPassDomain, raw)
	if err != nil {
		return DeploymentPass{}, err
	}
	c, err := parseDeploymentPassBody(body)
	if err != nil {
		return DeploymentPass{}, err
	}
	return DeploymentPass{c: c, ok: true}, nil
}

func verifyReleaseIgnoringClock(root *ecdsa.PublicKey, raw []byte) (AgentRelease, error) {
	body, err := openSignedObject(root, AgentReleaseDomain, raw)
	if err != nil {
		return AgentRelease{}, err
	}
	c, err := parseAgentReleaseBody(body)
	if err != nil {
		return AgentRelease{}, err
	}
	return AgentRelease{c: c, ok: true}, nil
}

// loadPassMode completes a pass-mode installer: m already holds the hash-checked artifacts.
func loadPassMode(m *ManagedInstaller, cfg ManagedInstallerConfig) error {
	if cfg.DeploymentPassFile == "" || cfg.AgentReleaseFile == "" {
		return passErr("installer-manifest.json is \"mode\":\"pass\", so CP_DEPLOYMENT_PASS_FILE and CP_AGENT_RELEASE_ATTESTATION_FILE are both required")
	}
	if cfg.PassRoot == nil {
		return passErr("no root key to verify the pass with")
	}
	passRaw, err := readSignedFile(cfg.DeploymentPassFile)
	if err != nil {
		return passErr("CP_DEPLOYMENT_PASS_FILE: %v", err)
	}
	relRaw, err := readSignedFile(cfg.AgentReleaseFile)
	if err != nil {
		return passErr("CP_AGENT_RELEASE_ATTESTATION_FILE: %v", err)
	}
	pass, err := verifyPassIgnoringClock(cfg.PassRoot, passRaw)
	if err != nil {
		return passErr("CP_DEPLOYMENT_PASS_FILE does not verify: %v", err)
	}
	rel, err := verifyReleaseIgnoringClock(cfg.PassRoot, relRaw)
	if err != nil {
		return passErr("CP_AGENT_RELEASE_ATTESTATION_FILE does not verify: %v", err)
	}
	pc, rc := pass.Claims(), rel.Claims()
	if cfg.TestRoot && !IsLabOrigin(pc.Origin) {
		return passErr("a test root key may only authorize lab origins (localhost, *.localhost, *.test), not %s", pc.Origin)
	}
	if pass.ControlPlaneURL() != cfg.ControlPlaneURL {
		return passErr("the pass is for %s, but this server's CP_MANAGED_INSTALL_CONTROL_PLANE_URL is %s", pass.ControlPlaneURL(), cfg.ControlPlaneURL)
	}
	if pass.SignalingURL() != cfg.SignalingURL {
		return passErr("the pass derives signaling %s, but this server's CP_SIGNALING_URL is %s", pass.SignalingURL(), cfg.SignalingURL)
	}
	if pc.GrantIssuerPubkey != strings.ToLower(cfg.GrantIssuerPubkey) {
		return passErr("the pass names grant issuer key %s, not this server's", pc.GrantIssuerPubkey)
	}
	if !pc.ForSetup {
		return passErr("the pass does not cover setup, but this installer directory serves Setup")
	}
	if len(m.support) > 0 && !pc.ForSupport {
		return passErr("the pass does not cover support, but this installer directory serves DeskRallySupport.exe")
	}
	if rc.MSISize != int64(len(m.msi)) || rc.MSISHA256 != sha256Hex(m.msi) {
		return passErr("the release attestation (%s, %d bytes) is not for the DeskRallyAgent.msi this server serves (%s, %d bytes)",
			rc.MSISHA256, rc.MSISize, sha256Hex(m.msi), len(m.msi))
	}
	if err := PassAdmitsRelease(pass, rel); err != nil {
		return passErr("%v", err)
	}
	m.passRaw, m.releaseRaw, m.pass, m.agentRelease = passRaw, relRaw, pass, rel
	return nil
}

// PassMode reports whether this installer serves generic binaries bound by a deployment pass.
func (m *ManagedInstaller) PassMode() bool { return m.pass.Verified() }

func (m *ManagedInstaller) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// issuanceRefusal is checked on every bundle request BEFORE any credential is minted, on the
// server's own clock. An install bundle needs a valid pass and a valid release attestation; a
// support bundle needs only the pass. Baked mode never refuses here.
func (m *ManagedInstaller) issuanceRefusal(install bool) string {
	if !m.PassMode() {
		return ""
	}
	now := m.clock()
	if err := m.pass.CheckValidAt(now); err != nil {
		if now.Before(m.pass.Claims().IssuedAt) {
			return "deployment pass is not valid yet"
		}
		return "deployment pass expired"
	}
	if install {
		if err := m.agentRelease.CheckValidAt(now); err != nil {
			if now.Before(m.agentRelease.Claims().IssuedAt) {
				return "agent release attestation is not valid yet"
			}
			return "agent release attestation expired"
		}
	} else if !m.pass.Claims().ForSupport {
		return "deployment pass does not cover support"
	}
	return ""
}

// passWarningWindow is how long before expiry admins are warned (docs/48).
const passWarningWindow = 7 * 24 * time.Hour

// PassWarnings lists what an admin should act on: a lapsed or soon-lapsing pass or attestation.
func (m *ManagedInstaller) PassWarnings() []string {
	if !m.PassMode() {
		return nil
	}
	now := m.clock()
	var out []string
	for _, it := range []struct {
		what            string
		gates           string // what a lapse refuses: the pass gates both, the attestation installs only
		issued, expires time.Time
	}{
		{"deployment pass", "new installs and support bundles", m.pass.Claims().IssuedAt, m.pass.Claims().ExpiresAt},
		{"agent release attestation", "new installs", m.agentRelease.Claims().IssuedAt, m.agentRelease.Claims().ExpiresAt},
	} {
		switch {
		case !now.Before(it.expires):
			out = append(out, fmt.Sprintf("The %s expired at %s. %s are refused until it is renewed.", it.what, it.expires.Format(PassTimeLayout), capitalize(it.gates)))
		case now.Before(it.issued.Add(-SignedObjectClockSkew)):
			out = append(out, fmt.Sprintf("The %s is not valid until %s; check this server's clock. %s are refused until then.", it.what, it.issued.Format(PassTimeLayout), capitalize(it.gates)))
		case it.expires.Sub(now) <= passWarningWindow:
			out = append(out, fmt.Sprintf("The %s expires at %s. Renew it before then, or %s will be refused.", it.what, it.expires.Format(PassTimeLayout), it.gates))
		}
	}
	return out
}

// handleAttendedSupportMode tells the public join page whether only the session bundle works:
// true in deployment-pass mode, where the standalone support exe is generic and needs the pass that
// only the bundle carries. Nothing else about the pass is exposed.
func (s *Server) handleAttendedSupportMode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	bundleOnly := s.ManagedInstaller != nil && s.ManagedInstaller.PassMode()
	writeJSON(w, http.StatusOK, map[string]bool{"bundle_only": bundleOnly})
}

// passStatus is the admin-visible part of GET /managed-installer.
func (m *ManagedInstaller) passStatus() map[string]any {
	pc, rc := m.pass.Claims(), m.agentRelease.Claims()
	warnings := m.PassWarnings()
	if warnings == nil {
		warnings = []string{}
	}
	return map[string]any{
		"pass_id":            pc.PassID,
		"issued_to":          pc.IssuedTo,
		"pass_expires_at":    pc.ExpiresAt.Format(PassTimeLayout),
		"agent_version":      rc.ProductVersion,
		"release_expires_at": rc.ExpiresAt.Format(PassTimeLayout),
		"warnings":           warnings,
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

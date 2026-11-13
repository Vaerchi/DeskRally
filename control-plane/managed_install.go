package controlplane

// Opt-in managed installation. Artifacts are validated and snapshotted at startup, never built
// from a request. Each authenticated download adds one short-lived, single-use enrollment token.
import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const managedInstallTTL = 15 * time.Minute
const maxInstallerArtifact = 128 << 20

type installerManifest struct {
	Version              int    `json:"version"`
	ControlPlaneURL      string `json:"control_plane_url"`
	SignalingURL         string `json:"signaling_url"`
	GrantIssuerPubkey    string `json:"grant_issuer_pubkey"`
	RequireSessionPolicy bool   `json:"require_session_policy"`
	MSISHA256            string `json:"msi_sha256"`
	SetupSHA256          string `json:"setup_sha256"`
	// SupportSHA256 is optional: when set, LoadManagedInstaller loads DeskRallySupport.exe and
	// hash-checks it, enabling the /attended-sessions/support-bundle endpoint. Absent (zero
	// value "") means no support exe is bundled — the endpoint returns 503 and the guest falls
	// back to the manual download + typed code. Backward-compatible: old manifests without this
	// field get "" and lose only the bundle endpoint, not the full managed installer.
	SupportSHA256 string `json:"support_sha256,omitempty"`
	// Mode is absent for a baked release (unchanged behaviour) or "pass" for generic binaries bound
	// by a deployment pass (managed_install_pass.go). In pass mode the URL fields are absent and the
	// server's identity comes from the pass. The manifest is never an authentication source.
	Mode string `json:"mode,omitempty"`
}

func sha256Hex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type ManagedInstaller struct {
	msi, setup, support []byte
	// Pass mode only (managed_install_pass.go): the verified pass and attestation, and their exact
	// file bytes, which go into the bundles unchanged.
	pass                DeploymentPass
	agentRelease        AgentRelease
	passRaw, releaseRaw []byte
	now                 func() time.Time // nil = time.Now; tests move the clock
	mu                  sync.Mutex
	active              int
	credits             float64
	last                time.Time
	// The ANONYMOUS support-bundle downloads get their own allowances, separate from the one above
	// (security audit 2026-10-18: sharing let anyone keep every technician's download at 429).
	// Per-IP / per-code budgets that the anonymous support-bundle route charges BEFORE this global
	// allowance (managed_install_limits.go, audit 2026-11-01 #11/#15).
	supportLim supportLimits
}

// SupportAvailable reports whether the support bundle endpoint is usable: only when a support
// exe was loaded and hash-checked at startup.
func (m *ManagedInstaller) SupportAvailable() bool { return len(m.support) > 0 }

// LoadManagedInstaller fails closed on stale or mismatched artifacts. Expected deployment values
// come from operator configuration, never Host/Forwarded headers or the downloaded manifest alone.
func LoadManagedInstaller(dir, controlPlaneURL, signalingURL, issuer string) (*ManagedInstaller, error) {
	return LoadManagedInstallerConfig(ManagedInstallerConfig{Dir: dir, ControlPlaneURL: controlPlaneURL, SignalingURL: signalingURL, GrantIssuerPubkey: issuer})
}

// LoadManagedInstallerConfig is LoadManagedInstaller with deployment-pass mode (docs/48 C). A
// baked manifest is validated exactly as before, and configuring pass files with one is refused.
func LoadManagedInstallerConfig(cfg ManagedInstallerConfig) (*ManagedInstaller, error) {
	dir, controlPlaneURL, signalingURL, issuer := cfg.Dir, cfg.ControlPlaneURL, cfg.SignalingURL, cfg.GrantIssuerPubkey
	bad := errors.New("invalid managed installer release")
	read := func(name string, limit int64) ([]byte, error) {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, bad
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
			return nil, bad
		}
		b, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil || int64(len(b)) > limit {
			return nil, bad
		}
		return b, nil
	}
	b, err := read("installer-manifest.json", 8192)
	if err != nil {
		return nil, bad
	}
	var manifest installerManifest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&manifest) != nil || d.Decode(new(any)) != io.EOF {
		return nil, bad
	}
	validURL := func(raw, scheme string) bool {
		u, err := url.Parse(raw)
		return err == nil && u.Scheme == scheme && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.ContainsAny(raw, "\r\n\t\\")
	}
	passConfigured := cfg.DeploymentPassFile != "" || cfg.AgentReleaseFile != ""
	switch manifest.Mode {
	case "":
		// Baked: the manifest carries this server's URLs. Pass files would be silently ignored, so
		// configuring them with a baked release is a mistake worth stopping for.
		if passConfigured {
			return nil, passErr("CP_DEPLOYMENT_PASS_FILE / CP_AGENT_RELEASE_ATTESTATION_FILE are set, but installer-manifest.json is a baked release (no \"mode\":\"pass\")")
		}
	case "pass":
		// Generic binaries: the server's identity comes from the pass, never the manifest.
		if manifest.ControlPlaneURL != "" || manifest.SignalingURL != "" {
			return nil, passErr("a \"mode\":\"pass\" installer-manifest.json must not carry control_plane_url or signaling_url")
		}
		manifest.ControlPlaneURL, manifest.SignalingURL = controlPlaneURL, signalingURL
	default:
		return nil, bad
	}
	key, err := hex.DecodeString(issuer)
	if err != nil || len(key) != 32 || !validURL(controlPlaneURL, "https") || !validURL(signalingURL, "wss") ||
		manifest.Version != 1 || manifest.ControlPlaneURL != controlPlaneURL || manifest.SignalingURL != signalingURL ||
		!strings.EqualFold(manifest.GrantIssuerPubkey, issuer) || !manifest.RequireSessionPolicy {
		return nil, bad
	}
	msi, err := read("DeskRallyAgent.msi", maxInstallerArtifact)
	if err != nil {
		return nil, bad
	}
	setup, err := read("DeskRallySetup.exe", maxInstallerArtifact)
	if err != nil {
		return nil, bad
	}
	check := func(data []byte, expected string) bool {
		h := sha256.Sum256(data)
		return len(data) > 0 && strings.EqualFold(hex.EncodeToString(h[:]), expected)
	}
	if !check(msi, manifest.MSISHA256) || !check(setup, manifest.SetupSHA256) {
		return nil, bad
	}
	installer := &ManagedInstaller{msi: msi, setup: setup, credits: 4, last: time.Now()}
	// Load the support exe when the manifest names it. Absence of the field is not an error —
	// it just means the bundle endpoint is unavailable for this deployment.
	if manifest.SupportSHA256 != "" {
		sup, err := read("DeskRallySupport.exe", maxInstallerArtifact)
		if err != nil || !check(sup, manifest.SupportSHA256) {
			return nil, bad
		}
		installer.support = sup
	}
	installer.now = cfg.Now
	if manifest.Mode == "pass" {
		if err := loadPassMode(installer, cfg); err != nil {
			return nil, err
		}
	}
	return installer, nil
}

// Pilot-release bound: at most two streams and four immediate downloads, then one per 15s per
// server. No request-keyed map, unbounded queue, compression work, or account-login throttle state.
func (m *ManagedInstaller) acquire() bool {
	return m.take(&m.active, &m.credits, &m.last)
}
func (m *ManagedInstaller) release() { m.mu.Lock(); m.active--; m.mu.Unlock() }

// acquireSupport takes ONE slot of the global support-bundle backstop only (no per-caller
// budget): kept so tests can drain the backstop; the handler uses acquireSupportFor.
func (m *ManagedInstaller) acquireSupport() bool {
	_, ok := m.supportLimiter().global.take("global", m.clock())
	return ok
}

func (m *ManagedInstaller) take(active *int, credits *float64, last *time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	*credits = min(4, *credits+now.Sub(*last).Seconds()/15)
	*last = now
	if *active >= 2 || *credits < 1 {
		return false
	}
	*active++
	*credits--
	return true
}

func (s *Server) handleManagedInstallStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := principalFrom(r.Context()).Grant.Require(CapManageEnrollment); err != nil {
		writeDenied(w, err)
		return
	}
	resp := map[string]any{"available": s.ManagedInstaller != nil, "expires_in_seconds": int(managedInstallTTL / time.Second)}
	if s.ManagedInstaller != nil && s.ManagedInstaller.PassMode() {
		resp["mode"] = "pass"
		resp["deployment_pass"] = s.ManagedInstaller.passStatus()
	} else if s.ManagedInstaller != nil {
		resp["mode"] = "baked"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleManagedInstallBundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageEnrollment); err != nil {
		writeDenied(w, err)
		return
	}
	if s.ManagedInstaller == nil || s.MachineGroups == nil {
		writeError(w, http.StatusServiceUnavailable, "managed installer is not published yet")
		return
	}
	var req struct {
		GroupID string `json:"group_id"`
	}
	if decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "invalid installer request") != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "select a machine group")
		return
	}
	if err := p.Grant.RequireMachine(CapManageEnrollment, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	groups, err := s.MachineGroups.ListMachineGroups(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine group")
		return
	}
	found := false
	for _, group := range groups {
		if group.ID == req.GroupID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "unknown machine group")
		return
	}
	// Before acquire and before minting: a refused request costs no download slot and no token.
	if msg := s.ManagedInstaller.issuanceRefusal(true); msg != "" {
		writeError(w, http.StatusServiceUnavailable, msg)
		return
	}
	if !s.ManagedInstaller.acquire() {
		w.Header().Set("Retry-After", "15")
		writeError(w, http.StatusTooManyRequests, "installer downloads are busy; try again shortly")
		return
	}
	defer s.ManagedInstaller.release()
	tok := &EnrollmentToken{GroupID: req.GroupID, CreatedBy: p.UserID, MaxUses: 1, ExpiresAt: time.Now().Add(managedInstallTTL)}
	secret, err := s.EnrollmentTokens.MintToken(r.Context(), p.TenantID, tok)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare installer")
		return
	}
	complete := false
	defer func() {
		if !complete {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			defer cancel()
			// Never log the token or errors that may echo it. TTL remains bounded even if revoke fails.
			_ = s.EnrollmentTokens.RevokeToken(ctx, p.TenantID, tok.ID)
		}
	}()
	if err := s.recordMgmtAudit(r, "managed_install.download", "enrollment_token", tok.ID, map[string]any{"group_id": req.GroupID, "max_uses": 1}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record installer download")
		return
	}
	releaseBoundConn(r.Context()) // DB work done; the ZIP body may drain slowly (review #5)
	complete = s.ManagedInstaller.writeBundle(w, secret) == nil
}

func (m *ManagedInstaller) writeBundle(w http.ResponseWriter, secret string) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="DeskRally-Install.zip"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	zw := zip.NewWriter(w)
	type entry struct {
		name string
		data []byte
	}
	var extra []entry
	if m.PassMode() {
		// The generic Setup verifies both itself, against the root key compiled into it.
		extra = []entry{{"deployment-pass.json", m.passRaw}, {"agent-release.json", m.releaseRaw}}
	}
	for _, entry := range append([]entry{
		{"DeskRallySetup.exe", m.setup}, {"DeskRallyAgent.msi", m.msi},
		{"enrollment.token", []byte(secret)},
		{"README.txt", []byte("DeskRally installation\r\n\r\nExtract all files, then double-click DeskRallySetup.exe. Approve permanent access only for a support provider you trust. Windows will ask for administrator approval.\r\n\r\nThis private bundle can enroll ONE computer in the selected account and expires 15 minutes after it was prepared. Do not post it publicly. Download a fresh bundle if it expires. Delete the ZIP and extracted files after installation.\r\n\r\nBefore approving the Windows administrator prompt, check that it names the publisher your support provider told you to expect.\r\n")},
	}, extra...) {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			return err
		}
		if _, err = f.Write(entry.data); err != nil {
			return err
		}
	}
	return zw.Close()
}

// writeSupportBundle writes the session-specific support bundle: a ZIP containing the signed
// (unmodified) DeskRallySupport.exe and a session.code sidecar holding the attend code. The
// native support client reads session.code from its own directory on startup and pre-fills the
// code prompt, eliminating the manual paste step for the guest.
//
// The code is NOT redeemed here — single-use redemption remains with the native client via
// POST /attended-sessions/redeem. This bundle is a packaging convenience, not an auth boundary.
func (m *ManagedInstaller) writeSupportBundle(w http.ResponseWriter, code string) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="DeskRally-Support.zip"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	zw := zip.NewWriter(w)
	type entry struct {
		name string
		data []byte
	}
	var extra []entry
	if m.PassMode() {
		extra = []entry{{"deployment-pass.json", m.passRaw}}
	}
	for _, entry := range append([]entry{
		{"DeskRallySupport.exe", m.support},
		// Plain text, no trailing newline. The native client strips whitespace before validating.
		{"session.code", []byte(code)},
		{"README.txt", []byte("DeskRally support session\r\n\r\nExtract all files to the same folder, then double-click DeskRallySupport.exe.\r\nThe support client will connect to your technician's session automatically. You will see a consent prompt before any access is granted and you can end the session at any time.\r\n\r\nThis file contains a one-time session code that expires shortly. Download a fresh bundle from your technician's link if it has expired.\r\nDo not share this file. Delete the ZIP and extracted files after the session.\r\n")},
	}, extra...) {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			return err
		}
		if _, err = f.Write(entry.data); err != nil {
			return err
		}
	}
	return zw.Close()
}

// validAttendCodeShape returns true if raw has the format of a plausible attend code:
// 8 characters (or a legacy 13-character code) from the Crockford base32 alphabet (uppercase only — the control
// plane normalises case on redemption). This is a FORMAT check only; it does not query the
// store, so it cannot tell whether the code is live, expired, or already spent.
//
// New codes encode 5 random bytes as 8 characters; 13-character legacy codes remain valid.
// The alphabet is the same one crockford.go encodes with: 0-9, A-H, J, K, M, N, P-T, V-Z
// (no I, L, O, U). Lower-case is explicitly rejected here because this endpoint receives
// codes from the browser, which should be upper-cased by the JoinPage (validatedAttendCode
// in attend_link.ts calls toUpperCase), and silently accepting lower-case would widen the
// surface without adding value.
func validAttendCodeShape(raw string) bool {
	if len(raw) != 8 && len(raw) != 13 {
		return false
	}
	const crockfordUpper = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		found := false
		for j := 0; j < len(crockfordUpper); j++ {
			if c == crockfordUpper[j] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// handleAttendedSupportBundle serves a session-specific support bundle ZIP to a guest.
//
// Unauthenticated (like /attended-sessions/redeem): the code in the request body is the guest's
// credential. The code is NOT redeemed here — the native client does that. This endpoint exists
// solely to package the exe and the code together so the guest does not have to manually type
// the code into the support client's prompt.
//
// Rate-limited by its OWN token bucket (acquireSupport), never the managed-install one: this route
// is anonymous. An invalid code shape gets 400; a missing support exe gets 503; 429 on burst
// exhaustion.
func (s *Server) handleAttendedSupportBundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.ManagedInstaller == nil || !s.ManagedInstaller.SupportAvailable() {
		writeError(w, http.StatusServiceUnavailable, "support bundle is not available for this deployment")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if decodeJSONBodyDetailed(w, r, maxAttendedBodyBytes, &req, "invalid bundle request") != nil {
		return
	}
	if !validAttendCodeShape(req.Code) {
		writeError(w, http.StatusBadRequest, "invalid session code format")
		return
	}
	if msg := s.ManagedInstaller.issuanceRefusal(false); msg != "" {
		writeError(w, http.StatusServiceUnavailable, msg)
		return
	}
	// The caller's OWN budgets (client IP, session code) are charged first and the generous global
	// backstop last, so an anonymous caller that spams codes exhausts only itself.
	release, ok := s.ManagedInstaller.acquireSupportFor(clientIP(r), req.Code)
	if !ok {
		w.Header().Set("Retry-After", "15")
		writeError(w, http.StatusTooManyRequests, "bundle downloads are busy; try again shortly")
		return
	}
	defer release()
	_ = s.ManagedInstaller.writeSupportBundle(w, req.Code)
}

// The guest already holds its attend bearer. This reuses the technician's requested promotion
// credential; it cannot mint one or change the target tenant/group. Setup still requires local UAC.
func (s *Server) handleAttendedInstallBundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.ManagedInstaller == nil {
		writeError(w, http.StatusServiceUnavailable, "managed installer is not published yet")
		return
	}
	token := attendBearer(r)
	if !validAttendTokenShape(token) {
		writeError(w, http.StatusForbidden, "invalid attend token")
		return
	}
	sess, err := s.Attended.ByToken(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusForbidden, "invalid attend token")
		return
	}
	if !attendedCanPromote(sess.State) || sess.PromoteToken == "" {
		writeError(w, http.StatusConflict, "installation has not been requested for this session")
		return
	}
	// Nonce binding: if the guest sent the attempt nonce it received in the status response, verify
	// it matches the current attempt before packaging the token. This is checked on the session
	// snapshot from ByToken above, which reads both PromoteToken and PromoteAttemptNonce atomically.
	// If the technician re-issued while the guest's download was in flight, the nonce will have
	// rotated and the request is rejected with 409 so the guest's poller can start a clean attempt
	// with the new nonce rather than silently installing a different token than the one it agreed to.
	if wantNonce := r.URL.Query().Get("attempt_nonce"); wantNonce != "" {
		if wantNonce != sess.PromoteAttemptNonce {
			writeError(w, http.StatusConflict, "installer request nonce does not match current attempt — the technician may have re-issued the request")
			return
		}
	}
	if msg := s.ManagedInstaller.issuanceRefusal(true); msg != "" {
		writeError(w, http.StatusServiceUnavailable, msg)
		return
	}
	if !s.ManagedInstaller.acquire() {
		w.Header().Set("Retry-After", "15")
		writeError(w, http.StatusTooManyRequests, "installer downloads are busy")
		return
	}
	defer s.ManagedInstaller.release()
	_ = s.ManagedInstaller.writeBundle(w, sess.PromoteToken)
}

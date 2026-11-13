package controlplane

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// passFix builds a pass-mode installer directory: generic artifacts, a "mode":"pass" manifest,
// and a pass + release attestation signed by the test root key. Each test changes one thing.
type passFix struct {
	t            *testing.T
	dir          string
	root         *ecdsa.PrivateKey
	signDomain   string // the domain the pass is signed under (to test a wrong one)
	pass         DeploymentPassClaims
	rel          AgentReleaseClaims
	msi          []byte
	support      bool
	manifestURLs bool   // a pass-mode manifest that wrongly carries URLs
	mode         string // manifest mode
	cfg          ManagedInstallerConfig
	now          time.Time
	noPassFiles  bool
}

const passFixOrigin = "https://support.example"

func newPassFix(t *testing.T) *passFix {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	f := &passFix{t: t, dir: t.TempDir(), root: testRootKey(t, "root"), signDomain: DeploymentPassDomain,
		msi: []byte("synthetic generic MSI, never executable"), support: true, mode: "pass", now: now}
	f.pass = DeploymentPassClaims{
		PassID: "3f6c1a2e-8b4d-4c1f-9e2a-7d5b6c8e9f01", IssuedTo: "Example MSP", Origin: passFixOrigin,
		GrantIssuerPubkey: strings.Repeat("ab", 32), ForSetup: true, ForSupport: true, MinAgentVersion: "1.3.4",
		IssuedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(20 * 24 * time.Hour),
	}
	f.rel = AgentReleaseClaims{
		MSISHA256: sha256Hex(f.msi), MSISize: int64(len(f.msi)), ProductVersion: "1.3.5",
		ProductCode: "{0F347057-1A2B-4C3D-8E9F-0123456789AB}", UpgradeCode: "{7B3E9C2A-4F1D-4E8B-9A6C-2D5E8F1A3B7C}",
		Arch: "x64", IssuedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(300 * 24 * time.Hour),
	}
	f.cfg = ManagedInstallerConfig{
		Dir: f.dir, ControlPlaneURL: passFixOrigin + "/cp", SignalingURL: "wss://support.example/ws",
		GrantIssuerPubkey:  strings.Repeat("ab", 32),
		DeploymentPassFile: filepath.Join(f.dir, "deployment-pass.json"), AgentReleaseFile: filepath.Join(f.dir, "agent-release.json"),
		PassRoot: &f.root.PublicKey, Now: func() time.Time { return f.now },
	}
	return f
}

func (f *passFix) write() {
	t := f.t
	t.Helper()
	setup, support := []byte("synthetic generic setup"), []byte("synthetic generic support")
	m := installerManifest{Version: 1, GrantIssuerPubkey: strings.Repeat("ab", 32), RequireSessionPolicy: true,
		MSISHA256: sha256Hex(f.msi), SetupSHA256: sha256Hex(setup), Mode: f.mode}
	if f.manifestURLs || f.mode == "" {
		m.ControlPlaneURL, m.SignalingURL = f.cfg.ControlPlaneURL, f.cfg.SignalingURL
	}
	files := map[string][]byte{"DeskRallyAgent.msi": f.msi, "DeskRallySetup.exe": setup}
	if f.support {
		m.SupportSHA256 = sha256Hex(support)
		files["DeskRallySupport.exe"] = support
	}
	files["installer-manifest.json"], _ = json.Marshal(m)
	// Every case signs a VALID body: the refusals under test are about whether the pass describes
	// this server and this MSI, not about the format (the vectors cover that).
	pb, err := EncodeDeploymentPassBody(f.pass)
	if err != nil {
		t.Fatalf("pass body: %v", err)
	}
	rb, err := EncodeAgentReleaseBody(f.rel)
	if err != nil {
		t.Fatalf("release body: %v", err)
	}
	files["deployment-pass.json"] = append(signEnvelope(t, f.root, f.signDomain, pb), '\n')
	files["agent-release.json"] = append(signEnvelope(t, f.root, AgentReleaseDomain, rb), '\n')
	for n, data := range files {
		if err := os.WriteFile(filepath.Join(f.dir, n), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if f.noPassFiles {
		f.cfg.DeploymentPassFile, f.cfg.AgentReleaseFile = "", ""
	}
}

func (f *passFix) load() (*ManagedInstaller, error) {
	f.t.Helper()
	f.write()
	return LoadManagedInstallerConfig(f.cfg)
}

func (f *passFix) mustLoad() *ManagedInstaller {
	f.t.Helper()
	m, err := f.load()
	if err != nil {
		f.t.Fatalf("load: %v", err)
	}
	return m
}

func zipFiles(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	z, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, zf := range z.File {
		r, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r)
		r.Close()
		out[zf.Name] = b
	}
	return out
}

func passBundleServer(t *testing.T, m *ManagedInstaller) (*Server, string) {
	t.Helper()
	srv, _ := newTestServer(ownerPrincipal("owner"))
	srv.ManagedInstaller = m
	g := &MachineGroup{Name: "Home"}
	if err := srv.MachineGroups.CreateMachineGroup(context.Background(), "tenant-123", g); err != nil {
		t.Fatal(err)
	}
	return srv, g.ID
}

func postInstall(srv *Server, group string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/managed-installer", strings.NewReader(`{"group_id":"`+group+`"}`)))
	return rec
}

func postSupport(srv *Server) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/attended-sessions/support-bundle", strings.NewReader(`{"code":"0123456789ABC"}`)))
	return rec
}

func tokenCount(t *testing.T, srv *Server) int {
	t.Helper()
	toks, err := srv.EnrollmentTokens.ListTokens(context.Background(), "tenant-123")
	if err != nil {
		t.Fatal(err)
	}
	return len(toks)
}

func TestPassModeBundlesCarryTheExactPassFiles(t *testing.T) {
	f := newPassFix(t)
	m := f.mustLoad()
	if !m.PassMode() {
		t.Fatal("pass-mode manifest did not load in pass mode")
	}
	passFile, _ := os.ReadFile(f.cfg.DeploymentPassFile)
	relFile, _ := os.ReadFile(f.cfg.AgentReleaseFile)

	srv, group := passBundleServer(t, m)
	rec := postInstall(srv, group)
	if rec.Code != 200 {
		t.Fatalf("install bundle: %d %s", rec.Code, rec.Body.String())
	}
	files := zipFiles(t, rec.Body.Bytes())
	if len(files) != 6 || !bytes.Equal(files["deployment-pass.json"], passFile) || !bytes.Equal(files["agent-release.json"], relFile) ||
		!bytes.Equal(files["DeskRallyAgent.msi"], f.msi) || len(files["enrollment.token"]) != 43 {
		t.Fatalf("install bundle files: %d %v", len(files), keys(files))
	}

	ssrv, _ := newAttendedServer(t)
	ssrv.ManagedInstaller = m
	rec = postSupport(ssrv)
	if rec.Code != 200 {
		t.Fatalf("support bundle: %d %s", rec.Code, rec.Body.String())
	}
	sfiles := zipFiles(t, rec.Body.Bytes())
	if len(sfiles) != 4 || !bytes.Equal(sfiles["deployment-pass.json"], passFile) || sfiles["agent-release.json"] != nil {
		t.Fatalf("support bundle files: %v", keys(sfiles))
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Every mismatch is fatal at startup and says which check failed.
func TestPassModeStartupRefusals(t *testing.T) {
	other := testRootKey(t, "other")
	cases := []struct {
		name  string
		setup func(f *passFix)
		want  string
	}{
		{"pass for another origin", func(f *passFix) { f.pass.Origin = "https://elsewhere.example" }, "the pass is for https://elsewhere.example/cp"},
		{"signaling differs", func(f *passFix) { f.cfg.SignalingURL = "wss://support.example:8443/ws" }, "derives signaling"},
		{"another grant key", func(f *passFix) { f.pass.GrantIssuerPubkey = strings.Repeat("cd", 32) }, "grant issuer key"},
		{"MSI not the attested one", func(f *passFix) { f.rel.MSISHA256 = strings.Repeat("00", 32) }, "not for the DeskRallyAgent.msi"},
		{"MSI size not the attested one", func(f *passFix) { f.rel.MSISize++ }, "not for the DeskRallyAgent.msi"},
		{"release older than min_agent_version", func(f *passFix) { f.rel.ProductVersion = "1.3.3" }, "older than the pass's min_agent_version"},
		{"signed by another root", func(f *passFix) { f.cfg.PassRoot = &other.PublicKey }, "does not verify"},
		{"pass signed for the release domain", func(f *passFix) { f.signDomain = AgentReleaseDomain }, "CP_DEPLOYMENT_PASS_FILE does not verify"},
		{"pass without setup", func(f *passFix) { f.pass.ForSetup = false }, "does not cover setup"},
		{"support served, pass without support", func(f *passFix) { f.pass.ForSupport = false }, "does not cover support"},
		{"pass manifest carrying URLs", func(f *passFix) { f.manifestURLs = true }, "must not carry"},
		{"baked manifest with pass files", func(f *passFix) { f.mode = "" }, "is a baked release"},
		{"pass manifest without pass files", func(f *passFix) { f.noPassFiles = true }, "are both required"},
		{"test root, real origin", func(f *passFix) { f.cfg.TestRoot = true }, "only authorize lab origins"},
		{"pass file missing", func(f *passFix) { f.cfg.DeploymentPassFile += ".missing" }, "CP_DEPLOYMENT_PASS_FILE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newPassFix(t)
			c.setup(f)
			_, err := f.load()
			var pe *PassModeError
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a PassModeError containing %q", err, c.want)
			}
		})
	}
	// Controls: the unchanged fixture loads, a pass support-only directory loads without
	// support, and a test root may authorize a lab origin.
	if _, err := newPassFix(t).load(); err != nil {
		t.Fatalf("control: %v", err)
	}
	f := newPassFix(t)
	f.support, f.pass.ForSupport = false, false
	if _, err := f.load(); err != nil {
		t.Fatalf("control (no support exe, pass without support): %v", err)
	}
	f = newPassFix(t)
	f.cfg.TestRoot = true
	f.pass.Origin = "https://lab.deskrally.test"
	f.cfg.ControlPlaneURL, f.cfg.SignalingURL = "https://lab.deskrally.test/cp", "wss://lab.deskrally.test/ws"
	if _, err := f.load(); err != nil {
		t.Fatalf("control (test root, lab origin): %v", err)
	}
}

// A lapsed pass does not stop the server (that would take every agent down on the next restart);
// it starts, warns, and refuses every bundle before minting anything.
func TestPassModeExpiryRefusesBundlesNotStartup(t *testing.T) {
	f := newPassFix(t)
	f.now = f.pass.ExpiresAt.Add(time.Hour) // expired before startup
	m := f.mustLoad()
	if w := m.PassWarnings(); len(w) != 1 || !strings.Contains(w[0], "deployment pass expired") {
		t.Fatalf("warnings %v", w)
	}
	srv, group := passBundleServer(t, m)
	rec := postInstall(srv, group)
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "deployment pass expired") {
		t.Fatalf("install with expired pass: %d %s", rec.Code, rec.Body.String())
	}
	if n := tokenCount(t, srv); n != 0 {
		t.Fatalf("a refused install minted %d token(s)", n)
	}
	ssrv, _ := newAttendedServer(t)
	ssrv.ManagedInstaller = m
	if rec := postSupport(ssrv); rec.Code != 503 || !strings.Contains(rec.Body.String(), "deployment pass expired") {
		t.Fatalf("support with expired pass: %d %s", rec.Code, rec.Body.String())
	}
	asrv, _, attendToken := installerSessionFixture(t)
	asrv.ManagedInstaller = m
	if code := installerGET(t, asrv, attendToken, ""); code != 503 {
		t.Fatalf("attended install with expired pass: %d", code)
	}

	// Re-checked at every issuance, not only at startup: valid at load, then the clock passes expiry.
	f = newPassFix(t)
	m = f.mustLoad()
	srv, group = passBundleServer(t, m)
	if rec := postInstall(srv, group); rec.Code != 200 {
		t.Fatalf("before expiry: %d", rec.Code)
	}
	f.now = f.pass.ExpiresAt
	if rec := postInstall(srv, group); rec.Code != 503 {
		t.Fatalf("at expiry: %d", rec.Code)
	}

	// An expired release attestation stops installs but not support bundles. The attestation is
	// made to expire an hour after "now", and the clock moved two hours, while the pass (20 days)
	// is still valid.
	f = newPassFix(t)
	f.rel.ExpiresAt = f.now.Add(time.Hour)
	m = f.mustLoad()
	f.now = f.now.Add(2 * time.Hour)
	srv, group = passBundleServer(t, m)
	if rec := postInstall(srv, group); rec.Code != 503 || !strings.Contains(rec.Body.String(), "agent release attestation expired") {
		t.Fatalf("install with expired attestation: %d %s", rec.Code, rec.Body.String())
	}
	ssrv, _ = newAttendedServer(t)
	ssrv.ManagedInstaller = m
	if rec := postSupport(ssrv); rec.Code != 200 {
		t.Fatalf("support with a valid pass and an expired attestation: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPassModeStatusWarnsSevenDaysAhead(t *testing.T) {
	f := newPassFix(t)
	m := f.mustLoad()
	status := func() map[string]any {
		srv, _ := passBundleServer(t, m)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/managed-installer", nil))
		var out map[string]any
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
		}
		return out
	}
	s := status()
	dp, _ := s["deployment_pass"].(map[string]any)
	if s["mode"] != "pass" || dp == nil || dp["issued_to"] != "Example MSP" || len(dp["warnings"].([]any)) != 0 {
		t.Fatalf("20 days left: %v", s)
	}
	f.now = f.pass.ExpiresAt.Add(-6 * 24 * time.Hour)
	dp = status()["deployment_pass"].(map[string]any)
	if w := dp["warnings"].([]any); len(w) != 1 || !strings.Contains(w[0].(string), "deployment pass expires") {
		t.Fatalf("6 days left: %v", dp["warnings"])
	}
	// Baked servers say so, and carry no pass block.
	_, baked := installerFixture(t)
	srv, _ := passBundleServer(t, baked)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/managed-installer", nil))
	if !strings.Contains(rec.Body.String(), `"mode":"baked"`) || strings.Contains(rec.Body.String(), "deployment_pass") {
		t.Fatalf("baked status: %s", rec.Body.String())
	}
}

// Baked releases are untouched by pass mode: no extra bundle files, never refused at issuance.
func TestBakedModeUnaffectedByPassMode(t *testing.T) {
	_, m := installerFixture(t)
	if m.PassMode() || m.issuanceRefusal(true) != "" || m.issuanceRefusal(false) != "" || m.PassWarnings() != nil {
		t.Fatal("a baked installer behaves as pass mode")
	}
	srv, group := passBundleServer(t, m)
	rec := postInstall(srv, group)
	if rec.Code != http.StatusOK {
		t.Fatalf("baked install: %d", rec.Code)
	}
	if files := zipFiles(t, rec.Body.Bytes()); len(files) != 4 || files["deployment-pass.json"] != nil {
		t.Fatalf("baked bundle files: %v", keys(files))
	}
}

func TestPassModeWarningEdgesAndSnapshot(t *testing.T) {
	// Exactly seven days before expiry warns; one second more does not.
	f := newPassFix(t)
	m := f.mustLoad()
	f.now = f.pass.ExpiresAt.Add(-passWarningWindow - time.Second)
	if w := m.PassWarnings(); len(w) != 0 {
		t.Fatalf("7 days + 1 s before expiry: %v", w)
	}
	f.now = f.pass.ExpiresAt.Add(-passWarningWindow)
	if w := m.PassWarnings(); len(w) != 1 {
		t.Fatalf("exactly 7 days before expiry: %v", w)
	}

	// A lapsed attestation warns about installs only, never support bundles.
	f = newPassFix(t)
	f.rel.ExpiresAt = f.now.Add(time.Hour)
	m = f.mustLoad()
	f.now = f.now.Add(2 * time.Hour)
	if w := m.PassWarnings(); len(w) != 1 || !strings.Contains(w[0], "New installs are refused") || strings.Contains(w[0], "support") {
		t.Fatalf("lapsed attestation warning: %v", w)
	}

	// Not yet valid (beyond the 5-minute skew): starts, warns, refuses bundles.
	f = newPassFix(t)
	f.pass.IssuedAt = f.now.Add(time.Hour)
	f.pass.ExpiresAt = f.now.Add(10 * 24 * time.Hour)
	m = f.mustLoad()
	if w := m.PassWarnings(); len(w) != 1 || !strings.Contains(w[0], "not valid until") {
		t.Fatalf("future pass warning: %v", w)
	}
	srv, group := passBundleServer(t, m)
	if rec := postInstall(srv, group); rec.Code != 503 || !strings.Contains(rec.Body.String(), "not valid yet") {
		t.Fatalf("future pass install: %d %s", rec.Code, rec.Body.String())
	}

	// Bundles serve the startup snapshot: changing files on disk afterwards changes nothing.
	f = newPassFix(t)
	m = f.mustLoad()
	passFile, _ := os.ReadFile(f.cfg.DeploymentPassFile)
	for _, p := range []string{f.cfg.DeploymentPassFile, filepath.Join(f.dir, "DeskRallyAgent.msi")} {
		if err := os.WriteFile(p, []byte("replaced after startup"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srv, group = passBundleServer(t, m)
	rec := postInstall(srv, group)
	files := zipFiles(t, rec.Body.Bytes())
	if rec.Code != 200 || !bytes.Equal(files["deployment-pass.json"], passFile) || !bytes.Equal(files["DeskRallyAgent.msi"], f.msi) {
		t.Fatalf("bundle did not serve the verified snapshot: %d", rec.Code)
	}
}

// The public join page learns only whether the bundle is the sole working download.
func TestAttendedSupportModeIsPublicAndReportsPassMode(t *testing.T) {
	get := func(m *ManagedInstaller) string {
		srv, _ := newAttendedServer(t)
		srv.ManagedInstaller = m
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/attended-sessions/support-mode", nil))
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status %d cache %q", rec.Code, rec.Header().Get("Cache-Control"))
		}
		return strings.TrimSpace(rec.Body.String())
	}
	if got := get(newPassFix(t).mustLoad()); got != `{"bundle_only":true}` {
		t.Fatalf("pass mode: %s", got)
	}
	_, baked := installerFixture(t)
	if got := get(baked); got != `{"bundle_only":false}` {
		t.Fatalf("baked: %s", got)
	}
	if got := get(nil); got != `{"bundle_only":false}` {
		t.Fatalf("no installer: %s", got)
	}
}

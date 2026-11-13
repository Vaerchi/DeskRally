package controlplane

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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func installerFixture(t *testing.T) (string, *ManagedInstaller) {
	t.Helper()
	dir := t.TempDir()
	msi, setup := []byte("synthetic MSI, never executable"), []byte("synthetic setup, never executable")
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	// Named-field syntax so adding new manifest fields does not require updating this call site.
	manifest := installerManifest{
		Version:              1,
		ControlPlaneURL:      "https://support.example/cp",
		SignalingURL:         "wss://support.example/ws",
		GrantIssuerPubkey:    strings.Repeat("ab", 32),
		RequireSessionPolicy: true,
		MSISHA256:            hash(msi),
		SetupSHA256:          hash(setup),
		// SupportSHA256 left empty: this fixture does not include the support exe, so the
		// bundle endpoint is unavailable. supportBundleFixture adds the support exe.
	}
	b, _ := json.Marshal(manifest)
	for n, data := range map[string][]byte{"installer-manifest.json": b, "DeskRallyAgent.msi": msi, "DeskRallySetup.exe": setup} {
		if err := os.WriteFile(filepath.Join(dir, n), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := LoadManagedInstaller(dir, manifest.ControlPlaneURL, manifest.SignalingURL, manifest.GrantIssuerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	return dir, m
}

// supportBundleFixture returns an installer that also loaded DeskRallySupport.exe.
func supportBundleFixture(t *testing.T) *ManagedInstaller {
	t.Helper()
	dir := t.TempDir()
	msi := []byte("synthetic MSI, never executable")
	setup := []byte("synthetic setup, never executable")
	support := []byte("synthetic DeskRallySupport.exe, never executable")
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	manifest := installerManifest{
		Version:              1,
		ControlPlaneURL:      "https://support.example/cp",
		SignalingURL:         "wss://support.example/ws",
		GrantIssuerPubkey:    strings.Repeat("ab", 32),
		RequireSessionPolicy: true,
		MSISHA256:            hash(msi),
		SetupSHA256:          hash(setup),
		SupportSHA256:        hash(support),
	}
	b, _ := json.Marshal(manifest)
	files := map[string][]byte{
		"installer-manifest.json": b,
		"DeskRallyAgent.msi":      msi,
		"DeskRallySetup.exe":      setup,
		"DeskRallySupport.exe":    support,
	}
	for n, data := range files {
		if err := os.WriteFile(filepath.Join(dir, n), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := LoadManagedInstaller(dir, manifest.ControlPlaneURL, manifest.SignalingURL, manifest.GrantIssuerPubkey)
	if err != nil {
		t.Fatal(err)
	}
	if !m.SupportAvailable() {
		t.Fatal("supportBundleFixture: support exe not loaded")
	}
	return m
}

func TestManagedInstallerRejectsArtifactDriftAndWrongDeployment(t *testing.T) {
	dir, _ := installerFixture(t)
	load := func(cp, pin string) error {
		_, err := LoadManagedInstaller(dir, cp, "wss://support.example/ws", pin)
		return err
	}
	if load("https://elsewhere.example/cp", strings.Repeat("ab", 32)) == nil {
		t.Fatal("accepted another deployment")
	}
	if load("https://support.example/cp", strings.Repeat("cd", 32)) == nil {
		t.Fatal("accepted another issuer")
	}
	if err := os.WriteFile(filepath.Join(dir, "DeskRallyAgent.msi"), []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if load("https://support.example/cp", strings.Repeat("ab", 32)) == nil {
		t.Fatal("accepted changed MSI")
	}
}

func bundleServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv, _ := newTestServer(ownerPrincipal("owner"))
	_, srv.ManagedInstaller = installerFixture(t)
	g := &MachineGroup{Name: "Home"}
	if err := srv.MachineGroups.CreateMachineGroup(context.Background(), "tenant-123", g); err != nil {
		t.Fatal(err)
	}
	return srv, g.ID
}

func TestManagedBundleContainsOnlyFixedFilesAndSingleUseScopedToken(t *testing.T) {
	srv, group := bundleServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/managed-installer", strings.NewReader(`{"group_id":"`+group+`"}`)))
	if rec.Code != 200 {
		t.Fatalf("status%d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential response can be cached")
	}
	z, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != 4 {
		t.Fatalf("files=%d", len(z.File))
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = b
	}
	if !bytes.Equal(files["DeskRallySetup.exe"], srv.ManagedInstaller.setup) || !bytes.Equal(files["DeskRallyAgent.msi"], srv.ManagedInstaller.msi) || len(files["README.txt"]) == 0 {
		t.Fatal("wrong artifacts")
	}
	secret := string(files["enrollment.token"])
	if len(secret) != 43 {
		t.Fatal("wrong token shape")
	}
	tok, err := srv.EnrollmentTokens.RedeemToken(context.Background(), secret)
	if err != nil {
		t.Fatal(err)
	}
	if tok.TenantID != "tenant-123" || tok.GroupID != group || tok.MaxUses != 1 || time.Until(tok.ExpiresAt) > 15*time.Minute || time.Until(tok.ExpiresAt) < 14*time.Minute {
		t.Fatal("wrong token scope/lifetime")
	}
	if _, err = srv.EnrollmentTokens.RedeemToken(context.Background(), secret); err == nil {
		t.Fatal("credential reused")
	}
}

func TestManagedBundleFailsClosedWithoutPublishingOrGroupPermission(t *testing.T) {
	srv, group := bundleServer(t)
	for _, tc := range []struct {
		name      string
		configure func()
		want      int
	}{
		{"unknown group", func() { group = "not-a-group" }, 404},
		{"disabled", func() { srv.ManagedInstaller = nil }, 503},
		{"read only", func() {
			srv.Auth = StubAuthenticator{Principal: &Principal{UserID: "reader", TenantID: "tenant-123", Grant: NewGrant("reader", "tenant-123", NewMembership(RoleReadOnly, AllGroups()))}}
		}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.configure()
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/managed-installer", strings.NewReader(`{"group_id":"`+group+`"}`)))
			if rec.Code != tc.want {
				t.Fatalf("status%d", rec.Code)
			}
		})
	}
	tokens, err := srv.EnrollmentTokens.ListTokens(context.Background(), "tenant-123")
	if err != nil || len(tokens) != 0 {
		t.Fatal("failure minted credential")
	}
}

type installerFailedWriter struct{ header http.Header }

func (w *installerFailedWriter) Header() http.Header { return w.header }
func (w *installerFailedWriter) WriteHeader(int)     {}
func (w *installerFailedWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic disconnected client")
}

func TestManagedBundleDisconnectRevokesCredential(t *testing.T) {
	srv, group := bundleServer(t)
	w := &installerFailedWriter{make(http.Header)}
	srv.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/managed-installer", strings.NewReader(`{"group_id":"`+group+`"}`)))
	tokens, err := srv.EnrollmentTokens.ListTokens(context.Background(), "tenant-123")
	if err != nil || len(tokens) != 1 {
		t.Fatal("missing mint")
	}
	if !tokens[0].Revoked {
		t.Fatal("failed download left live credential")
	}
}

func TestManagedInstallerAdmissionIsBounded(t *testing.T) {
	_, m := installerFixture(t)
	if !m.acquire() || !m.acquire() || m.acquire() {
		t.Fatal("stream count not bounded")
	}
	m.release()
	m.release()
	if !m.acquire() {
		t.Fatal("released stream stayed busy")
	}
	m.release()
	if !m.acquire() {
		t.Fatal("fourth credit missing")
	}
	m.release()
	if m.acquire() {
		t.Fatal("download mint rate unbounded")
	}
}

func TestManagedBundleAuditFailureRevokesAndNeverReturnsZIP(t *testing.T) {
	srv, group := bundleServer(t)
	srv.MgmtAudit = &auditFailsAfterN{MgmtAuditStore: srv.MgmtAudit, failFrom: 1}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/managed-installer", strings.NewReader(`{"group_id":"`+group+`"}`)))
	if rec.Code != 500 || rec.Header().Get("Content-Type") == "application/zip" {
		t.Fatal("audit failure delivered bundle")
	}
	tokens, err := srv.EnrollmentTokens.ListTokens(context.Background(), "tenant-123")
	if err != nil || len(tokens) != 1 || !tokens[0].Revoked {
		t.Fatal("audit failure left credential active")
	}
}

func TestManagedBundleGroupAndTenantIsolation(t *testing.T) {
	srv, group := bundleServer(t)
	srv.Auth = StubAuthenticator{Principal: &Principal{UserID: "scoped", TenantID: "tenant-123", Grant: NewGrant("scoped", "tenant-123", NewMembership(RoleAdmin, Groups("other-group")))}}
	if code := apiJSON(t, srv, "POST", "/managed-installer", `{"group_id":"`+group+`"}`, nil); code != 403 {
		t.Fatalf("cross-group status%d", code)
	}
	srv.Auth = StubAuthenticator{Principal: &Principal{UserID: "other", TenantID: "other-tenant", Grant: NewGrant("other", "other-tenant", NewMembership(RoleOwner, AllGroups()))}}
	if code := apiJSON(t, srv, "POST", "/managed-installer", `{"group_id":"`+group+`"}`, nil); code != 404 {
		t.Fatalf("cross-tenant status%d", code)
	}
}

func TestAttendedInstallerRequiresConsentAndTechnicianRequest(t *testing.T) {
	srv, _ := newAttendedServer(t)
	_, srv.ManagedInstaller = installerFixture(t)
	var created attendedCreateResp
	if apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created) != 201 {
		t.Fatal("create failed")
	}
	var guest attendedRedeemResp
	if apiJSON(t, srv, "POST", "/attended-sessions/redeem", `{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"test"}`, &guest) != 201 {
		t.Fatal("redeem failed")
	}
	get := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/attended-sessions/installer", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 6; i++ {
		if get(strings.Repeat("A", 43)).Code != 403 {
			t.Fatal("bad bearer accepted or consumed valid-user download budget")
		}
	}
	if get(guest.AttendToken).Code != 409 {
		t.Fatal("pre-consent download")
	}
	if apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", guest.AttendToken, `{"decision":"accept"}`, nil) != 200 {
		t.Fatal("consent failed")
	}
	if get(guest.AttendToken).Code != 409 {
		t.Fatal("guest minted own installation")
	}
	if code := apiJSON(t, srv, "POST", "/attended-sessions/"+created.Session.ID+"/promote", "", nil); code != 200 {
		t.Fatalf("request failed%d", code)
	}
	w := get(guest.AttendToken)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" {
		t.Fatal("requested download failed")
	}
	if apiJSON(t, srv, "POST", "/attended-sessions/"+created.Session.ID+"/end", "", nil) != 200 {
		t.Fatal("end failed")
	}
	if code := get(guest.AttendToken).Code; code != 403 && code != 409 {
		t.Fatal("ended guest got installer")
	}
}

func TestManagedInstallerManifestRefusals(t *testing.T) {
	for _, kind := range []string{"version", "policy", "unknown", "trailing", "plain-cp", "plain-ws", "short-key", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir, _ := installerFixture(t)
			p := filepath.Join(dir, "installer-manifest.json")
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var v map[string]any
			if json.Unmarshal(b, &v) != nil {
				t.Fatal("fixture")
			}
			cp, ws, pin := "https://support.example/cp", "wss://support.example/ws", strings.Repeat("ab", 32)
			switch kind {
			case "version":
				v["version"] = 2
			case "policy":
				v["require_session_policy"] = false
			case "unknown":
				v["ignore_me"] = true
			case "plain-cp":
				cp = "http://support.example/cp"
				v["control_plane_url"] = cp
			case "plain-ws":
				ws = "ws://support.example/ws"
				v["signaling_url"] = ws
			case "short-key":
				pin = "ab"
				v["grant_issuer_pubkey"] = pin
			case "oversize":
				if err := os.Truncate(filepath.Join(dir, "DeskRallyAgent.msi"), maxInstallerArtifact+1); err != nil {
					t.Fatal(err)
				}
			}
			b, err = json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "trailing" {
				b = append(b, []byte(" {}")...)
			}
			if os.WriteFile(p, b, 0600) != nil {
				t.Fatal("write manifest")
			}
			if _, err := LoadManagedInstaller(dir, cp, ws, pin); err == nil {
				t.Fatal("invalid release accepted")
			}
		})
	}
}

func TestManagedInstallerConcurrentAdmission(t *testing.T) {
	_, m := installerFixture(t)
	start := make(chan struct{})
	results := make(chan bool, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; results <- m.acquire() }()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	if winners != 2 {
		t.Fatalf("admitted %d concurrent streams, want2", winners)
	}
	m.release()
	m.release()
}

func TestManagedInstallerLoadsSupportExe(t *testing.T) {
	dir := t.TempDir()
	msi := []byte("synthetic MSI, never executable")
	setup := []byte("synthetic setup, never executable")
	support := []byte("synthetic DeskRallySupport.exe, never executable")
	hash := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	writeManifest := func(supportHash string) {
		manifest := installerManifest{
			Version:              1,
			ControlPlaneURL:      "https://support.example/cp",
			SignalingURL:         "wss://support.example/ws",
			GrantIssuerPubkey:    strings.Repeat("ab", 32),
			RequireSessionPolicy: true,
			MSISHA256:            hash(msi),
			SetupSHA256:          hash(setup),
			SupportSHA256:        supportHash,
		}
		b, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(dir, "installer-manifest.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"DeskRallyAgent.msi", "DeskRallySetup.exe", "DeskRallySupport.exe"} {
		var data []byte
		switch name {
		case "DeskRallyAgent.msi":
			data = msi
		case "DeskRallySetup.exe":
			data = setup
		default:
			data = support
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	writeManifest(strings.Repeat("00", 32))
	if _, err := LoadManagedInstaller(dir, "https://support.example/cp", "wss://support.example/ws", strings.Repeat("ab", 32)); err == nil {
		t.Fatal("accepted wrong support sha")
	}

	writeManifest(hash(support))
	m, err := LoadManagedInstaller(dir, "https://support.example/cp", "wss://support.example/ws", strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if !m.SupportAvailable() {
		t.Fatal("support exe not loaded")
	}
}

func supportBundleServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv, machines := newAttendedServer(t)
	// Wire in the extra stores that the bundle handler needs indirectly (MachineGroups is only
	// needed by handleManagedInstallBundle, but set it for completeness).
	srv.MachineGroups = NewInMemoryMachineGroupStore()
	srv.ManagedInstaller = supportBundleFixture(t)
	// Reuse the machines store that newAttendedServer already created; also expose it on
	// InMemoryMachineStore so callers can seed machines if needed.
	_ = machines
	return srv, ""
}

func TestAttendedSupportBundleServesZipWithSidecar(t *testing.T) {
	srv, _ := supportBundleServer(t)
	const code = "0123456789ABC"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/attended-sessions/support-bundle", strings.NewReader(`{"code":"`+code+`"}`)))
	if rec.Code != 200 {
		t.Fatalf("status%d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("bundle response can be cached")
	}
	if rec.Header().Get("Content-Type") != "application/zip" {
		t.Fatal("wrong content-type")
	}
	z, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = b
	}
	if len(files) != 3 {
		t.Fatalf("files=%d", len(files))
	}
	if !bytes.Equal(files["DeskRallySupport.exe"], srv.ManagedInstaller.support) {
		t.Fatal("wrong support exe")
	}
	if string(files["session.code"]) != code {
		t.Fatalf("wrong sidecar code: %q", files["session.code"])
	}
	if len(files["README.txt"]) == 0 {
		t.Fatal("missing README")
	}
}

func TestAttendedSupportBundleRejectsInvalidCodeShape(t *testing.T) {
	srv, _ := supportBundleServer(t)
	for _, bad := range []string{
		"",
		"0123456789AB",           // 12 chars (too short)
		"0123456789ABCD",         // 14 chars (too long)
		"0123456789ABi",          // lowercase 'i' not in Crockford
		"0123456789ABL",          // 'L' not in Crockford alphabet
		"0123456789ABO",          // 'O' not in Crockford alphabet
		"0123456789ABU",          // 'U' not in Crockford alphabet
		"0123456789AB!",          // punctuation
	} {
		body := `{"code":"` + bad + `"}`
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/attended-sessions/support-bundle", strings.NewReader(body)))
		if rec.Code != 400 {
			t.Errorf("code %q: status%d, want 400", bad, rec.Code)
		}
	}
}

func TestAttendedSupportBundleUnavailableWithoutSupportExe(t *testing.T) {
	srv, _ := newAttendedServer(t)
	_, srv.ManagedInstaller = installerFixture(t) // no support exe in this fixture
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/attended-sessions/support-bundle", strings.NewReader(`{"code":"0123456789ABC"}`)))
	if rec.Code != 503 {
		t.Fatalf("status%d, want 503", rec.Code)
	}
}

func TestAttendedSupportBundleRateLimited(t *testing.T) {
	srv, _ := supportBundleServer(t)
	// Exhaust the support allowance (active cap 2) without releasing.
	for srv.ManagedInstaller.acquireSupport() {
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/attended-sessions/support-bundle", strings.NewReader(`{"code":"0123456789ABC"}`)))
	if rec.Code != 429 {
		t.Fatalf("status%d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
}

// Security audit 2026-10-18: the anonymous support-bundle route cannot spend the authenticated
// install budget, through the handler itself, and the reverse holds too.
func TestAttendedSupportBundleCannotStarveManagedInstalls(t *testing.T) {
	srv, _ := supportBundleServer(t)
	for i := 0; i < 8; i++ {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/attended-sessions/support-bundle", strings.NewReader(`{"code":"0123456789ABC"}`)))
	}
	if !srv.ManagedInstaller.acquire() {
		t.Fatal("anonymous support-bundle requests spent the managed-install allowance")
	}
	srv.ManagedInstaller.release()
	srv, _ = supportBundleServer(t) // fresh allowances for the reverse direction
	for srv.ManagedInstaller.acquire() {
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/attended-sessions/support-bundle", strings.NewReader(`{"code":"0123456789ABC"}`)))
	if rec.Code != 200 {
		t.Fatalf("support bundle with the install budget exhausted = %d, want 200", rec.Code)
	}
}

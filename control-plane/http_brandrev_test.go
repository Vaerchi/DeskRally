package controlplane

// The Owner and operator HTTP surfaces of branding revisions (docs/66 stage 1b) over the in-memory stores. The
// storage rules are the contract suites'; this file is about who may call what, what is validated before any
// child process is spent, the logo path through the real child, and the operator's review and findings.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/color"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	brOwnerTenant = "00000000-0000-0000-0000-0000000000bb"
	brTargetID    = "00000000-0000-0000-0000-0000000000ee"
)

type brandSrv struct {
	srv   *Server
	hosts *InMemoryHostnameStore
	brand *InMemoryBrandingStore
}

func newBrandSrv(t *testing.T, role Role, session string) *brandSrv {
	t.Helper()
	p := &Principal{
		UserID: "00000000-0000-0000-0000-0000000000aa", TenantID: brOwnerTenant, SessionID: session,
		Grant: NewGrant("00000000-0000-0000-0000-0000000000aa", brOwnerTenant, NewMembership(role, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: p}, &recordingBinder{})
	srv.MgmtAudit = NewInMemoryMgmtAuditStore()
	hosts := &InMemoryHostnameStore{}
	srv.Hostnames, srv.TenantHostSuffix, srv.HostPolicy = hosts, ".example.test", scopedPolicy(t)
	brand := NewInMemoryBrandingStore(hosts)
	srv.BrandingRevisions = brand
	srv.LogoConverter = testConverter(2, 8, "logo-convert")
	return &brandSrv{srv: srv, hosts: hosts, brand: brand}
}

func (b *brandSrv) call(method, path, body string) (int, map[string]any, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	b.srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec
}

func revBody(name string, extra string) string {
	return `{"product_name":"` + name + `","accent_color":"#35654a","support_text":"Open 9-5","support_contact":{"kind":"phone","value":"+1 555 010 0199"}` + extra + `}`
}

func pngDataURI(raw []byte) string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(raw)
}

func TestOwnerCreatesRevisionsAndNothingPublishes(t *testing.T) {
	b := newBrandSrv(t, RoleOwner, "00000000-0000-0000-0000-0000000000dd")
	code, out, _ := b.call("POST", "/tenant/branding/revisions", revBody("Acme Support", ""))
	if code != http.StatusCreated || out["created"] != true {
		t.Fatalf("create: %d %v", code, out)
	}
	rev := out["revision"].(map[string]any)
	if rev["seq"].(float64) != 1 || rev["product_name"] != "Acme Support" || len(rev["normalized_hash"].(string)) != 64 {
		t.Fatalf("revision: %v", rev)
	}
	if _, has := rev["logo_png"]; has {
		t.Error("the revision JSON carries logo bytes")
	}
	if code, out, _ = b.call("POST", "/tenant/branding/revisions", revBody("Acme Support", "")); code != http.StatusOK || out["created"] != false {
		t.Fatalf("identical edit: %d %v", code, out)
	}
	code, out, _ = b.call("GET", "/tenant/branding/revisions", "")
	st := out["state"].(map[string]any)
	if code != 200 || st["live"] != false || st["published"] != nil || st["draft"] == nil || out["logo_upload_supported"] != true {
		t.Fatalf("state: %d %v", code, out)
	}
	if n := len(b.srv.MgmtAudit.(*InMemoryMgmtAuditStore).events); n != 1 {
		t.Errorf("audit rows = %d, want exactly one (the no-op edit writes none)", n)
	}
}

func TestRevisionRoutesRequireTheOwnerCapability(t *testing.T) {
	for _, role := range []Role{RoleAdmin, RoleTechnician} {
		b := newBrandSrv(t, role, "00000000-0000-0000-0000-0000000000dd")
		if code, _, _ := b.call("POST", "/tenant/branding/revisions", revBody("Acme Support", "")); code != http.StatusForbidden {
			t.Errorf("%v: POST = %d, want 403 (Owner-only: CapManageTenant)", role, code)
		}
		// Reading the state is any authenticated member.
		if code, _, _ := b.call("GET", "/tenant/branding/revisions", ""); code != http.StatusOK {
			t.Errorf("%v: GET = %d", role, code)
		}
	}
}

func TestRevisionValidationRefusesBeforeAnyChildIsSpent(t *testing.T) {
	b := newBrandSrv(t, RoleOwner, "00000000-0000-0000-0000-0000000000dd")
	started0, _ := b.srv.LogoConverter.Stats()
	logo := `,"logo_data_uri":"` + pngDataURI(solidPNG(t, 20, 20, colorBlack)) + `"`
	cases := map[string]struct{ body, field string }{
		"bidi name":        {revBody("Acme"+U(0x202e)+"Support", logo), "product_name"},
		"short name":       {revBody("Ab", logo), "product_name"},
		"bad contrast":     {strings.Replace(revBody("Acme Support", logo), "#35654a", "#aaaaaa", 1), "accent_color"},
		"zero width text":  {strings.Replace(revBody("Acme Support", logo), "Open 9-5", "Open"+U(0x200b)+"now", 1), "support_text"},
		"bad contact kind": {strings.Replace(revBody("Acme Support", logo), `"phone"`, `"fax"`, 1), "support_contact"},
		"http contact":     {strings.Replace(strings.Replace(revBody("Acme Support", logo), `"phone"`, `"url"`, 1), "+1 555 010 0199", "http://x.example.com", 1), "support_contact"},
		"logo and keep":    {revBody("Acme Support", logo+`,"keep_logo":true`), "logo"},
	}
	for name, c := range cases {
		code, out, _ := b.call("POST", "/tenant/branding/revisions", c.body)
		if code != http.StatusBadRequest || out["field"] != c.field {
			t.Errorf("%s: %d %v (want 400 on %s)", name, code, out, c.field)
		}
	}
	if code, out, _ := b.call("POST", "/tenant/branding/revisions", strings.Replace(revBody("Acme Support", ""), "#35654a", "#aaaaaa", 1)); code != 400 || !strings.Contains(out["error"].(string), "contrast") {
		t.Errorf("the contrast refusal must carry the measured ratio: %v", out)
	}
	if s, _ := b.srv.LogoConverter.Stats(); s != started0 {
		t.Errorf("a text refusal still spent %d child process(es)", s-started0)
	}
	if code, _, _ := b.call("POST", "/tenant/branding/revisions", `{"product_name":`); code != 400 {
		t.Errorf("malformed json: %d", code)
	}
}

func TestLogoUploadGoesThroughTheChild(t *testing.T) {
	b := newBrandSrv(t, RoleOwner, "00000000-0000-0000-0000-0000000000dd")
	png := solidPNG(t, 800, 400, colorBlack)
	code, out, _ := b.call("POST", "/tenant/branding/revisions", revBody("Logo Co", `,"logo_data_uri":"`+pngDataURI(png)+`"`))
	if code != http.StatusCreated {
		t.Fatalf("upload: %d %v", code, out)
	}
	rev := out["revision"].(map[string]any)
	if rev["has_logo"] != true || len(rev["logo_sha256"].(string)) != 64 {
		t.Fatalf("revision: %v", rev)
	}
	if s, _ := b.srv.LogoConverter.Stats(); s != 1 {
		t.Errorf("children started = %d", s)
	}
	// keep_logo reuses the stored bytes without a child.
	code, out, _ = b.call("POST", "/tenant/branding/revisions", revBody("Logo Co Two", `,"keep_logo":true`))
	if code != http.StatusCreated || out["revision"].(map[string]any)["logo_sha256"] != rev["logo_sha256"] {
		t.Fatalf("keep_logo: %d %v", code, out)
	}
	if s, _ := b.srv.LogoConverter.Stats(); s != 1 {
		t.Errorf("keep_logo spent a child: %d", s)
	}
	// Refusals from the child are 400s with the logo field; WebP is refused before the child.
	for name, uri := range map[string]string{
		"svg":        "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<svg/>")),
		"webp":       "data:image/webp;base64," + base64.StdEncoding.EncodeToString([]byte("RIFF\x00\x00\x00\x00WEBP")),
		"bomb":       pngDataURI(bombPNG(30000, 30000)),
		"truncated":  pngDataURI(png[:40]),
		"svg as png": pngDataURI([]byte("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>")),
		"not base64": "data:image/png;base64,@@@@",
	} {
		code, out, _ := b.call("POST", "/tenant/branding/revisions", revBody("Logo Co Three", `,"logo_data_uri":"`+uri+`"`))
		if code != http.StatusBadRequest || out["field"] != "logo" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	// An over-size file is refused before the child.
	big := pngDataURI(append(append([]byte(nil), logoPNGMagic...), make([]byte, LogoMaxInputBytes)...))
	started, _ := b.srv.LogoConverter.Stats()
	if code, _, _ := b.call("POST", "/tenant/branding/revisions", revBody("Logo Co Four", `,"logo_data_uri":"`+big+`"`)); code != 400 && code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize: %d", code)
	}
	if s, _ := b.srv.LogoConverter.Stats(); s != started {
		t.Errorf("oversize image spent a child")
	}
}

func TestLogoUploadIsRefusedWhereNoConverterOrBusyOrOverBudget(t *testing.T) {
	b := newBrandSrv(t, RoleOwner, "00000000-0000-0000-0000-0000000000dd")
	png := pngDataURI(solidPNG(t, 20, 20, colorBlack))
	b.srv.LogoConverter = nil
	code, out, _ := b.call("POST", "/tenant/branding/revisions", revBody("No Child", `,"logo_data_uri":"`+png+`"`))
	if code != http.StatusNotImplemented || !strings.Contains(out["error"].(string), "not supported") {
		t.Fatalf("no converter: %d %v", code, out)
	}
	if code, out, _ := b.call("GET", "/tenant/branding/revisions", ""); out["logo_upload_supported"] != false || code != 200 {
		t.Errorf("the console must be told to hide the field: %v", out)
	}
	// A text-only revision still works without a converter.
	if code, _, _ := b.call("POST", "/tenant/branding/revisions", revBody("No Child", "")); code != http.StatusCreated {
		t.Errorf("text-only without converter: %d", code)
	}
	// Queue full: 429 with Retry-After.
	busy := NewLogoConverter(1, 0)
	busy.Command = selfCmd("logo-test-hang")
	busy.Deadline = 600 * 1e6
	b.srv.LogoConverter = busy
	go func() { _, _ = busy.Convert(t.Context(), solidPNG(t, 8, 8, colorBlack)) }()
	eventually(t, 2e9, "the slot to be taken", func() bool { s, _ := busy.Stats(); return s == 1 })
	code, _, rec := b.call("POST", "/tenant/branding/revisions", revBody("Busy Co", `,"logo_data_uri":"`+png+`"`))
	if code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("busy: %d", code)
	}
	// Per-tenant upload budget: 10 a minute.
	b.srv.LogoConverter = testConverter(2, 8, "logo-convert")
	b.srv.logoRate = newRateBudget(logoUploadsPerMinute, 60*1e9, 100)
	b.srv.logoRateOnce.Do(func() {})
	n429 := 0
	for i := 0; i < logoUploadsPerMinute+3; i++ {
		img := pngDataURI(solidPNG(t, 10+i, 10, colorBlack))
		if code, _, _ := b.call("POST", "/tenant/branding/revisions", revBody("Budget Co "+string(rune('A'+i)), `,"logo_data_uri":"`+img+`"`)); code == http.StatusTooManyRequests {
			n429++
		}
	}
	if n429 != 3 {
		t.Errorf("per-tenant upload budget: %d refusals, want 3", n429)
	}
}

// ---- the operator --------------------------------------------------------------------------------------------

func operatorWithDraft(t *testing.T, name string) (*brandSrv, *BrandingRevision, *HostnameAssignment) {
	t.Helper()
	b := newBrandSrv(t, RoleOwner, "00000000-0000-0000-0000-0000000000dd")
	asg, err := b.hosts.Assign(t.Context(), PlatformCaller{SessionID: "x"}, brTargetID, "widget.example.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	rev, _, err := b.brand.CreateRevision(t.Context(), brTargetID, "owner", BrandingRevisionInput{ProductName: name, AccentColor: "#35654a",
		SupportText: "Hello", Contact: BrandContact{Kind: "email", Value: "help@widget.example.test"}, LogoPNG: tinyLogo(t, 3)})
	if err != nil {
		t.Fatal(err)
	}
	return b, rev, asg
}

// genJSON is the review generation the operator's review would return right now.
func genJSON(b *brandSrv) string {
	rv, err := b.brand.Review(context.Background(), PlatformCaller{SessionID: "x"}, brTargetID)
	if err != nil {
		return `,"review_generation":0` // a non-operator cannot review: the refusal is what the test is about
	}
	return fmt.Sprintf(`,"review_generation":%d`, rv.Generation)
}

func approveBody(b *brandSrv, rev *BrandingRevision, asg *HostnameAssignment, extra string) string {
	return `{"revision_id":"` + rev.ID + `","normalized_hash":"` + rev.Hash + `","assignment_id":"` + asg.ID + `"` + genJSON(b) + extra + `}`
}

func TestOperatorReviewShowsTheRenderedIdentityWithFindings(t *testing.T) {
	b, rev, asg := operatorWithDraft(t, "Widget Support")
	code, out, _ := b.call("GET", "/platform/tenants/"+brTargetID+"/branding/review", "")
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	rv := out["review"].(map[string]any)
	draft := rv["draft"].(map[string]any)
	if draft["id"] != rev.ID || draft["normalized_hash"] != rev.Hash || draft["product_name"] != "Widget Support" {
		t.Errorf("draft: %v", draft)
	}
	if rv["assignment"].(map[string]any)["id"] != asg.ID {
		t.Errorf("assignment: %v", rv["assignment"])
	}
	raw, err := base64.StdEncoding.DecodeString(out["logo_png_base64"].(string))
	if err != nil || VerifyConvertedLogo(raw) != nil {
		t.Errorf("the review must carry the exact logo to render: %v", err)
	}
	if f := out["findings"].([]any); len(f) != 0 {
		t.Errorf("clean name has findings: %v", f)
	}
	// A lookalike gets findings listed.
	b2, _, _ := operatorWithDraft(t, "Micr0soft Helpdesk")
	_, out, _ = b2.call("GET", "/platform/tenants/"+brTargetID+"/branding/review", "")
	if f := out["findings"].([]any); len(f) == 0 {
		t.Errorf("a denylisted lookalike has no findings")
	}
}

func TestOperatorApproveIsACompareAndSwapAndRequiresAcknowledgementOfFindings(t *testing.T) {
	b, rev, asg := operatorWithDraft(t, "Widget Support")
	path := "/platform/tenants/" + brTargetID + "/branding/approve"
	for name, body := range map[string]string{
		"wrong hash":       `{"revision_id":"` + rev.ID + `","normalized_hash":"` + strings.Repeat("0", 64) + `","assignment_id":"` + asg.ID + `"` + genJSON(b) + `}`,
		"wrong assignment": `{"revision_id":"` + rev.ID + `","normalized_hash":"` + rev.Hash + `","assignment_id":"` + newUUID() + `"` + genJSON(b) + `}`,
		"wrong revision":   `{"revision_id":"` + newUUID() + `","normalized_hash":"` + rev.Hash + `","assignment_id":"` + asg.ID + `"` + genJSON(b) + `}`,
	} {
		code, out, _ := b.call("POST", path, body)
		if code != http.StatusConflict || out["code"] != "stale" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	for name, body := range map[string]string{"missing ids": `{}`, "bad hash": `{"revision_id":"` + rev.ID + `","normalized_hash":"x","assignment_id":"` + asg.ID + `"` + genJSON(b) + `}`} {
		if code, _, _ := b.call("POST", path, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	// An approval that does not carry the review generation is refused outright (a missing field must not mean 0).
	noGen := `{"revision_id":"` + rev.ID + `","normalized_hash":"` + rev.Hash + `","assignment_id":"` + asg.ID + `"}`
	if code, _, _ := b.call("POST", path, noGen); code != http.StatusBadRequest {
		t.Errorf("approval without review_generation: %d, want 400", code)
	}
	if p, _ := b.brand.PublicLookup(t.Context(), "widget.example.test", false); p != nil {
		t.Fatal("published by a refused approval")
	}
	code, out, _ := b.call("POST", path, approveBody(b, rev, asg, ""))
	if code != http.StatusOK || out["published"].(map[string]any)["revision_id"] != rev.ID {
		t.Fatalf("approve: %d %v", code, out)
	}
	if n := len(b.hosts.Audit); n < 4 {
		t.Errorf("approval not audited on both chains: %v", b.hosts.Audit)
	}

	// Findings: 409 until EVERY code is acknowledged with a reason; the override is recorded.
	b2, rev2, asg2 := operatorWithDraft(t, "Micr0soft Helpdesk")
	code, out, _ = b2.call("POST", path, approveBody(b2, rev2, asg2, ""))
	if code != http.StatusConflict || out["code"] != "findings" || len(out["findings"].([]any)) == 0 {
		t.Fatalf("approve with findings, no acknowledgement: %d %v", code, out)
	}
	var codes []string
	for _, f := range out["findings"].([]any) {
		codes = append(codes, `"`+f.(map[string]any)["code"].(string)+`"`)
	}
	ack := `,"acknowledge":[` + strings.Join(codes, ",") + `]`
	if code, _, _ = b2.call("POST", path, approveBody(b2, rev2, asg2, ack)); code != http.StatusConflict {
		t.Errorf("acknowledged without a reason: %d", code)
	}
	if code, _, _ = b2.call("POST", path, approveBody(b2, rev2, asg2, `,"acknowledge":["unrelated"],"override_reason":"ok"`)); code != http.StatusConflict {
		t.Errorf("acknowledged the wrong code: %d", code)
	}
	if p, _ := b2.brand.PublicLookup(t.Context(), "widget.example.test", false); p != nil {
		t.Fatal("published without the override")
	}
	if code, out, _ = b2.call("POST", path, approveBody(b2, rev2, asg2, ack+`,"override_reason":"customer is the real Micr0soft reseller"`)); code != http.StatusOK {
		t.Fatalf("override: %d %v", code, out)
	}
	if _, err := b2.hosts.Activate(t.Context(), PlatformCaller{SessionID: "x"}, asg2.ID, nil); err != nil {
		t.Fatal(err)
	}
	if p, _ := b2.brand.PublicLookup(t.Context(), "widget.example.test", false); p == nil {
		t.Error("the overridden approval did not publish")
	}
}

func TestOperatorWithdrawNeedsAReasonAndIsAudited(t *testing.T) {
	b, rev, asg := operatorWithDraft(t, "Widget Support")
	if code, _, _ := b.call("POST", "/platform/tenants/"+brTargetID+"/branding/approve", approveBody(b, rev, asg, "")); code != 200 {
		t.Fatal(code)
	}
	path := "/platform/tenants/" + brTargetID + "/branding/withdraw"
	if code, _, _ := b.call("POST", path, `{}`); code != http.StatusBadRequest {
		t.Errorf("withdraw without a reason: %d", code)
	}
	if code, _, _ := b.call("POST", path, `{"reason":"impersonation complaint"}`); code != http.StatusOK {
		t.Errorf("withdraw: %d", code)
	}
	if code, out, _ := b.call("POST", path, `{"reason":"again"}`); code != http.StatusConflict || out["code"] != "not_published" {
		t.Errorf("second withdraw: %d %v", code, out)
	}
	if p, _ := b.brand.PublicLookup(t.Context(), "widget.example.test", false); p != nil {
		t.Error("still published after withdrawal")
	}
}

func TestOperatorRoutesRefuseNonOperatorsAndTokensWithoutASession(t *testing.T) {
	b, rev, asg := operatorWithDraft(t, "Widget Support")
	b.hosts.Authorize = func(PlatformCaller) bool { return false }
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/platform/tenants/" + brTargetID + "/branding/review", ""},
		{"POST", "/platform/tenants/" + brTargetID + "/branding/approve", approveBody(b, rev, asg, "")},
		{"POST", "/platform/tenants/" + brTargetID + "/branding/withdraw", `{"reason":"x"}`},
	} {
		if code, _, _ := b.call(c.method, c.path, c.body); code != http.StatusForbidden {
			t.Errorf("non-operator %s %s: %d", c.method, c.path, code)
		}
	}
	tok := newBrandSrv(t, RoleOwner, "") // an API token has no interactive session
	if code, _, _ := tok.call("GET", "/platform/tenants/"+brTargetID+"/branding/review", ""); code != http.StatusForbidden {
		t.Errorf("session-less caller: %d", code)
	}
	if code, _, _ := b.call("GET", "/platform/tenants/not-a-uuid/branding/review", ""); code != http.StatusForbidden && code != http.StatusNotFound {
		t.Errorf("bad tenant id: %d", code)
	}
}

func TestPublicApprovalNeverFollowsFromAnOwnerEdit(t *testing.T) {
	// The whole point of P2: no sequence of Owner calls publishes anything.
	b := newBrandSrv(t, RoleOwner, "00000000-0000-0000-0000-0000000000dd")
	_, _ = b.hosts.Assign(t.Context(), PlatformCaller{SessionID: "x"}, brOwnerTenant, "owner.example.test", nil)
	for i := 0; i < 5; i++ {
		b.call("POST", "/tenant/branding/revisions", revBody("Owner Edit "+string(rune('A'+i)), ""))
	}
	b.call("PUT", "/tenant/branding", `{"product_name":"Console Name"}`)
	if p, _ := b.brand.PublicLookup(t.Context(), "owner.example.test", false); p != nil {
		t.Fatal("an Owner-only sequence published")
	}
}

var colorBlack = color.NRGBA{A: 255}

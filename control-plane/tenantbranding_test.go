package controlplane

// In-memory + handler proofs for per-tenant branding (docs/01 §9): the validation gate, the store
// contract, and the HTTP surface (GET is any-authenticated, PUT is CapManageTenant, invalid input is
// a 400). The DB-gated RLS isolation is in tenantbranding_pgstore_test.go.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// dataURI builds a data:image/<subtype>;base64,<payload> from raw bytes, for the logo tests.
func dataURI(subtype string, raw []byte) string {
	return "data:image/" + subtype + ";base64," + base64.StdEncoding.EncodeToString(raw)
}

var (
	pngMagic  = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	validPNG  = dataURI("png", append(append([]byte{}, pngMagic...), 1, 2, 3))
	validGIF  = dataURI("gif", []byte("GIF89a\x00\x00"))
	validJPEG = dataURI("jpeg", []byte{0xFF, 0xD8, 0xFF, 0x00})
	validWEBP = dataURI("webp", append([]byte("RIFF\x00\x00\x00\x00WEBP"), 1, 2, 3, 4))
)

func TestValidateLogoDataURI(t *testing.T) {
	for _, s := range []string{"", validPNG, validGIF, validJPEG, validWEBP} {
		if !ValidateLogoDataURI(s) {
			t.Errorf("want valid, got invalid: %.48q", s)
		}
	}
	bad := map[string]string{
		"svg (script-bearing) is refused outright": dataURI("svg+xml", []byte("<svg onload=alert(1)/>")),
		"png label but gif bytes (mislabeled)":     dataURI("png", []byte("GIF89a")),
		"not a data URI at all":                    "https://evil.example/logo.png",
		"empty base64 payload":                     "data:image/png;base64,",
		"non-base64 payload":                       "data:image/png;base64,not*valid*b64",
		"oversized (decoded > MaxLogoBytes)":        dataURI("png", append(append([]byte{}, pngMagic...), make([]byte, MaxLogoBytes)...)),
		"unknown subtype":                          dataURI("bmp", []byte{0x42, 0x4D}),
		"webp too short for the RIFF/WEBP check":   dataURI("webp", []byte("RIFF")),
	}
	for name, s := range bad {
		if ValidateLogoDataURI(s) {
			t.Errorf("%s: want invalid, got valid", name)
		}
	}
}

func TestIsHexColor(t *testing.T) {
	for _, s := range []string{"#ff0000", "#00FF00", "#123abc", "#ABCDEF"} {
		if !IsHexColor(s) {
			t.Fatalf("IsHexColor(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "red", "#fff", "#fffffff", "ff0000", "#gg0000", "#12345"} {
		if IsHexColor(s) {
			t.Fatalf("IsHexColor(%q) = true, want false", s)
		}
	}
}

func TestNormalizeBranding(t *testing.T) {
	// Trims both fields; a valid accent + a within-cap name are accepted.
	got, ok := NormalizeBranding(Branding{ProductName: "  Acme Remote  ", AccentColor: "  #ff0000 "})
	if !ok || got.ProductName != "Acme Remote" || got.AccentColor != "#ff0000" {
		t.Fatalf("normalize = (%+v, %v), want trimmed + ok", got, ok)
	}
	// An empty accent is valid (means "use the default").
	if _, ok := NormalizeBranding(Branding{ProductName: "Acme", AccentColor: ""}); !ok {
		t.Fatal("empty accent must be valid")
	}
	// A non-hex accent is rejected.
	if _, ok := NormalizeBranding(Branding{AccentColor: "red"}); ok {
		t.Fatal("non-hex accent must be invalid")
	}
	// An over-long product name is rejected (the length is checked AFTER trimming).
	if _, ok := NormalizeBranding(Branding{ProductName: strings.Repeat("x", MaxProductNameLen+1)}); ok {
		t.Fatal("over-long product name must be invalid")
	}
	if _, ok := NormalizeBranding(Branding{ProductName: strings.Repeat("x", MaxProductNameLen)}); !ok {
		t.Fatal("exactly the cap must be valid")
	}
	// A control character (NUL in particular — invalid in a Postgres text column) is rejected, so the
	// in-memory fake and the pg store agree instead of diverging (200 vs 500).
	if _, ok := NormalizeBranding(Branding{ProductName: "Acme\x00Remote"}); ok {
		t.Fatal("a NUL in the product name must be invalid")
	}
	if _, ok := NormalizeBranding(Branding{ProductName: "Acme\nRemote"}); ok {
		t.Fatal("a newline in the product name must be invalid")
	}
	// The cap is in CHARACTERS (runes), not bytes: 100 accented letters (200 bytes) is VALID, 101 is not.
	if _, ok := NormalizeBranding(Branding{ProductName: strings.Repeat("é", MaxProductNameLen)}); !ok {
		t.Fatal("100 multi-byte characters must be valid (rune cap, not byte cap)")
	}
	if _, ok := NormalizeBranding(Branding{ProductName: strings.Repeat("é", MaxProductNameLen+1)}); ok {
		t.Fatal("101 characters must be invalid even though the byte count differs")
	}
	// A valid raster logo passes and is preserved; an SVG (or any invalid logo) fails the whole set.
	if got, ok := NormalizeBranding(Branding{ProductName: "Acme", LogoDataURI: validPNG}); !ok || got.LogoDataURI != validPNG {
		t.Fatalf("valid logo = %+v ok=%v, want preserved", got, ok)
	}
	if _, ok := NormalizeBranding(Branding{LogoDataURI: dataURI("svg+xml", []byte("<svg/>"))}); ok {
		t.Fatal("an SVG logo must be rejected")
	}
}

func TestInMemoryTenantBranding(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryTenantBrandingStore()
	// Unset → the zero Branding (defaults).
	if b, _ := s.Get(ctx, "t1"); b != (Branding{}) {
		t.Fatalf("unset branding = %+v, want zero", b)
	}
	if err := s.Set(ctx, "t1", Branding{ProductName: "Acme", AccentColor: "#ff0000"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if b, _ := s.Get(ctx, "t1"); b.ProductName != "Acme" || b.AccentColor != "#ff0000" {
		t.Fatalf("get after set = %+v", b)
	}
	// Another tenant is unaffected (the fake is tenant-scoped like the pg store's RLS).
	if b, _ := s.Get(ctx, "t2"); b != (Branding{}) {
		t.Fatalf("other tenant leaked = %+v", b)
	}
}

func brandingReq(t *testing.T, role Role, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(role, AllGroups())),
	}
	srv, _ := newTestServer(p)
	rec := httptest.NewRecorder()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, "/tenant/branding", strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, "/tenant/branding", nil)
	}
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

func TestTenantBrandingHandler(t *testing.T) {
	// GET needs no capability — any authenticated member themes their console.
	if rec := brandingReq(t, RoleReadOnly, "GET", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET as ReadOnly = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	// A fresh tenant reads defaults (empty strings).
	rec := brandingReq(t, RoleOwner, "GET", "")
	var got Branding
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got != (Branding{}) {
		t.Fatalf("default branding = %+v, want empty", got)
	}
	// PUT requires CapManageTenant: an Admin is denied.
	if rec := brandingReq(t, RoleAdmin, "PUT", `{"product_name":"X","accent_color":"#ff0000"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("PUT as Admin = %d, want 403", rec.Code)
	}
	// PUT validates: a non-hex accent and an over-long name are 400.
	if rec := brandingReq(t, RoleOwner, "PUT", `{"accent_color":"red"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT bad accent = %d, want 400", rec.Code)
	}
	if rec := brandingReq(t, RoleOwner, "PUT", `{"product_name":"`+strings.Repeat("x", 101)+`"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT long name = %d, want 400", rec.Code)
	}
}

// TestTenantBrandingSetThenGet drives PUT then GET over ONE server so the round-trip (trim + persist +
// read-back) is proven end to end through the HTTP surface.
func TestTenantBrandingSetThenGet(t *testing.T) {
	p := &Principal{
		UserID:   "owner-1",
		TenantID: "tenant-123",
		Grant:    NewGrant("owner-1", "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
	srv, _ := newTestServer(p)

	put := httptest.NewRecorder()
	srv.Handler().ServeHTTP(put, httptest.NewRequest("PUT", "/tenant/branding",
		strings.NewReader(`{"product_name":"  Acme Remote  ","accent_color":"#3b82f6"}`)))
	if put.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200 (%s)", put.Code, put.Body.String())
	}
	// The PUT echoes the TRIMMED value.
	var echoed Branding
	if err := json.Unmarshal(put.Body.Bytes(), &echoed); err != nil {
		t.Fatalf("decode PUT: %v", err)
	}
	if echoed.ProductName != "Acme Remote" {
		t.Fatalf("PUT echo product = %q, want trimmed", echoed.ProductName)
	}

	get := httptest.NewRecorder()
	srv.Handler().ServeHTTP(get, httptest.NewRequest("GET", "/tenant/branding", nil))
	var got Branding
	if err := json.Unmarshal(get.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if got.ProductName != "Acme Remote" || got.AccentColor != "#3b82f6" {
		t.Fatalf("GET after PUT = %+v", got)
	}
}

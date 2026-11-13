package controlplane

// Per-tenant branding (docs/01 §9) — white-label settings a tenant admin sets and every member's
// console reads to theme itself: a product name (console title/header) and an accent colour (the
// console's `--accent` CSS variable). Persistence seam in the same shape as the other tenant-scoped
// stores: a TenantBrandingStore interface, an in-memory fake for tests + dev, and a pgx impl
// (PgTenantBrandingStore) over `tenant_branding` (migrations/0028). Validation lives in
// NormalizeBranding, shared by the handler; the pure IsHexColor mirrors the viewer's isHexColor.

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Branding is a tenant's white-label settings. Empty fields mean "use the product default": an
// empty ProductName keeps the built-in name, an empty AccentColor keeps the built-in accent, and an
// empty LogoDataURI shows no logo (the text name).
type Branding struct {
	ProductName string `json:"product_name"`
	AccentColor string `json:"accent_color"`
	// LogoDataURI is empty, or a validated raster-image data URI (data:image/<png|jpeg|gif|webp>;base64,…)
	// the console header renders in an <img>. Validated by ValidateLogoDataURI before it is ever stored.
	LogoDataURI string `json:"logo_data_uri"`
}

// MaxProductNameLen bounds the product name — a title/header label, not free-form content.
const MaxProductNameLen = 100

// MaxLogoBytes bounds the DECODED logo image (not the base64 text): a header logo, not an asset store.
const MaxLogoBytes = 128 * 1024

// logoDataURIRe splits a raster-image data URI into its declared subtype and base64 payload. Only the
// four raster types are allowed; SVG is deliberately excluded (an <img> will not run its scripts, but
// refusing it removes any question and keeps the stored value a plain bitmap).
var logoDataURIRe = regexp.MustCompile(`^data:image/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/]+={0,2})$`)

// rasterMagic maps a declared subtype to the leading bytes a real file of that type must start with, so
// a payload cannot be mislabeled (e.g. SVG or a script smuggled under image/png).
var rasterMagic = map[string][]byte{
	"png":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
	"jpeg": {0xFF, 0xD8, 0xFF},
	"gif":  {0x47, 0x49, 0x46, 0x38}, // "GIF8"
}

// ValidateLogoDataURI reports whether s is an acceptable logo: empty (no logo), or a base64 data URI of
// an allowed raster type whose DECODED bytes start with that type's magic number and are within
// MaxLogoBytes. WebP is matched structurally ("RIFF"…"WEBP") rather than by a single prefix.
func ValidateLogoDataURI(s string) bool {
	if s == "" {
		return true
	}
	m := logoDataURIRe.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	subtype, b64 := m[1], m[2]
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 || len(raw) > MaxLogoBytes {
		return false
	}
	if subtype == "webp" {
		return len(raw) >= 12 && string(raw[0:4]) == "RIFF" && string(raw[8:12]) == "WEBP"
	}
	magic := rasterMagic[subtype]
	if magic == nil || len(raw) < len(magic) {
		return false
	}
	for i, b := range magic {
		if raw[i] != b {
			return false
		}
	}
	return true
}

// hexColorRe matches a `#rrggbb` colour (the form a browser <input type=color> and CSS both accept).
var hexColorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// IsHexColor reports whether s is a `#rrggbb` hex colour. Empty is NOT a hex colour; callers treat an
// empty accent as "no override" and validate it separately. Mirrors the viewer's isHexColor.
func IsHexColor(s string) bool { return hexColorRe.MatchString(s) }

// NormalizeBranding trims both fields and reports whether the result is VALID: the product name must
// contain no control characters and be within the length cap (in CHARACTERS), and the accent must be
// empty or a `#rrggbb` hex colour. The normalized value is returned regardless (the handler stores it
// only when ok). Keeping this pure + shared means the server never persists an accent the CSS could
// not apply, and it makes the in-memory fake and the pg store agree on which inputs are accepted.
func NormalizeBranding(b Branding) (Branding, bool) {
	out := Branding{
		ProductName: strings.TrimSpace(b.ProductName),
		AccentColor: strings.TrimSpace(b.AccentColor),
		// A data URI carries no leading/trailing whitespace; trimming is harmless and defends against a
		// stray newline a client might append.
		LogoDataURI: strings.TrimSpace(b.LogoDataURI),
	}
	// Reject control characters in the product name — it is a single-line display label. This is not
	// only cosmetic: a NUL (U+0000) is invalid in a Postgres `text` column, so the in-memory fake would
	// store it (200) while the pg store's INSERT would fail (500). Rejecting here makes both stores
	// agree and turns that divergence into an honest 400.
	if strings.ContainsFunc(out.ProductName, unicode.IsControl) {
		return out, false
	}
	// Cap by RUNE count, not bytes, so "at most 100 characters" is accurate and matches the console
	// input's maxLength for ordinary text. A byte cap wrongly rejected accented/CJK names well before
	// the advertised limit (100 'é' = 200 bytes; a 34-char Japanese name = ~102 bytes).
	if utf8.RuneCountInString(out.ProductName) > MaxProductNameLen {
		return out, false
	}
	if out.AccentColor != "" && !IsHexColor(out.AccentColor) {
		return out, false
	}
	if !ValidateLogoDataURI(out.LogoDataURI) {
		return out, false
	}
	return out, true
}

// TenantBrandingStore is the persistence seam for per-tenant branding. Production wires
// PgTenantBrandingStore (RLS-scoped via withTenant); tests + dev wire InMemoryTenantBrandingStore.
type TenantBrandingStore interface {
	// Get returns the tenant's branding, or a zero Branding (all defaults) when none has been set.
	Get(ctx context.Context, tenantID string) (Branding, error)
	// Set upserts the tenant's branding (one row per tenant). The caller normalizes/validates first.
	Set(ctx context.Context, tenantID string, b Branding) error
}

// -------------------------------------------------------------------------------------
// InMemoryTenantBrandingStore — concurrency-safe fake for tests + dev. A plain tenantID -> Branding
// map; an absent entry is the zero Branding, exactly what the pg store returns for no row.
// -------------------------------------------------------------------------------------

type InMemoryTenantBrandingStore struct {
	mu       sync.Mutex
	branding map[string]Branding
}

// NewInMemoryTenantBrandingStore constructs an empty in-memory branding store.
func NewInMemoryTenantBrandingStore() *InMemoryTenantBrandingStore {
	return &InMemoryTenantBrandingStore{branding: make(map[string]Branding)}
}

var _ TenantBrandingStore = (*InMemoryTenantBrandingStore)(nil)

// Get implements TenantBrandingStore: the stored branding, or the zero value when unset.
func (s *InMemoryTenantBrandingStore) Get(_ context.Context, tenantID string) (Branding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.branding[tenantID], nil
}

// Set implements TenantBrandingStore: overwrite the tenant's branding.
func (s *InMemoryTenantBrandingStore) Set(_ context.Context, tenantID string, b Branding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.branding[tenantID] = b
	return nil
}

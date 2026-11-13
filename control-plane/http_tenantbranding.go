package controlplane

// Per-tenant branding handlers (docs/01 §9): GET /tenant/branding (any authenticated member reads
// it to theme their console) and PUT /tenant/branding (CapManageTenant sets it). Both are tenant-
// scoped by the pinned tenant + RLS.

import (
	"net/http"
)

func (s *Server) handleGetTenantBranding(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	// No capability check: branding is display data every authenticated member needs to theme their
	// own console. It stays tenant-scoped (the pinned tenant + RLS), and it reveals nothing sensitive.
	if s.TenantBranding == nil {
		writeError(w, http.StatusInternalServerError, "branding store not configured")
		return
	}
	b, err := s.TenantBranding.Get(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read branding")
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) handleSetTenantBranding(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.TenantBranding == nil {
		writeError(w, http.StatusInternalServerError, "branding store not configured")
		return
	}
	var req Branding
	// The branding tier (bodylimit.go), because the body now carries an optional logo as a base64 raster
	// data URI (decoded cap MaxLogoBytes). It is sized to that logo and no larger; product_name and
	// accent_color remain bounded far below by their own validators.
	if err := decodeJSONBodyDetailed(w, r, maxBrandingBodyBytes, &req, "malformed branding body"); err != nil {
		return
	}
	norm, ok := NormalizeBranding(req)
	if !ok {
		writeError(w, http.StatusBadRequest,
			"invalid branding: product_name must be at most 100 characters with no control characters, accent_color must be empty or a #rrggbb hex colour, and logo must be empty or a PNG/JPEG/GIF/WebP data URI at most 128 KiB")
		return
	}
	if err := s.TenantBranding.Set(r.Context(), p.TenantID, norm); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save branding")
		return
	}
	if err := s.recordMgmtAudit(r, "tenant.branding.set", "tenant", p.TenantID,
		map[string]any{"product_name": norm.ProductName, "accent_color": norm.AccentColor, "has_logo": norm.LogoDataURI != ""}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// Echo the normalized value the server stored (trimmed), so the console adopts exactly that.
	writeJSON(w, http.StatusOK, norm)
}

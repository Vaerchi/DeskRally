package controlplane

// Branding revision handlers (docs/66 stage 1b).
//
// OWNER (CapManageTenant for the write; any authenticated member reads):
//
//	POST /tenant/branding/revisions   create a new immutable draft revision (name, accent, support text,
//	                                  contact, logo). Moves only the DRAFT pointer: the previously approved
//	                                  revision stays published. Nothing an Owner does here publishes.
//	GET  /tenant/branding/revisions   draft, published, the tenant's current assignment, and whether guests
//	                                  see the published revision right now.
//
// PLATFORM OPERATOR (interactive session + recent second factor, decided by the database):
//
//	GET  /platform/tenants/{id}/branding/review    the draft exactly as stored (logo as base64) with the
//	                                               ids and hash the approval binds, and the automated findings
//	POST /platform/tenants/{id}/branding/approve   compare-and-swap publish (409 when stale), findings
//	                                               acknowledged with a reason, audited on both chains
//	POST /platform/tenants/{id}/branding/withdraw  clear the published pointer (audited on both chains)

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

// brandingRevisionRequest is the Owner's edit. The logo travels as a base64 raster data URI, as in the console
// (PNG, JPEG or GIF; at most 128 KiB decoded); keep_logo reuses the current draft's logo without re-sending it.
type brandingRevisionRequest struct {
	ProductName    string       `json:"product_name"`
	AccentColor    string       `json:"accent_color"`
	SupportText    string       `json:"support_text"`
	SupportContact BrandContact `json:"support_contact"`
	LogoDataURI    string       `json:"logo_data_uri"`
	KeepLogo       bool         `json:"keep_logo"`
}

// logoUploadsPerMinute is the per-tenant budget of logo conversions (docs/66 2a.8).
const logoUploadsPerMinute = 10

func (s *Server) logoBudget() *rateBudget {
	s.logoRateOnce.Do(func() { s.logoRate = newRateBudget(logoUploadsPerMinute, time.Minute, 10_000) })
	return s.logoRate
}

func writeBrandingErr(w http.ResponseWriter, err error) {
	var fe *BrandFieldError
	var le *LogoError
	switch {
	case errors.As(err, &fe):
		writeJSON(w, http.StatusBadRequest, fe)
	case errors.As(err, &le):
		writeJSON(w, http.StatusBadRequest, &BrandFieldError{Field: "logo", Msg: le.Msg})
	case errors.Is(err, ErrBrandingStale):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "review is stale: the revision, its hash or the hostname assignment changed; reload and review again", "code": "stale"})
	case errors.Is(err, ErrBrandingNotPublished):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "nothing is published for this tenant", "code": "not_published"})
	case errors.Is(err, ErrBrandingRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, ErrBrandingRateLimited.Error())
	case errors.Is(err, ErrBrandingBusy):
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, ErrBrandingBusy.Error())
	case errors.Is(err, ErrBrandingNoLogoToKeep):
		writeError(w, http.StatusBadRequest, ErrBrandingNoLogoToKeep.Error())
	case errors.Is(err, ErrLogoBusy):
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusTooManyRequests, ErrLogoBusy.Error())
	case errors.Is(err, ErrLogoUnsupported):
		writeError(w, http.StatusNotImplemented, ErrLogoUnsupported.Error())
	default:
		writeHostnameErr(w, err)
	}
}

// decodeLogoDataURI extracts the raw bytes of a PNG, JPEG or GIF data URI (WebP and SVG are refused here, before
// any child process is spent on them).
func decodeLogoDataURI(uri string) ([]byte, *BrandFieldError) {
	m := logoDataURIRe.FindStringSubmatch(strings.TrimSpace(uri))
	if m == nil {
		return nil, fieldErr("logo", "must be a base64 PNG, JPEG or GIF data URI")
	}
	if m[1] == "webp" {
		return nil, fieldErr("logo", "WebP logos are not supported; use PNG, JPEG or GIF")
	}
	raw, err := base64.StdEncoding.DecodeString(m[2])
	if err != nil || len(raw) == 0 {
		return nil, fieldErr("logo", "must be a base64 PNG, JPEG or GIF data URI")
	}
	if len(raw) > LogoMaxInputBytes {
		return nil, fieldErr("logo", "image file is larger than 128 KiB")
	}
	return raw, nil
}

// POST /tenant/branding/revisions
func (s *Server) handleCreateBrandingRevision(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.BrandingRevisions == nil {
		writeError(w, http.StatusInternalServerError, "branding store not configured")
		return
	}
	var req brandingRevisionRequest
	if err := decodeJSONBodyDetailed(w, r, maxBrandingBodyBytes, &req, "malformed branding revision body"); err != nil {
		return
	}
	// The text first: a refusal there must not cost a child process.
	in, ferr := PrepareBrandingRevision(BrandingRevisionInput{ProductName: req.ProductName, AccentColor: req.AccentColor,
		SupportText: req.SupportText, Contact: req.SupportContact, KeepLogo: req.KeepLogo})
	if ferr != nil {
		writeBrandingErr(w, ferr)
		return
	}
	if req.LogoDataURI != "" {
		if req.KeepLogo {
			writeBrandingErr(w, fieldErr("logo", "send a new logo or keep_logo, not both"))
			return
		}
		if s.LogoConverter == nil || !s.LogoConverter.Supported() {
			writeBrandingErr(w, ErrLogoUnsupported)
			return
		}
		raw, derr := decodeLogoDataURI(req.LogoDataURI)
		if derr != nil {
			writeBrandingErr(w, derr)
			return
		}
		if !s.logoBudget().Allow(p.TenantID) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many logo uploads; retry later")
			return
		}
		pngBytes, cerr := s.LogoConverter.Convert(r.Context(), raw)
		if cerr != nil {
			var le *LogoError
			if errors.As(cerr, &le) || errors.Is(cerr, ErrLogoBusy) || errors.Is(cerr, ErrLogoUnsupported) {
				writeBrandingErr(w, cerr)
			} else {
				writeError(w, http.StatusInternalServerError, "could not process the logo")
			}
			return
		}
		in.LogoPNG = pngBytes
	}
	rev, created, err := s.BrandingRevisions.CreateRevision(r.Context(), p.TenantID, p.UserID, in)
	if err != nil {
		writeBrandingErr(w, err)
		return
	}
	if created {
		if err := s.recordMgmtAudit(r, "tenant.branding.revision.create", "tenant", p.TenantID, map[string]any{
			"revision_id": rev.ID, "seq": rev.Seq, "normalized_hash": rev.Hash, "has_logo": rev.HasLogo, "logo_sha256": rev.LogoSHA256}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
	}
	status := http.StatusCreated
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"revision": rev, "created": created})
}

// GET /tenant/branding/revisions
func (s *Server) handleGetBrandingRevisions(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if s.BrandingRevisions == nil {
		writeError(w, http.StatusInternalServerError, "branding store not configured")
		return
	}
	st, err := s.BrandingRevisions.OwnerState(r.Context(), p.TenantID)
	if err != nil {
		writeBrandingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"state":                 st,
		"logo_upload_supported": s.LogoConverter != nil && s.LogoConverter.Supported(),
	})
}

func (s *Server) brandingCaller(w http.ResponseWriter, r *http.Request) (PlatformCaller, bool) {
	c, ok := s.platformCaller(r)
	if !ok || s.BrandingRevisions == nil {
		writeError(w, http.StatusForbidden, "platform operator access denied")
		return PlatformCaller{}, false
	}
	return c, true
}

// brandFindings builds the comparison context (other tenants only) and runs the automated review.
func (s *Server) brandFindings(ctx context.Context, c PlatformCaller, tenantID, name string) ([]HostFinding, error) {
	var bc BrandReviewContext
	peers, err := s.BrandingRevisions.Peers(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, p := range peers {
		if p.TenantID != tenantID {
			bc.OtherBrandNames = append(bc.OtherBrandNames, p.ProductName)
		}
	}
	if s.Hostnames != nil {
		all, err := s.Hostnames.List(ctx, c, "")
		if err != nil {
			return nil, err
		}
		for _, a := range all {
			if a.TenantID != tenantID {
				bc.OtherHostLabels = append(bc.OtherHostLabels, strings.SplitN(a.Host, ".", 2)[0])
			}
		}
	}
	f := ReviewBrandFindings(name, bc)
	if f == nil {
		f = []HostFinding{}
	}
	return f, nil
}

// GET /platform/tenants/{id}/branding/review
func (s *Server) handlePlatformBrandingReview(w http.ResponseWriter, r *http.Request) {
	c, ok := s.brandingCaller(w, r)
	if !ok {
		return
	}
	tenantID := r.PathValue("id")
	if !isUUID(tenantID) {
		writeError(w, http.StatusNotFound, "no such tenant")
		return
	}
	rv, err := s.BrandingRevisions.Review(r.Context(), c, tenantID)
	if err != nil {
		writeBrandingErr(w, err)
		return
	}
	findings := []HostFinding{}
	var logoB64 string
	if rv.Draft != nil {
		if findings, err = s.brandFindings(r.Context(), c, tenantID, rv.Draft.ProductName); err != nil {
			writeBrandingErr(w, err)
			return
		}
		if len(rv.Draft.LogoPNG) > 0 {
			logoB64 = base64.StdEncoding.EncodeToString(rv.Draft.LogoPNG)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"review":          rv,
		"logo_png_base64": logoB64,
		"findings":        findings,
		"contrast_pairs": []map[string]any{
			{"against": ContrastLabelBackground, "min": ContrastLabelMin}, {"against": ContrastSurface, "min": ContrastSurfaceMin}},
	})
}

type brandingApproveRequest struct {
	BrandingApproval
	// Generation shadows the embedded field so its ABSENCE is detectable (a missing one must not mean 0).
	Generation     *int64   `json:"review_generation"`
	Acknowledge    []string `json:"acknowledge"`
	OverrideReason string   `json:"override_reason"`
}

// POST /platform/tenants/{id}/branding/approve {revision_id, normalized_hash, assignment_id, acknowledge[],
// override_reason}. 409 "stale" when the draft, its hash or the live assignment is no longer what was reviewed;
// 409 "findings" until every finding code of the revision is acknowledged with a reason; either way nothing is
// published.
func (s *Server) handlePlatformBrandingApprove(w http.ResponseWriter, r *http.Request) {
	c, ok := s.brandingCaller(w, r)
	if !ok {
		return
	}
	tenantID := r.PathValue("id")
	if !isUUID(tenantID) {
		writeError(w, http.StatusNotFound, "no such tenant")
		return
	}
	var req brandingApproveRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed approval body"); err != nil {
		return
	}
	if !isUUID(req.RevisionID) || !isUUID(req.AssignmentID) || !validSHA256Hex(req.Hash) || req.Generation == nil {
		writeError(w, http.StatusBadRequest, "revision_id, normalized_hash, assignment_id and review_generation are required")
		return
	}
	// Findings are computed for the EXACT revision the operator named (it must be the stored draft with that
	// hash); the compare-and-swap below then re-checks it under the tenant's lock.
	rv, err := s.BrandingRevisions.Review(r.Context(), c, tenantID)
	if err != nil {
		writeBrandingErr(w, err)
		return
	}
	if rv.Draft == nil || rv.Draft.ID != req.RevisionID || rv.Draft.Hash != req.Hash {
		writeBrandingErr(w, ErrBrandingStale)
		return
	}
	findings, err := s.brandFindings(r.Context(), c, tenantID, rv.Draft.ProductName)
	if err != nil {
		writeBrandingErr(w, err)
		return
	}
	extra := map[string]any{}
	if len(findings) > 0 {
		acked := map[string]bool{}
		for _, a := range req.Acknowledge {
			acked[a] = true
		}
		reason := strings.TrimSpace(req.OverrideReason)
		codes := make([]string, 0, len(findings))
		for _, f := range findings {
			if !acked[f.Code] || reason == "" || len(reason) > 500 {
				writeJSON(w, http.StatusConflict, map[string]any{
					"error":    "the review has findings; acknowledge every code and give a reason (at most 500 characters)",
					"code":     "findings",
					"findings": findings,
				})
				return
			}
			codes = append(codes, f.Code)
		}
		extra["override_codes"] = codes
		extra["override_reason"] = reason
	}
	req.BrandingApproval.Generation = *req.Generation
	res, err := s.BrandingRevisions.Approve(r.Context(), c, tenantID, req.BrandingApproval, extra)
	if err != nil {
		writeBrandingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"published": res})
}

type brandingWithdrawRequest struct {
	Reason string `json:"reason"`
}

// POST /platform/tenants/{id}/branding/withdraw {reason}
func (s *Server) handlePlatformBrandingWithdraw(w http.ResponseWriter, r *http.Request) {
	c, ok := s.brandingCaller(w, r)
	if !ok {
		return
	}
	tenantID := r.PathValue("id")
	if !isUUID(tenantID) {
		writeError(w, http.StatusNotFound, "no such tenant")
		return
	}
	var req brandingWithdrawRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed withdrawal body"); err != nil {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > 500 {
		writeError(w, http.StatusBadRequest, "a reason is required (at most 500 characters)")
		return
	}
	if err := s.BrandingRevisions.Withdraw(r.Context(), c, tenantID, map[string]any{"reason": reason}); err != nil {
		writeBrandingErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"withdrawn": true})
}

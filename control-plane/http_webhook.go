package controlplane

// Webhook CRUD handlers — GET/POST/DELETE /tenant/webhooks.
//
// All three require CapManageTenant (the same capability as branding and API tokens) because
// webhooks fire on management-plane events and their delivery URLs + secrets are deployment
// configuration, not technician data.
//
// The secret is generated server-side (32 random bytes, hex-encoded) and returned ONCE in
// the POST 201 response body. Subsequent GET /tenant/webhooks calls omit the secret field.
// This mirrors the enrollment-token and API-token patterns.

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// handleListWebhooks serves GET /tenant/webhooks.
// Returns the tenant's registered webhooks (without secrets). Requires CapManageTenant.
func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Webhooks == nil {
		writeError(w, http.StatusInternalServerError, "webhook store not configured")
		return
	}
	whs, err := s.Webhooks.List(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list webhooks")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": whs})
}

// createWebhookRequest is the body accepted by POST /tenant/webhooks.
type createWebhookRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
}

// handleCreateWebhook serves POST /tenant/webhooks.
// Validates the URL, generates a signing secret, stores the webhook, and returns the
// new row plus the secret (shown ONCE). Requires CapManageTenant.
func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Webhooks == nil {
		writeError(w, http.StatusInternalServerError, "webhook store not configured")
		return
	}
	var req createWebhookRequest
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed create-webhook request body"); err != nil {
		return
	}
	// Validate URL.
	rawURL := strings.TrimSpace(req.URL)
	if rawURL == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}
	if len(rawURL) > maxWebhookURLLen {
		writeError(w, http.StatusBadRequest, "url is too long (max 2048 characters)")
		return
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		// http:// is intentionally excluded: it would allow SSRF probing of internal endpoints
		// (cloud IMDS at 169.254.169.254, internal Postgres port, signaling server, etc.) using
		// the control plane's own outbound HTTP stack as the probe tool.
		writeError(w, http.StatusBadRequest, "url must be a valid https URL")
		return
	}
	// Validate events.
	if len(req.Events) > maxWebhookEvents {
		writeError(w, http.StatusBadRequest, "too many events (max 20)")
		return
	}
	for _, ev := range req.Events {
		trimmed := strings.TrimSpace(ev)
		if trimmed == "" {
			writeError(w, http.StatusBadRequest, "event strings must not be blank")
			return
		}
		if len(trimmed) > maxWebhookEventLen {
			writeError(w, http.StatusBadRequest, "event strings must not exceed 128 characters")
			return
		}
	}
	events := req.Events
	if events == nil {
		events = []string{}
	}
	// Generate the signing secret.
	secret, err := generateWebhookSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate webhook secret")
		return
	}
	wh := TenantWebhook{
		ID:        newUUID(),
		URL:       rawURL,
		Events:    events,
		CreatedAt: time.Now().UTC(),
	}
	// Create atomically checks the cap and inserts in one operation; ErrWebhookCapExceeded
	// means we're already at maxWebhooksPerTenant (no TOCTOU window between check and insert).
	if err := s.Webhooks.Create(r.Context(), p.TenantID, &wh, secret, maxWebhooksPerTenant); err != nil {
		if errors.Is(err, ErrWebhookCapExceeded) {
			writeError(w, http.StatusConflict, "webhook limit reached (max 10 per tenant)")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create webhook")
		return
	}
	if err := s.recordMgmtAudit(r, "webhook.create", "webhook", wh.ID,
		map[string]any{"url": wh.URL, "events": wh.Events}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"webhook": CreatedWebhook{TenantWebhook: wh, Secret: secret},
	})
}

// handleListWebhookDeliveries serves GET /tenant/webhooks/{id}/deliveries.
// Returns the last webhookDeliveryRingSize delivery records for the named webhook, newest-first.
// Returns 404 when the webhook does not belong to this tenant. Requires CapManageTenant.
func (s *Server) handleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Webhooks == nil {
		writeError(w, http.StatusInternalServerError, "webhook store not configured")
		return
	}
	webhookID := r.PathValue("id")
	if webhookID == "" {
		writeError(w, http.StatusBadRequest, "webhook id is required")
		return
	}
	// Verify the webhook belongs to this tenant before exposing its delivery history.
	whs, err := s.Webhooks.List(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list webhooks")
		return
	}
	found := false
	for _, wh := range whs {
		if wh.ID == webhookID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "webhook not found")
		return
	}
	records := []WebhookDeliveryRecord{}
	if s.Dispatcher != nil {
		records = s.Dispatcher.RecentDeliveries(webhookID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": records})
}

// handleDeleteWebhook serves DELETE /tenant/webhooks/{id}.
// Idempotent: returns 204 whether or not the webhook existed. Requires CapManageTenant.
func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageTenant); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Webhooks == nil {
		writeError(w, http.StatusInternalServerError, "webhook store not configured")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "webhook id is required")
		return
	}
	found, err := s.Webhooks.Delete(r.Context(), p.TenantID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete webhook")
		return
	}
	if found {
		// Evict the delivery ring so the map entry does not accumulate across webhook
		// lifecycle churn (create / delete cycles). The ring is ephemeral by design.
		if s.Dispatcher != nil {
			s.Dispatcher.DeleteRing(id)
		}
		if err := s.recordMgmtAudit(r, "webhook.delete", "webhook", id, nil); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

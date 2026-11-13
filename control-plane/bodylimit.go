package controlplane

// Request-body size limits for every JSON handler — the fix for docs/25 F05, "unbounded body
// parsing happens while holding a tenant database connection".
//
// WHY THE BYTE CAP IS A DATABASE CONCERN AND NOT MERELY A MEMORY ONE
//
// Handler() wraps the protected mux as ipAllow → csrf → auth → tenant → tenantIPAllow → handler.
// tenantMiddleware binds the caller's tenant through TenantBinder.BindTenant, and the production
// binder (PgBinder.BindTenant, binder.go) ACQUIRES a connection out of the shared pgx pool and pins
// app.current_tenant on it so PostgreSQL RLS scopes every downstream query. The matching release
// runs from a `defer` in that middleware, which means the pinned connection is held until the
// HANDLER RETURNS — not until the handler stops using the database.
//
// A handler that decodes an unbounded body therefore holds one of the pool's finite connections for
// as long as the client chooses to keep sending, and the client picks BOTH axes: how many bytes and
// how slowly. That is not a per-request memory nuisance the process shrugs off. The pool is shared
// by every tenant on the deployment, so a handful of slow uploads from one authenticated (or, on
// POST /sessions, barely-authorized) principal can hold every connection and stop unrelated tenants
// from working. The external review reproduced the check-ordering half of this: a read-only
// principal's >1 MiB body was read in full before the 403 came back.
//
// The cap converts "the attacker decides how long we hold a connection" into "the attacker gets
// maxBytes, then the read fails". It is one half of a pair: the byte axis is bounded here, the time
// axis by the server's ReadTimeout/WriteTimeout/IdleTimeout (cmd/controlplane/main.go). Neither
// alone is sufficient — a 64 KiB body dribbled one byte a minute still pins a connection, and an
// unbounded body inside the read timeout still buffers whatever the network can deliver in it.
//
// WHY 413 AND NOT 400
//
// An over-limit body is answered 413 Request Entity Too Large. Before this change every capped site
// answered 400 and, at the sites that append the decoder's error to the response, leaked the literal
// runtime string "http: request body too large" into the API contract. 413 says the same thing as
// policy rather than as an accident, is distinguishable by a client that wants to retry smaller, and
// does not vary with the Go version's wording.
//
// The over-limit case is recognised with errors.As against *http.MaxBytesError — the typed error
// http.MaxBytesReader has returned since Go 1.19 — and NEVER by string-matching the message. A
// string match silently stops working the day the runtime rewords it (failing OPEN, back to 400),
// and it would equally match a same-worded error that arrived from somewhere else entirely.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Body-size ceilings. These are deliberately coarse: two tiers, each with a reason, rather than a
// bespoke number per route that nobody can justify later. Existing endpoint-specific constants
// (maxAuditBodyBytes, maxPasswordBodyBytes, maxCredentialTokenBodyBytes, maxRedeemBodyBytes,
// maxAttendedBodyBytes) keep their own values and their own rationale.
const (
	// maxSmallJSONBodyBytes is the house default for a management request body: a flat JSON object
	// of a few short scalar fields — a name, a group id, a CIDR, a TTL, a property value. The
	// largest field any of them accepts is bounded far below this by its own validator
	// (maxMachineNameLen 255, maxMachinePropertyValueLen 4096, MaxProductNameLen 100), so 64 KiB is
	// already orders of magnitude of headroom; it is chosen to be obviously generous rather than
	// tight, because a cap that legitimate traffic can reach is a cap somebody will quietly raise.
	// It matches the value HandleLogin and the redeem endpoints already used, so the authenticated
	// surface is not looser than the pre-auth one.
	maxSmallJSONBodyBytes = 1 << 16 // 64 KiB

	// maxBulkJSONBodyBytes covers the two bulk routes whose body legitimately carries a LIST —
	// POST /machines/bulk-status and POST /machines/bulk-group, both capped at 200 machine ids
	// downstream. 200 UUIDs is roughly 8 KiB, so 1 MiB still leaves two orders of magnitude of
	// slack for whitespace and future fields while staying a bound rather than a formality.
	maxBulkJSONBodyBytes = 1 << 20 // 1 MiB

	// maxBrandingBodyBytes covers PUT /tenant/branding, whose body carries an optional logo as a
	// base64 raster data URI. The DECODED image is capped at MaxLogoBytes (128 KiB); base64 inflates
	// that by 4/3 (~171 KiB), so 256 KiB holds the logo plus the product name, accent and JSON
	// envelope with room to spare while staying a real bound. The logo's own validator
	// (ValidateLogoDataURI) enforces the decoded cap after decoding.
	maxBrandingBodyBytes = 1 << 18 // 256 KiB
)

// decodeJSONBody reads at most maxBytes of r.Body, decodes the JSON into dst, and ANSWERS THE
// REQUEST ITSELF on failure — 413 when the cap was hit, 400 with badRequestMsg verbatim otherwise.
// It returns the decode error so the caller's whole error path is `if err != nil { return }`; a
// caller must not write a second response.
//
// badRequestMsg is passed in rather than generated because the wording is a security decision that
// differs per endpoint. The pre-auth handlers (login, TOTP, credential redemption) answer a
// deliberately flat "invalid request body" and must keep doing so: the decoder's own message
// describes the struct it failed to fill, which is free schema reconnaissance for an unauthenticated
// caller. Use decodeJSONBodyDetailed only where the caller is already authenticated and the detail
// helps an operator debug their own request.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any, badRequestMsg string) error {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes)).Decode(dst)
	if err == nil {
		return nil
	}
	if !writeIfBodyTooLarge(w, err) {
		writeError(w, http.StatusBadRequest, badRequestMsg)
	}
	return err
}

// decodeJSONBodyDetailed is decodeJSONBody for AUTHENTICATED management endpoints that echo the
// decoder's own complaint: the 400 body is badRequestPrefix + ": " + the decode error. The detail is
// suppressed on the over-limit path, which is the point — that path used to be how
// "http: request body too large" reached the client.
func decodeJSONBodyDetailed(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any, badRequestPrefix string) error {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes)).Decode(dst)
	if err == nil {
		return nil
	}
	if !writeIfBodyTooLarge(w, err) {
		writeError(w, http.StatusBadRequest, badRequestPrefix+": "+err.Error())
	}
	return err
}

// writeIfBodyTooLarge answers 413 and reports true when err is the over-limit error from
// http.MaxBytesReader; it writes nothing and reports false for any other error. The limit quoted
// back is the one the reader actually enforced (MaxBytesError.Limit), not a number the caller
// believes it passed, so the message can never disagree with the enforcement.
//
// The limit is not a secret: telling a client the ceiling lets it split a legitimate request, and it
// tells an attacker only what one over-limit probe would have told them anyway.
func writeIfBodyTooLarge(w http.ResponseWriter, err error) bool {
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		return false
	}
	writeError(w, http.StatusRequestEntityTooLarge,
		"request body exceeds this endpoint's limit of "+strconv.FormatInt(tooLarge.Limit, 10)+" bytes")
	return true
}

// Body admission is independent of the database pool. Slow clients may hold a bounded
// body slot, but cannot hold a tenant connection while transmitting request bytes.
var tenantBodySlots = make(chan struct{}, 32)
var tenantBodyCounts = struct {
	sync.Mutex
	counts map[string]int
}{counts: make(map[string]int)}

func bufferTenantBody(w http.ResponseWriter, r *http.Request) (func(), bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return func() {}, true
	}
	select {
	case tenantBodySlots <- struct{}{}:
	default:
		writeError(w, http.StatusServiceUnavailable, "request body capacity exhausted")
		return nil, false
	}
	tenantID := principalFrom(r.Context()).TenantID
	tenantBodyCounts.Lock()
	if tenantBodyCounts.counts[tenantID] >= 8 {
		tenantBodyCounts.Unlock()
		<-tenantBodySlots
		writeError(w, http.StatusServiceUnavailable, "tenant request body capacity exhausted")
		return nil, false
	}
	tenantBodyCounts.counts[tenantID]++
	tenantBodyCounts.Unlock()
	release := func() {
		tenantBodyCounts.Lock()
		tenantBodyCounts.counts[tenantID]--
		if tenantBodyCounts.counts[tenantID] == 0 {
			delete(tenantBodyCounts.counts, tenantID)
		}
		tenantBodyCounts.Unlock()
		<-tenantBodySlots
	}
	limit := int64(maxSmallJSONBodyBytes)
	switch r.URL.Path {
	case "/audit/ingest", "/machines/bulk-status", "/machines/bulk-group",
		// The public-API alias of bulk-group (docs/59) carries the same up-to-200-id list and gets
		// the same tier; the exact-path match means the alias would otherwise silently fall to the
		// small default.
		publicAPIBasePath + "/machines/bulk-group":
		limit = maxBulkJSONBodyBytes
	}
	// Toolbox item writes carry a script body: its worst-case JSON escaping needs more than the house
	// default (maxToolboxRequestBytes, toolbox.go). The handler enforces the same cap again.
	if r.URL.Path == "/toolbox" || strings.HasPrefix(r.URL.Path, "/toolbox/") {
		limit = maxToolboxRequestBytes
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	_ = r.Body.Close()
	if err != nil {
		release()
		if !writeIfBodyTooLarge(w, err) {
			writeError(w, http.StatusBadRequest, "could not read request body")
		}
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	return release, true
}

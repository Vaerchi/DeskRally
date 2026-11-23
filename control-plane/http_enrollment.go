package controlplane

// Enrollment tokens (M1) and device identity (M3). Split out of http.go (routing and middleware stay there).

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// -------------------------------------------------------------------------------------
// Enrollment tokens (M1)
// -------------------------------------------------------------------------------------

// mintEnrollmentTokenRequest is the body of POST /enrollment-tokens. TTLSeconds and MaxUses
// are optional (defaults: DefaultEnrollmentTokenTTL, single-use).
type mintEnrollmentTokenRequest struct {
	GroupID    string `json:"group_id"`
	TTLSeconds int    `json:"ttl_seconds"`
	MaxUses    int    `json:"max_uses"`
}

func (s *Server) handleMintEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageEnrollment); err != nil {
		writeDenied(w, err)
		return
	}
	var req mintEnrollmentTokenRequest
	// docs/25 F05: same shape as handleEnroll — the tenant-wide capability gate above precedes the
	// decode, and the cap bounds the authorized caller's body.
	if err := decodeJSONBodyDetailed(w, r, maxSmallJSONBodyBytes, &req, "malformed mint-token request body"); err != nil {
		return
	}
	if req.GroupID == "" {
		writeError(w, http.StatusBadRequest, "group_id is required")
		return
	}
	// SECURITY: the tenant-wide Require above only says the caller may manage enrollment SOMEWHERE.
	// The token plants a machine into req.GroupID, and the machine's group is what every downstream
	// authorization check scopes against (BackstageCapsFor, RequireMachine), so the group named here
	// must itself be covered by the caller's memberships. Without this, a group-scoped Admin could
	// mint a token for a group they have no rights over and then reach the machine that redeems it.
	if err := p.Grant.RequireMachine(CapManageEnrollment, req.GroupID); err != nil {
		writeDenied(w, err)
		return
	}
	// The ceiling is compared in SECONDS, before the multiplication — the same shape, and for the
	// same reason, as HandleIssuePasswordReset's. Converting first overflows int64 for ttl_seconds
	// above ~9.2e9 (1e10 s is 1e19 ns against a 9.22e18 ceiling), and the wrapped NEGATIVE duration
	// then passes any `ttl > Max…` test, minting a token whose expires_at is already in the past
	// behind a 201: the caller is told they hold an enrollment secret, and every redemption of it
	// fails. Unbounded-but-positive is the other half — see MaxEnrollmentTokenTTL for what an
	// effectively immortal enrollment secret grants.
	const maxTTLSeconds = int(MaxEnrollmentTokenTTL / time.Second)
	ttl := DefaultEnrollmentTokenTTL
	switch {
	case req.TTLSeconds < 0:
		writeError(w, http.StatusBadRequest, "ttl_seconds must be positive")
		return
	case req.TTLSeconds > maxTTLSeconds:
		writeError(w, http.StatusBadRequest, "ttl_seconds exceeds the maximum enrollment-token lifetime")
		return
	case req.TTLSeconds > 0:
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	// The same two halves as the ttl ceiling above — negative refused, unbounded-but-positive
	// refused — because bounding only the LIFETIME left the sharper quantity open: how many machines
	// one secret plants into the group. See MaxEnrollmentTokenUses.
	//
	// There is no arithmetic to overflow here (the value reaches the store as-is), but the
	// destination is NARROWER than the Go int that carries it: enrollment_token.max_uses is a 32-bit
	// PostgreSQL `int`. Uncapped, a request for 2^31 reached the INSERT with a value the column
	// cannot hold and the driver's range error surfaced as a 500 — measured. The cap is far inside
	// that range, so this answers 400 without asking the database.
	maxUses := defaultEnrollmentMaxUses
	switch {
	case req.MaxUses < 0:
		writeError(w, http.StatusBadRequest, "max_uses must be positive")
		return
	case req.MaxUses > MaxEnrollmentTokenUses:
		writeError(w, http.StatusBadRequest, "max_uses exceeds the maximum enrollment-token use count")
		return
	case req.MaxUses > 0:
		maxUses = req.MaxUses
	}
	tok := &EnrollmentToken{
		GroupID:   req.GroupID,
		CreatedBy: p.UserID,
		ExpiresAt: time.Now().Add(ttl),
		MaxUses:   maxUses,
	}
	plaintext, err := s.EnrollmentTokens.MintToken(r.Context(), p.TenantID, tok)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint enrollment token")
		return
	}
	if err := s.recordMgmtAudit(r, "enrollment_token.mint", "enrollment_token", tok.ID,
		map[string]any{"group_id": tok.GroupID, "max_uses": tok.MaxUses}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// The plaintext is shown ONCE, here; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"token": plaintext, "enrollment_token": tok})
}

func (s *Server) handleListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageEnrollment); err != nil {
		writeDenied(w, err)
		return
	}
	all, err := s.EnrollmentTokens.ListTokens(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list enrollment tokens")
		return
	}
	// RLS already scoped the query to the tenant; now, like machine and session listing, confine
	// visibility to the groups the caller's memberships actually cover.
	tokens := make([]EnrollmentToken, 0, len(all))
	for _, t := range all {
		if p.Grant.AllowsInGroup(CapManageEnrollment, t.GroupID) {
			tokens = append(tokens, t)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollment_tokens": tokens})
}

// findEnrollmentToken resolves one of the tenant's tokens by id. The store deliberately exposes no
// single-token read — a token's only identity-bearing column is its hash, which never leaves the
// database — so this filters the (RLS-scoped) listing. Token counts are per-tenant administrative
// data, not a hot path.
func (s *Server) findEnrollmentToken(r *http.Request, tenantID, id string) (*EnrollmentToken, error) {
	tokens, err := s.EnrollmentTokens.ListTokens(r.Context(), tenantID)
	if err != nil {
		return nil, err
	}
	for i := range tokens {
		if tokens[i].ID == id {
			return &tokens[i], nil
		}
	}
	return nil, ErrEnrollmentTokenNotFound
}

func (s *Server) handleRevokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if err := p.Grant.Require(CapManageEnrollment); err != nil {
		writeDenied(w, err)
		return
	}
	id := r.PathValue("id")
	// Resolve the token's REAL group from stored data and gate on THAT, mirroring how the machine
	// handlers resolve a machine's group: a group-scoped admin must not be able to revoke (i.e.
	// disrupt enrollment for) a group they hold no rights over. A token outside the caller's scope
	// is reported as unknown, not as forbidden, so the surface does not confirm its existence.
	tok, err := s.findEnrollmentToken(r, p.TenantID, id)
	if err != nil {
		if errors.Is(err, ErrEnrollmentTokenNotFound) {
			writeError(w, http.StatusNotFound, "unknown enrollment token")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve enrollment token")
		return
	}
	if !p.Grant.AllowsInGroup(CapManageEnrollment, tok.GroupID) {
		writeError(w, http.StatusNotFound, "unknown enrollment token")
		return
	}
	if err := s.EnrollmentTokens.RevokeToken(r.Context(), p.TenantID, id); err != nil {
		if errors.Is(err, ErrEnrollmentTokenNotFound) {
			writeError(w, http.StatusNotFound, "unknown enrollment token")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not revoke enrollment token")
		return
	}
	if err := s.recordMgmtAudit(r, "enrollment_token.revoke", "enrollment_token", id, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "id": id})
}

// redeemEnrollmentRequest is the body of the PUBLIC POST /enroll/redeem: the bearer token plus
// the agent's identity. pubkey (hex-encoded 32-byte Ed25519) is REQUIRED — redemption is what
// pins the agent key.
type redeemEnrollmentRequest struct {
	Token string `json:"token"`
	// DeviceID is DEPRECATED and IGNORED. This endpoint is UNAUTHENTICATED — anyone holding any
	// tenant's enrollment token could otherwise name an arbitrary device id, and the device id is
	// exactly what a session ticket authorizes the signaling server to broker to
	// (server/signaling/ticket.go). The identity is therefore minted server-side and returned in
	// the response; the field is retained only so older installers deserialize cleanly.
	DeviceID string `json:"device_id"`
	Pubkey   string `json:"pubkey"`
	Name     string `json:"name"`
	// OS is the agent's self-reported OS description, stored as machine.os (migrations/0017) for
	// the console's inventory column. Display-only: nothing authorizes on it, and it is attacker-
	// controlled on this UNAUTHENTICATED endpoint, so it is length-bounded like Name and never
	// interpreted.
	OS string `json:"os"`
	// RequireSessionPolicy is the agent's self-reported `require_session_policy` config flag
	// (crates/agent-windows/src/config.rs), stored as machine.require_session_policy
	// (migrations/0037). Set means the agent opens every session VIEW-ONLY until a signed access
	// policy verifies, so the control plane must mint one for it even when its group has no mandate
	// — otherwise that agent is stranded view-only forever.
	//
	// Attacker-controlled on this UNAUTHENTICATED endpoint, like OS, and safe for the same kind of
	// reason but a sharper one: the ONLY thing it can do is cause a policy to be minted for the
	// machine the redeemer just created. It cannot suppress a mandate (an enforcing group still
	// mints view_only regardless of this bit) and it cannot reach any other machine. Setting it
	// falsely only makes your own agent receive a policy it will ignore.
	//
	// A POINTER so that ABSENT and FALSE are distinguishable: an older installer that does not send
	// the key must not be read as "the operator turned it off". Absent leaves the column at its
	// migration DEFAULT false, which is the same value, but the distinction is what keeps the
	// re-enroll path honest and mirrors the *bool convention on the attended redeem wire.
	RequireSessionPolicy *bool `json:"require_session_policy"`
}

// maxRedeemBodyBytes caps the UNAUTHENTICATED redeem body, matching HandleLogin's cap on the other
// public endpoint. Without it a single unauthenticated request can make the process buffer an
// arbitrary amount of memory before any credential is checked.
const maxRedeemBodyBytes = 1 << 16

// maxMachineNameLen bounds the free-text display name a redeemer supplies. It is stored verbatim
// (machine.hostname) and echoed back into listings and audit metadata, so it is bounded here rather
// than left to the database's unbounded `text`.
const maxMachineNameLen = 255

// enrollTombstoneDeadline bounds the enroll door's key-tombstone read. Enrollment has no timing floor, so this is
// a plain availability bound, not part of a response schedule.
const enrollTombstoneDeadline = 2 * time.Second

// handleRedeemEnrollment is UNAUTHENTICATED (mounted on the root mux): the enrollment token is
// the authorization. It resolves tenant + group through the atomic SECURITY DEFINER redeem,
// creates the machine tenant-pinned, and pins the agent's Ed25519 public key. Every invalid
// token — unknown, revoked, expired, exhausted — is the same generic 403, so a caller probing
// the endpoint learns nothing about which check failed.
func (s *Server) handleRedeemEnrollment(w http.ResponseWriter, r *http.Request) {
	var req redeemEnrollmentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRedeemBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed redeem request body: "+err.Error())
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if len(req.Name) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "name is too long")
		return
	}
	if len(req.OS) > maxMachineNameLen {
		writeError(w, http.StatusBadRequest, "os is too long")
		return
	}
	pub, err := hex.DecodeString(req.Pubkey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "pubkey must be a hex-encoded 32-byte Ed25519 public key")
		return
	}
	// Token guessing is metered per source (there is no account to key on here). Malformed
	// requests above cost no budget — only a real token check does.
	th := s.throttle()
	keys := []string{ipKey("redeem", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	// docs/65 D-C9: an agent key that was pinned on a REMOVED machine is a tombstone. It cannot be enrolled
	// again (a re-install generates a NEW key and enrolls as a NEW machine). Checked before the token is
	// consumed so a refused install does not burn a use.
	// Bounded like the redeem door's check (docs/66 release gate R1): it runs on the anonymous lookup pool, and a
	// slow database must not hold an unauthenticated request there for as long as the client keeps it open.
	tombCtx, cancelTomb := context.WithTimeout(r.Context(), enrollTombstoneDeadline)
	tombstoned, terr := s.Machines.KeyTombstoned(tombCtx, hex.EncodeToString(pub))
	cancelTomb()
	if terr != nil {
		writeError(w, http.StatusInternalServerError, "could not check the agent identity")
		return
	} else if tombstoned {
		writeError(w, http.StatusForbidden, "this agent identity was removed; reinstall to create a new one")
		return
	}
	tok, err := s.EnrollmentTokens.RedeemToken(r.Context(), req.Token)
	if err != nil {
		if errors.Is(err, ErrEnrollmentTokenInvalid) {
			th.Fail(keys...)
			writeError(w, http.StatusForbidden, "invalid enrollment token")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not redeem enrollment token")
		return
	}
	th.Reset(keys...)
	// SECURITY: the device id is minted SERVER-SIDE, never taken from req.DeviceID. A redeemer who
	// could choose it would be choosing which agent the tenant's session tickets authorize
	// brokering to — see the redeemEnrollmentRequest doc and migrations/0008.
	deviceID := newUUID()
	// Tenant + group come from the REDEEMED TOKEN, never the request; the store pins the
	// tenant itself (this path has no request binder). Normalize the pubkey through the
	// decode so mixed-case hex stores canonically.
	m := &Machine{
		TenantID: tok.TenantID,
		DeviceID: deviceID,
		GroupID:  tok.GroupID,
		Name:     req.Name,
		OS:       req.OS,
		Pubkey:   hex.EncodeToString(pub),
		// Absent means false, which is also the column DEFAULT — but read it through the pointer
		// rather than relying on the zero value, so that an installer which sends `false` and one
		// which sends nothing are handled by the same line rather than by accident.
		RequireSessionPolicy: req.RequireSessionPolicy != nil && *req.RequireSessionPolicy,
	}
	if err := s.Machines.EnrollMachine(r.Context(), tok.TenantID, m); err != nil {
		// A conflict is now only reachable through a uuid collision (the device id is minted
		// here). It stays mapped rather than surfacing as a 500, and the redeemed use stays
		// consumed — this endpoint is unauthenticated, so a failure never hands the use back.
		if errors.Is(err, ErrMachineDeviceIDTaken) {
			writeError(w, http.StatusConflict, "device_id already enrolled")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not enroll machine")
		return
	}
	// Audited with an EMPTY actor: there is no authenticated principal here (recordMgmtAudit
	// needs one, so record directly). A recording failure still fails the request.
	if s.MgmtAudit != nil {
		meta, err := json.Marshal(map[string]any{"token_id": tok.ID, "device_id": m.DeviceID})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
		if err := s.MgmtAudit.RecordEvent(r.Context(), tok.TenantID, &MgmtAuditEvent{
			Action: "machine.enroll", TargetKind: "machine", TargetID: m.ID, Metadata: meta,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not record audit event")
			return
		}
	}
	resp := map[string]any{"machine": m}
	if s.DirectiveIssuer != nil {
		// The agent pins this into its ACL-protected config (docs/65 D-C3); an agent without a pinned
		// directive key refuses every directive.
		resp["directive_pubkey"] = s.DirectiveIssuer.PublicKeyHex()
	}
	if s.Grants != nil {
		// docs/69 §3.7: the key that signs session policies, backstage grants and binding grants. The
		// agent pins it (config `grant_issuer_pubkey`) unless an installer already pinned one; the
		// enrollment token authenticates this exchange over the control plane's TLS.
		resp["grant_issuer_pubkey"] = s.Grants.PublicKeyHex()
	}
	writeJSON(w, http.StatusCreated, resp)
}

// -------------------------------------------------------------------------------------
// Device identity (M3) — docs/11-agent-identity-contract.md §4.1
// -------------------------------------------------------------------------------------

// deviceIdentityAuthorized reports whether the request carries the configured service token.
// Constant-time so the token cannot be recovered a byte at a time from response latency.
func (s *Server) deviceIdentityAuthorized(r *http.Request) bool {
	want := s.DeviceIdentityToken
	if len(want) < DeviceIdentityTokenMinLen {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(want)) == 1
}

// handleDeviceIdentity answers GET /internal/devices/{device_id}/identity for the signaling
// server: the tenant + pinned Ed25519 public key for a device id, so signaling can verify that a
// connection claiming that device id holds the enrolled private key.
//
// Posture, all deliberate:
//   - Service-token auth (constant-time), never a tenant principal — the lookup is cross-tenant and
//     signaling belongs to no tenant. The route is not even mounted without the token.
//   - Unknown device and enrolled-but-unpinned are the SAME 404, so the response never distinguishes
//     "no such machine" from "machine I cannot authenticate".
//   - Metered per source like /enroll/redeem, so a token-guessing or id-probing run backs off.
//   - NOT recorded in the management audit trail. This is a read on a hot path — every agent
//     reconnect — and auditing it would drown the trail that exists to record human actions.
func (s *Server) handleDeviceIdentity(w http.ResponseWriter, r *http.Request) {
	th := s.throttle()
	keys := []string{ipKey("device-identity", clientIP(r))}
	if retry, ok := th.Allow(keys...); !ok {
		writeThrottled(w, retry)
		return
	}
	if !s.deviceIdentityAuthorized(r) {
		th.Fail(keys...)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, err := s.Machines.LookupDeviceIdentity(r.Context(), r.PathValue("device_id"))
	if err != nil {
		if errors.Is(err, ErrMachineNotFound) {
			// DELIBERATELY NOT th.Fail — this was a live, unauthenticated, fleet-wide denial of
			// service, and the reasoning is worth keeping because the call looks symmetric with the
			// 401 above.
			//
			// The key is `clientIP(r)`, and this is an INTERNAL route: the client is always the
			// signaling container. So it is not a per-attacker key, it is the ONE key every
			// legitimate agent registration in every tenant shares.
			//
			// Signaling resolves a device identity BEFORE it verifies the caller's Ed25519
			// signature, so an anonymous WebSocket can make it look up arbitrary device ids. Each
			// miss lands here. Five failures lock the key for 15 minutes, every further miss re-arms
			// it, and `th.Reset` below only runs on a success that can no longer happen — so one
			// unauthenticated peer could stop every agent everywhere from registering, indefinitely.
			//
			// The 401 arm SHOULD fail: that is someone guessing the service token, and locking them
			// out is exactly the point. This arm must not, because the caller has already PROVEN it
			// holds the token — a 404 only means "that device is not enrolled", which is an ordinary
			// answer during an enrollment race or for a machine that was removed. The sibling route
			// takes the same shape: `ErrTicketAlreadyRedeemed` returns 409 without failing.
			//
			// docs/23, the first internet-facing audit. CRITICAL.
			writeError(w, http.StatusNotFound, "unknown device")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve device identity")
		return
	}
	// docs/65 D-C1: a RETIRED machine resolves ONLY for a caller that asked for the restricted mode
	// (directives and acknowledgements, never presence or brokering). A signaling that predates this feature
	// does not ask, so it keeps refusing retired machines exactly as before its upgrade.
	if id.Status == MachineStatusRetired && r.URL.Query().Get("restricted") != "1" {
		th.Reset(keys...)
		writeError(w, http.StatusNotFound, "unknown device")
		return
	}
	th.Reset(keys...)
	writeJSON(w, http.StatusOK, id)
}

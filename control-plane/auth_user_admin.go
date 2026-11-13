package controlplane

// User management (docs/01 §5): the console surface for an admin to SEE the tenant's technicians and
// enable/disable their access. Lives on AuthService (like the password-reset endpoints) because it
// reuses the same UserStore, session revocation, canAdministerUser hierarchy guard, and audit trail.
//
// Disabling is robust without any session bookkeeping: SessionAuthenticator re-reads the user's
// Disabled flag on EVERY authenticated request, so a disabled user is refused on their next request.
// The session revocation below only makes that immediate rather than up-to-one-request delayed.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// sameUserID reports whether two id strings denote the SAME user. A plain string match handles the
// symbolic ids the in-memory stores and DEV use ("owner", "tech"); the canonical-uuid fallback closes
// a self-check bypass a raw `==` leaves open. Postgres resolves a uuid case/format-insensitively —
// parsePgUUID accepts uppercase, {braces}, and dashless spellings — so `A0EE…` and `a0ee…` name the
// SAME row, yet a raw compare sees them as different. Without this, an admin could disable their OWN
// account (self-lockout) by POSTing their id re-spelled, defeating the self-disable guard entirely.
func sameUserID(a, b string) bool {
	if a == b {
		return true
	}
	ca, aok := parsePgUUID(a)
	cb, bok := parsePgUUID(b)
	return aok && bok && ca == cb
}

// HandleListUsers is the protected GET /users: the tenant's users (management view). CapManageUsers.
func (s *AuthService) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := p.Grant.Require(CapManageUsers); err != nil {
		writeDenied(w, err)
		return
	}
	users, err := s.Users.ListUsers(r.Context(), p.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	// A group-SCOPED CapManageUsers holder sees only users who hold a membership in at least one
	// group inside their scope (security review 2026-11-01 #13); a tenant-wide holder sees all.
	if scope, _ := p.Grant.ScopeFor(CapManageUsers); !scope.All {
		visible := make([]UserSummary, 0, len(users))
		for _, u := range users {
			if summaryInUserAdminScope(scope, u) {
				visible = append(visible, u)
			}
		}
		users = visible
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// summaryInUserAdminScope is the list-side form of grantInUserAdminScope: a scoped caller sees a
// user only if EVERY membership the user holds is inside the caller's scope. No membership, a
// tenant-wide membership (empty ScopedGroupIDs) or any group outside the scope hides the user.
func summaryInUserAdminScope(scope GroupScope, u UserSummary) bool {
	if scope.All {
		return true
	}
	if len(u.Roles) == 0 || len(u.ScopedGroupIDs) == 0 {
		return false
	}
	for _, id := range u.ScopedGroupIDs {
		if !scope.Covers(id) {
			return false
		}
	}
	return true
}

// grantInUserAdminScope is the per-user-route form of the same rule: a scoped caller may act on a
// user only when EVERY membership of the target is group-scoped and wholly inside the caller's
// CapManageUsers scope (no tenant-wide membership, no out-of-scope group). A user with no
// membership is out of scope (fail closed).
func grantInUserAdminScope(actor, target *Grant) bool {
	scope, held := actor.ScopeFor(CapManageUsers)
	if !held {
		return false
	}
	if scope.All {
		return true
	}
	if target == nil || len(target.Members) == 0 {
		return false
	}
	for _, m := range target.Members {
		if m.Scope.All || len(m.Scope.assigned) == 0 {
			return false
		}
		for id := range m.Scope.assigned {
			if !scope.Covers(id) {
				return false
			}
		}
	}
	return true
}

// canAdministerExistingUser is canAdministerUser for a route that acts on an EXISTING user by id:
// it first refuses (with the same ErrEscalation the hierarchy guard gives, so the response does not
// distinguish "exists but out of scope" from "above you") a user a scoped admin could not even
// list, and then applies the capability-by-capability hierarchy check.
func canAdministerExistingUser(actor, target *Grant) error {
	if actor != nil && !grantInUserAdminScope(actor, target) {
		return ErrEscalation
	}
	return canAdministerUser(actor, target)
}

// roleCatalogEntry is one row of GET /roles: an assignable preset role and the capability keys it grants.
type roleCatalogEntry struct {
	Role         string   `json:"role"`
	Capabilities []string `json:"capabilities"`
}

// HandleListRoles is the protected GET /roles: the assignable preset roles and the capabilities each GRANTS
// (docs/01 §5) — a READ-ONLY reference so an admin about to assign a role can see what it permits, closing the
// role-assignment loop (loop 48 assigns roles by NAME; this shows what those names mean). The catalog is the
// STATIC rbac vocabulary (identical for every tenant), sourced from AssignableRoles() + Role.Capabilities() so
// it can never drift from what the server actually enforces. Gated on CapManageRoles — the same audience that
// sees the role picker.
func (s *AuthService) HandleListRoles(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := p.Grant.Require(CapManageRoles); err != nil {
		writeDenied(w, err)
		return
	}
	roles := AssignableRoles()
	out := make([]roleCatalogEntry, 0, len(roles))
	for _, role := range roles {
		caps := role.Capabilities()
		capKeys := make([]string, len(caps))
		for i, c := range caps {
			capKeys[i] = string(c)
		}
		out = append(out, roleCatalogEntry{Role: string(role), Capabilities: capKeys})
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": out})
}

// HandleDisableUser is the protected POST /users/{id}/disable.
func (s *AuthService) HandleDisableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserDisabled(w, r, true)
}

// HandleSignOutUser is the protected POST /users/{id}/sign-out: an admin REVOKES all of a user's live login
// sessions, forcing them to log in again — WITHOUT disabling the account (unlike /disable, which is a permanent
// block). Use cases: make a just-changed role take effect immediately, or evict a suspected-stolen session while
// keeping the legitimate user able to sign back in. Same gate as disable — CapManageUsers PLUS the
// canAdministerUser hierarchy (a lower/scoped admin cannot sign out somebody more privileged) — and the target
// is resolved INSIDE the caller's tenant so this cannot cross a tenant boundary. Signing out YOURSELF is allowed
// (it is benign — you simply log in again), unlike self-disable.
func (s *AuthService) HandleSignOutUser(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := p.Grant.Require(CapManageUsers); err != nil {
		writeDenied(w, err)
		return
	}
	if s.Sessions == nil {
		writeError(w, http.StatusInternalServerError, "session manager not configured")
		return
	}
	targetID := r.PathValue("id")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "user id is required")
		return
	}
	target, err := s.Users.FindUserByID(r.Context(), p.TenantID, targetID)
	if err != nil || target == nil {
		if err != nil && !errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusInternalServerError, "could not resolve user")
			return
		}
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	targetGrant, err := s.Users.StoredGrantFor(r.Context(), p.TenantID, targetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve user capabilities")
		return
	}
	if err := canAdministerExistingUser(p.Grant, targetGrant); err != nil {
		writeDenied(w, err)
		return
	}
	// keepTokenHash "" keeps NONE, i.e. revokes EVERY live session of the target — the same call disable makes.
	revoked, err := s.Sessions.RevokeOtherSessions(r.Context(), p.TenantID, targetID, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke sessions")
		return
	}
	if err := s.recordAuthEventFor(r.Context(), p.TenantID, p.UserID, targetID, "user.signed_out",
		map[string]any{"ip": clientIP(r), "revoked": revoked}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": revoked})
}

// HandleEnableUser is the protected POST /users/{id}/enable.
func (s *AuthService) HandleEnableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserDisabled(w, r, false)
}

// HandleClearUserLockout is the protected DELETE /users/{id}/lockout: an admin CLEARS the per-account
// TOTP-login and TOTP-enrollment throttle counters for a user who has been locked out by too many failed
// second-factor attempts. Returns 204 No Content on success and records a user.lockout_cleared audit event.
//
// WHAT IS CLEARED: the TOTP-login step-up key (accountKey "login-totp") and the TOTP enrollment step-up key
// (accountKey "totp") — both are pure per-account keys keyed on user ID, so the admin can clear them without
// knowing the user's source IP.
//
// WHAT IS NOT CLEARED:
//   - The login-source key (accountKey "login-source" + clientIP suffix). HandleLogin builds that key as a
//     compound account-AND-IP pair to prevent an attacker on one IP from locking a user out globally. The
//     admin does not know the user's IP, so this key cannot be targeted here. A user locked out by failed
//     password attempts should use a password-reset link (which redeems without going through the throttle)
//     or wait for the 15-minute idle decay.
//   - The shared per-source-IP budget (ipKey "login") — an attacker must not use admin calls to clear their
//     own IP budget.
//
// Same gate as sign-out: CapManageUsers PLUS the canAdministerUser hierarchy (a lower/scoped admin cannot
// act on somebody more privileged). Clearing YOUR OWN lockout IS allowed (it is benign — the same outcome
// can be achieved by waiting for the idle decay). No self-clear restriction.
func (s *AuthService) HandleClearUserLockout(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := p.Grant.Require(CapManageUsers); err != nil {
		writeDenied(w, err)
		return
	}
	targetID := r.PathValue("id")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "user id is required")
		return
	}
	target, err := s.Users.FindUserByID(r.Context(), p.TenantID, targetID)
	if err != nil || target == nil {
		if err != nil && !errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusInternalServerError, "could not resolve user")
			return
		}
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	targetGrant, err := s.Users.StoredGrantFor(r.Context(), p.TenantID, targetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve user capabilities")
		return
	}
	if err := canAdministerExistingUser(p.Grant, targetGrant); err != nil {
		writeDenied(w, err)
		return
	}
	// Clear the TOTP throttle keys for this user (both are pure per-user-ID keys with no IP suffix).
	// The login-source key is a compound account+IP pair — the admin does not know the IP, so it is not
	// touched here; see the comment above. The shared source-IP budget is also never cleared here.
	if th := s.throttle(); th != nil {
		th.Reset(
			accountKey("login-totp", p.TenantID, targetID),
			accountKey("totp", p.TenantID, targetID),
		)
	}
	// An unauditable access-control action must be loud (the change already committed).
	if err := s.recordAuthEventFor(r.Context(), p.TenantID, p.UserID, targetID, "user.lockout_cleared",
		map[string]any{"ip": clientIP(r)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setUserDisabled flips a user's disabled flag. Gated on CapManageUsers PLUS the canAdministerUser
// hierarchy (a lower/scoped admin cannot act on somebody more privileged), and disabling YOURSELF is
// refused (self-lockout). A disable also revokes the target's live sessions (best effort) and both
// directions record an audit event.
func (s *AuthService) setUserDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := p.Grant.Require(CapManageUsers); err != nil {
		writeDenied(w, err)
		return
	}
	targetID := r.PathValue("id")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "user id is required")
		return
	}
	// Disabling your OWN account would lock you out, and no enable path is reachable from a disabled
	// account — an admin who wants to leave asks another admin. Refuse it. (Enabling yourself is
	// impossible anyway: a disabled user cannot authenticate to call this.)
	if disabled && sameUserID(targetID, p.UserID) {
		writeError(w, http.StatusBadRequest, "you cannot disable your own account")
		return
	}
	// Resolve the target INSIDE the caller's tenant — an id from another tenant is simply not found,
	// so this endpoint cannot be aimed across a tenant boundary.
	target, err := s.Users.FindUserByID(r.Context(), p.TenantID, targetID)
	if err != nil || target == nil {
		if err != nil && !errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusInternalServerError, "could not resolve user")
			return
		}
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	// Hierarchy guard: the actor's authority must cover the target's (same escalation check the
	// password-reset path uses), so a scoped/lower admin cannot disable somebody more privileged.
	targetGrant, err := s.Users.StoredGrantFor(r.Context(), p.TenantID, targetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve user capabilities")
		return
	}
	if err := canAdministerExistingUser(p.Grant, targetGrant); err != nil {
		writeDenied(w, err)
		return
	}
	if err := s.Users.SetUserDisabled(r.Context(), p.TenantID, targetID, disabled); err != nil {
		if errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusNotFound, "no such user")
			return
		}
		if errors.Is(err, ErrLastOwner) {
			writeError(w, http.StatusConflict, ErrLastOwner.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	action := "user.enabled"
	if disabled {
		action = "user.disabled"
		// Immediate lock-out: revoke the target's live sessions too. Best effort — the disable flag is
		// already set and enforced per request, so a revoke failure is logged, not surfaced. Skipped
		// when no session manager is wired (the DEV skeleton has no login), where it is a no-op anyway.
		if s.Sessions != nil {
			if _, rerr := s.Sessions.RevokeOtherSessions(r.Context(), p.TenantID, targetID, ""); rerr != nil {
				log.Printf("user %s disabled but sessions could not be revoked: %v", targetID, rerr)
			}
		}
	}
	// An unauditable access-control mutation must be loud (the change already committed, so failing
	// the request here surfaces the missing audit rather than hiding it).
	if err := s.recordAuthEventFor(r.Context(), p.TenantID, p.UserID, targetID, action,
		map[string]any{"ip": clientIP(r)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": targetID, "disabled": disabled})
}

// setUserRoleRequest is the body of POST /users/{id}/role. ScopedGroupIDs is a POINTER so the handler
// can tell "field absent" (preserve the target's current scope — never silently widen) from "present
// and empty" (an explicit, deliberate tenant-wide assignment). See docs/55.
type setUserRoleRequest struct {
	Role           string    `json:"role"`
	ScopedGroupIDs *[]string `json:"scoped_group_ids"`
	// ExpiresAt (docs/56): ABSENT (nil) preserves the stored expiry, `null` clears it (never), a
	// string sets it. RawMessage so absent and null stay distinct.
	ExpiresAt json.RawMessage `json:"expires_at"`
	// AccessWindow (docs/57): the same three-way presence rule as ExpiresAt.
	AccessWindow json.RawMessage `json:"access_window"`
}

// Expiry bounds for a SUPPLIED timestamp (docs/56 sec. 4). The floor absorbs ordinary clock skew
// between the API server (which validates) and the database (which enforces); the ceiling is a typo
// guard, not a policy.
const (
	minAccessExpiryLead = time.Minute
	maxAccessExpiryLead = 5 * 365 * 24 * time.Hour
)

// parseAccessExpiry decodes an `expires_at` field: present=false when absent; a nil value for an
// explicit null (never expires); otherwise a validated future instant (UTC). It writes the 400 and
// returns ok=false on a malformed or out-of-range value.
func parseAccessExpiry(w http.ResponseWriter, raw json.RawMessage) (present bool, at *time.Time, ok bool) {
	if raw == nil {
		return false, nil, true
	}
	if string(raw) == "null" {
		return true, nil, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		writeError(w, http.StatusBadRequest, "expires_at must be an RFC 3339 timestamp or null")
		return false, nil, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		writeError(w, http.StatusBadRequest, "expires_at must be an RFC 3339 timestamp or null")
		return false, nil, false
	}
	now := time.Now()
	if t.Before(now.Add(minAccessExpiryLead)) {
		writeError(w, http.StatusBadRequest, "expires_at must be at least a minute in the future")
		return false, nil, false
	}
	if t.After(now.Add(maxAccessExpiryLead)) {
		writeError(w, http.StatusBadRequest, "expires_at is too far in the future")
		return false, nil, false
	}
	t = t.UTC()
	return true, &t, true
}

// parseAccessWindowField decodes an `access_window` field like parseAccessExpiry: present=false when
// absent; nil for an explicit null (any time); otherwise a validated window. It writes the 400 and
// returns ok=false on a malformed one.
func parseAccessWindowField(w http.ResponseWriter, raw json.RawMessage) (present bool, window *AccessWindow, ok bool) {
	if raw == nil {
		return false, nil, true
	}
	if string(raw) == "null" {
		return true, nil, true
	}
	win, err := ParseAccessWindow(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false, nil, false
	}
	return true, win, true
}

// windowJSON renders a window for a response or audit payload (null = any time).
func windowJSON(win *AccessWindow) any {
	if win == nil {
		return nil
	}
	return *win
}

// nonNilStrings returns ids, or an empty (non-nil) slice so the JSON is `[]`, never `null`.
func nonNilStrings(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

// expiryJSON renders an optional expiry for audit details and responses (RFC 3339 or null).
func expiryJSON(at *time.Time) any {
	if at == nil {
		return nil
	}
	return at.UTC().Format(time.RFC3339)
}

// resolveExplicitScope validates an EXPLICITLY-supplied group scope for an assignment: it dedupes the
// ids, rejects a malformed (non-uuid) id (400), requires the group store to be wired (500), and
// confirms every id is a real machine group in the caller's tenant — resolved through the same
// tenant-pinned group listing the rest of the API uses — answering 400 for a dangling or another
// tenant's id (docs/62 R1a: a dangling id expands to nothing, so accepting one would let a scoped actor
// "include" {missing-id} and a group later created with that id would activate it). It writes the error response
// and returns ok=false on any failure. An empty input is a deliberate tenant-wide scope: valid, returns
// (nil, true). This is the clean user-facing check; PgUserStore additionally revalidates inside the
// write transaction so a group deleted between here and the write becomes a controlled error, not a bad row.
func (s *AuthService) resolveExplicitScope(w http.ResponseWriter, r *http.Request, tenantID string, raw []string) ([]string, bool) {
	if len(raw) == 0 {
		return nil, true // explicit tenant-wide
	}
	seen := make(map[string]struct{}, len(raw))
	ids := make([]string, 0, len(raw))
	for _, id := range raw {
		if !isUUID(id) {
			writeError(w, http.StatusBadRequest, "scoped_group_ids must be machine group uuids")
			return nil, false
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if s.MachineGroups == nil {
		writeError(w, http.StatusInternalServerError, "machine group store not configured")
		return nil, false
	}
	groups, err := s.MachineGroups.ListMachineGroups(r.Context(), tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve machine groups")
		return nil, false
	}
	known := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		known[g.ID] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := known[id]; !ok {
			writeError(w, http.StatusBadRequest, "scoped_group_ids must name existing machine groups of this tenant")
			return nil, false
		}
	}
	return ids, true
}

// HandleSetUserRole is the protected POST /users/{id}/role: REPLACE a user's role with a single
// tenant-wide preset (docs/01 §5 role assignment). Gated on CapManageRoles PLUS two anti-escalation
// checks, because assigning a role is a privilege-granting primitive:
//
//  1. THE ACTOR MUST BE ABLE TO ADMINISTER THE TARGET AS THEY ARE. canAdministerUser(actor, current)
//     stops a scoped/lower admin from re-roling somebody more privileged (an Admin cannot touch an
//     Owner) — the same guard disable and password-reset use.
//  2. THE ACTOR'S AUTHORITY MUST COVER THE NEW ROLE. canAdministerUser(actor, newRole) stops anyone
//     from granting a role beyond what they themselves hold (an Admin cannot mint an Owner). Without
//     it the CapManageRoles gate alone would let an Admin escalate a peer — or themselves via a peer —
//     straight past the tenant's trust boundary.
//
// Changing your OWN role is refused outright (self-lockout / self-escalation), compared canonically so
// a re-spelled uuid cannot slip past (the same bypass the self-disable guard closes). A successful
// change records a `user.role_set` audit event carrying the new role.
func (s *AuthService) HandleSetUserRole(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := p.Grant.Require(CapManageRoles); err != nil {
		writeDenied(w, err)
		return
	}
	targetID := r.PathValue("id")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "user id is required")
		return
	}
	var req setUserRoleRequest
	if err := decodeOptionalJSON(w, r, maxSmallJSONBodyBytes, &req, "invalid request body"); err != nil {
		return
	}
	role := Role(req.Role)
	if !IsAssignableRole(role) {
		writeError(w, http.StatusBadRequest, "unknown role")
		return
	}
	// Refuse changing your OWN role: a self-demotion could strip your own CapManageRoles (locking role
	// management out of the tenant) and a self-promotion is exactly the escalation guard #2 blocks —
	// simplest and safest to refuse it entirely, as self-disable does.
	if sameUserID(targetID, p.UserID) {
		writeError(w, http.StatusBadRequest, "you cannot change your own role")
		return
	}
	// Resolve the target INSIDE the caller's tenant — an id from another tenant is simply not found.
	target, err := s.Users.FindUserByID(r.Context(), p.TenantID, targetID)
	if err != nil || target == nil {
		if err != nil && !errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusInternalServerError, "could not resolve user")
			return
		}
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	expiryPresent, expiresAt, ok := parseAccessExpiry(w, req.ExpiresAt)
	if !ok {
		return
	}
	windowPresent, window, ok := parseAccessWindowField(w, req.AccessWindow)
	if !ok {
		return
	}
	// Escalation guard #1: the actor's authority must cover the target's CURRENT authority. The STORED
	// grant (expired memberships included, docs/56 sec. 4.2): an expired Admin is still not editable
	// by someone who could not edit them before it lapsed.
	targetGrant, err := s.Users.StoredGrantFor(r.Context(), p.TenantID, targetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve user capabilities")
		return
	}
	if err := canAdministerExistingUser(p.Grant, targetGrant); err != nil {
		writeDenied(w, err)
		return
	}
	// Resolve the membership's group scope. ABSENT field → PRESERVE the target's current scope (a role
	// change must not silently widen a scoped user to tenant-wide, docs/55 R1); the preserved ids are
	// carried forward WITHOUT re-validation (a since-deleted group is a safe dangling deny, and
	// re-validating could block an unrelated role change). PRESENT field → validate it explicitly.
	// docs/56 r3, docs/57 r2: preserving "the" scope, expiry or window of several DIFFERENT stored
	// memberships is ambiguous (it could revive an expired row's scope, or merge "A by day" and "B by
	// night" into "A and B any time"), so such a user's edit must state all three explicitly.
	if (req.ScopedGroupIDs == nil || !expiryPresent || !windowPresent) && !targetGrant.Homogeneous() {
		writeError(w, http.StatusBadRequest,
			"this user has several memberships; send scoped_group_ids, expires_at and access_window explicitly")
		return
	}
	// ABSENT expiry → PRESERVE the stored one, as stored, even if already past: renewing access is
	// always an explicit new timestamp or null (docs/56 sec. 4).
	if !expiryPresent {
		expiresAt = targetGrant.AccessExpiry()
	}
	// ABSENT window → PRESERVE the stored one EXACTLY as stored (docs/57 sec. 4 r3): no zone
	// re-validation, so an unrelated edit never fails on a zone since dropped (that window keeps denying).
	if !windowPresent {
		window, _ = targetGrant.AccessWindowSummary() // homogeneous here, so never "varies"
	}
	// The Owner role is the tenant's recovery path: it never expires and is never limited to set hours,
	// checked on the RESULT (a preserved expiry or window blocks a promotion to Owner until cleared).
	if role == RoleOwner && expiresAt != nil {
		writeError(w, http.StatusBadRequest, "owner access cannot expire; clear the expiry")
		return
	}
	if role == RoleOwner && window != nil {
		writeError(w, http.StatusBadRequest, "owner access cannot be limited to set hours; clear the access window")
		return
	}
	var scopeIDs []string
	if req.ScopedGroupIDs == nil {
		scopeIDs = targetGrant.AssignmentScope().GroupIDs()
	} else {
		var ok bool
		if scopeIDs, ok = s.resolveExplicitScope(w, r, p.TenantID, *req.ScopedGroupIDs); !ok {
			return
		}
	}
	// Escalation guard #2: the actor's authority must cover the NEW role AT THE ASSIGNED SCOPE, so
	// nobody can grant a role — or a breadth of machines — stronger than their own. canAdministerUser
	// already composes with group scope (actorScope.Includes(targetScope) per capability), so a
	// group-scoped admin can only assign within their own groups and cannot assign tenant-wide.
	newGrant := NewGrant(targetID, p.TenantID, NewMembership(role, Groups(scopeIDs...)))
	if err := canAdministerUser(p.Grant, newGrant); err != nil {
		writeDenied(w, err)
		return
	}
	if err := s.Users.SetUserAssignment(r.Context(), p.TenantID, targetID,
		Assignment{Role: role, ScopedGroupIDs: scopeIDs, ExpiresAt: expiresAt,
			Window: window, WindowSupplied: windowPresent && window != nil,
			ExpectTreeVersion: expectTreeVersion(p.Grant)}); err != nil {
		if errors.Is(err, ErrGroupTreeChanged) {
			writeError(w, http.StatusConflict, ErrGroupTreeChanged.Error())
			return
		}
		if errors.Is(err, ErrUnknownTimeZone) {
			writeError(w, http.StatusBadRequest, "access_window.time_zone is not a time zone this server knows")
			return
		}
		if errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusNotFound, "no such user")
			return
		}
		if errors.Is(err, ErrLastOwner) {
			writeError(w, http.StatusConflict, ErrLastOwner.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not set role")
		return
	}
	// An unauditable access-control mutation must be loud (the change already committed).
	if err := s.recordAuthEventFor(r.Context(), p.TenantID, p.UserID, targetID, "user.role_set",
		map[string]any{"role": string(role), "scoped_group_ids": scopeIDs, "expires_at": expiryJSON(expiresAt),
			"access_window": windowJSON(window), "ip": clientIP(r)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": targetID, "role": string(role), "scoped_group_ids": scopeIDs,
		"expires_at": expiryJSON(expiresAt), "access_window": windowJSON(window)})
}

// maxDisplayNameRunes caps a user's display name (rune count, matching the branding cap style).
const maxDisplayNameRunes = 200

// normalizeEmail trims raw and reports whether it is a syntactically acceptable address to STORE: a
// single '@' with a non-empty local and domain part, no spaces or control characters, and no longer
// than 254 bytes (RFC 5321). It is deliberately permissive (no DNS/TLD checks) and does NOT lowercase —
// login matches the email exactly, so storing what the admin typed keeps create and login consistent.
func normalizeEmail(raw string) (string, bool) {
	e := strings.TrimSpace(raw)
	if e == "" || len(e) > 254 {
		return "", false
	}
	at := strings.IndexByte(e, '@')
	if at <= 0 || at == len(e)-1 || at != strings.LastIndexByte(e, '@') {
		return "", false
	}
	for _, r := range e {
		if r <= ' ' || unicode.IsControl(r) {
			return "", false
		}
	}
	return e, true
}

// normalizeDisplayName trims raw, rejects control characters (which would corrupt the console table and
// diverge fake-vs-pg like the branding name did), and caps it at maxDisplayNameRunes RUNES (not bytes).
// An empty display name is allowed (app_user.display_name defaults to ”), so ok is false only for a
// name that is present but invalid.
func normalizeDisplayName(raw string) (string, bool) {
	n := strings.TrimSpace(raw)
	if strings.ContainsFunc(n, func(r rune) bool { return unicode.IsControl(r) }) {
		return "", false
	}
	if utf8.RuneCountInString(n) > maxDisplayNameRunes {
		return "", false
	}
	return n, true
}

// createUserRequest is the body of POST /users. ScopedGroupIDs is a plain slice (not a pointer):
// a NEW user has no existing scope to preserve, so absent/empty is simply tenant-wide.
type createUserRequest struct {
	Email          string          `json:"email"`
	DisplayName    string          `json:"display_name"`
	Role           string          `json:"role"`
	ScopedGroupIDs []string        `json:"scoped_group_ids"`
	ExpiresAt      json.RawMessage `json:"expires_at"`    // docs/56: absent or null = never
	AccessWindow   json.RawMessage `json:"access_window"` // docs/57: absent or null = any time
}

// HandleCreateUser is the protected POST /users: INVITE a new user (docs/01 §5). It creates a
// credential-less app_user in the caller's tenant with a single tenant-wide preset role. Gated on
// CapManageUsers (the rbac vocabulary literally names this "invite/disable users"), PLUS the same
// no-escalation guard role assignment uses — canAdministerUser(actor, the NEW role) — so an admin
// cannot mint a user more privileged than themselves (an Admin cannot create an Owner). Records a
// user.created audit event. The new account has NO credential; it is provisioned separately (a
// first-password setup link) or binds on first OIDC login.
func (s *AuthService) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := p.Grant.Require(CapManageUsers); err != nil {
		writeDenied(w, err)
		return
	}
	var req createUserRequest
	if err := decodeOptionalJSON(w, r, maxSmallJSONBodyBytes, &req, "invalid request body"); err != nil {
		return
	}
	email, ok := normalizeEmail(req.Email)
	if !ok {
		writeError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	displayName, ok := normalizeDisplayName(req.DisplayName)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid display name")
		return
	}
	role := Role(req.Role)
	if !IsAssignableRole(role) {
		writeError(w, http.StatusBadRequest, "unknown role")
		return
	}
	// Validate the (optional) group scope: absent/empty is tenant-wide for a new user.
	scopeIDs, ok := s.resolveExplicitScope(w, r, p.TenantID, req.ScopedGroupIDs)
	if !ok {
		return
	}
	_, expiresAt, ok := parseAccessExpiry(w, req.ExpiresAt)
	if !ok {
		return
	}
	if role == RoleOwner && expiresAt != nil {
		writeError(w, http.StatusBadRequest, "owner access cannot expire; clear the expiry")
		return
	}
	_, window, ok := parseAccessWindowField(w, req.AccessWindow)
	if !ok {
		return
	}
	if role == RoleOwner && window != nil {
		writeError(w, http.StatusBadRequest, "owner access cannot be limited to set hours; clear the access window")
		return
	}
	// No-escalation: an admin cannot create a user whose role — at the assigned scope — exceeds their
	// own authority. canAdministerUser composes with group scope, so a group-scoped admin can only
	// invite within their own groups and cannot mint a tenant-wide user.
	newGrant := NewGrant("", p.TenantID, NewMembership(role, Groups(scopeIDs...)))
	if err := canAdministerUser(p.Grant, newGrant); err != nil {
		writeDenied(w, err)
		return
	}
	userID := newUUID()
	if err := s.Users.CreateUserAssignment(r.Context(), p.TenantID, userID, email, displayName,
		Assignment{Role: role, ScopedGroupIDs: scopeIDs, ExpiresAt: expiresAt, Window: window, WindowSupplied: window != nil,
			ExpectTreeVersion: expectTreeVersion(p.Grant)}); err != nil {
		switch {
		case errors.Is(err, ErrGroupTreeChanged):
			writeError(w, http.StatusConflict, ErrGroupTreeChanged.Error())
		case errors.Is(err, ErrUnknownTimeZone):
			writeError(w, http.StatusBadRequest, "access_window.time_zone is not a time zone this server knows")
		case errors.Is(err, ErrEmailExists):
			writeError(w, http.StatusConflict, "a user with that email already exists")
		case errors.Is(err, ErrUnknownRole):
			writeError(w, http.StatusBadRequest, "unknown role")
		default:
			writeError(w, http.StatusInternalServerError, "could not create user")
		}
		return
	}
	if err := s.recordAuthEventFor(r.Context(), p.TenantID, p.UserID, userID, "user.created",
		map[string]any{"email": email, "role": string(role), "scoped_group_ids": scopeIDs,
			"expires_at": expiryJSON(expiresAt), "access_window": windowJSON(window), "ip": clientIP(r)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": UserSummary{
		ID: userID, Email: email, DisplayName: displayName, Disabled: false, Roles: []string{string(role)},
		ScopedGroupIDs: nonNilStrings(scopeIDs), AccessExpiresAt: expiresAt, AccessWindow: window,
	}})
}

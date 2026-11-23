package controlplane

// First-password provisioning and administrative password reset — the path POST /me/password
// deliberately refuses to be (auth.go: it answers 409 when there is no credential to verify
// against, because a live session alone must never be able to mint a first password).
//
// Three endpoints, two of them administrative:
//
//	POST   /users/{id}/password-reset   mint a single-use setup link for a named user   CapManageUsers
//	DELETE /users/{id}/password-reset   cancel that user's outstanding links            CapManageUsers
//	POST   /auth/password/redeem        the user redeems one and sets a password        PUBLIC
//
// The design rationale lives in migrations/0020_credential_token.sql and credential_token.go; the
// two properties worth repeating where the handlers are, because they are what keeps an
// administrative reset from being an administrative TAKEOVER:
//
//   - redeeming NEVER touches user_totp, so a reset re-provisions the first factor only and the
//     account owner's second factor still stands in the way;
//   - redeeming NEVER issues a session, so possession of a link is not access — the redeemer sets a
//     password and then logs in through the one path that enforces TOTP.

import (
	"errors"
	"log"
	"net/http"
	"time"
)

// maxCredentialTokenBodyBytes caps the redeem body. The policy's own MaxLen bounds the password
// itself; this bounds the envelope, matching maxPasswordBodyBytes on the change path.
const maxCredentialTokenBodyBytes = 1 << 16

// ErrEscalation is returned when a caller tries to administer an account that holds a capability
// the caller does not. See canAdministerUser.
var ErrEscalation = errors.New("cannot reset the credentials of an account with capabilities you do not hold")

// canAdministerUser reports whether actor may re-provision target's credential.
//
// CapManageUsers alone is NOT sufficient, and this is the check that keeps the capability from
// silently meaning "everything". A password-reset link is an account-takeover primitive: whoever
// mints one can redeem it themselves. So without this rule, any Admin could mint a link for the
// Owner, set a password on that account, and hold every capability in the tenant — CapManageTenant
// included — while the audit trail recorded nothing more alarming than a password reset. The
// tenant's privilege hierarchy would be decorative.
//
// The rule is the standard one for delegated administration: you may only re-credential an account
// whose effective authority is a SUBSET of your own. An Owner may reset anyone; two Admins may
// reset each other (lateral, not escalation); an Admin may not reset an Owner.
//
// AUTHORITY MEANS (capability, group scope), NOT capability alone. The first draft compared
// `target.Allows(c)` against `actor.Allows(c)`, and Allows discards the group scope by design — so
// a group-scoped Admin was credited with tenant-wide authority and the check passed for targets it
// should have refused. Concretely: Alice is Admin over group A only; Bob is Technician over group B.
// Every capability Bob holds is inside the Admin preset, so the old check said "subset" and minted
// the link; Alice redeemed it herself, logged in as Bob, and then passed
// RequireMachine(CapStartSession, "group-B") and AllowsInGroup(CapBackstageShell, "group-B") — a
// SYSTEM-level backstage shell on machines her own grant denies her, which is the exact isolation
// this product sells. The comparison is therefore per capability AND per scope: for every
// capability the target holds anywhere, the actor must hold it over at least the same groups.
//
// This is the same lesson handleMintEnrollmentToken already learned (its group check exists because
// "a group-scoped Admin could mint a token for a group they have no rights over and then reach the
// machine that redeems it") — an authority-granting endpoint cannot be gated on a tenant-wide
// capability test when the authority it grants is group-scoped.
//
// Note the asymmetry is only in what each side is asked. The TARGET's scope is read as a union over
// all its memberships (everything that account can do anywhere), because whoever takes the account
// over inherits all of it. The ACTOR is asked whether that union fits inside theirs.
//
// The operational cost is real and deliberate: if a tenant's only Owner loses their password, no
// Admin can reset it, and recovery is an out-of-band database operation. That is the correct
// trade — the alternative is that "Admin" and "Owner" are the same role with extra steps.
//
// TIMING: this is checked when the link is MINTED and cannot be rechecked when it is redeemed —
// redemption is unauthenticated by construction, so there is no actor to re-evaluate. A link
// therefore outlives the authority that produced it, bounded by the token's TTL (one hour by
// default) and cancellable with DELETE /users/{id}/password-reset.
func canAdministerUser(actor, target *Grant) error {
	if actor == nil {
		return ErrEscalation
	}
	if target == nil {
		// No grant resolved for the target means no capabilities, which is a subset of anything.
		return nil
	}
	for _, c := range AllCapabilities {
		targetScope, held := target.ScopeFor(c)
		if !held {
			continue
		}
		actorScope, actorHolds := actor.ScopeFor(c)
		if !actorHolds || !actorScope.Includes(targetScope) {
			return ErrEscalation
		}
	}
	return nil
}

// issuePasswordResetRequest is the body of POST /users/{id}/password-reset. Password is REQUIRED:
// see the step-up note on HandleIssuePasswordReset. TTLSeconds is optional.
type issuePasswordResetRequest struct {
	Password   string `json:"password"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// HandleIssuePasswordReset is the protected POST /users/{id}/password-reset: an administrator
// mints a single-use, expiring link that lets the named user set a password — their FIRST one
// (provisioning) or a replacement (reset).
//
// It hands the plaintext back to the ADMINISTRATOR rather than mailing it, because this deployment
// has no mail path at all (docs/01 §8: "no SMTP/mail path anywhere"). Distribution is therefore
// out of band and the administrator sees the secret, which is exactly why the token is single-use,
// short-lived, superseded by the next mint, and unable to touch the account's second factor.
//
// TWO CHECKS BEYOND CapManageUsers, both of which the first draft of this handler lacked and an
// adversarial review found:
//
//   - THE CALLER RE-PROVES THEIR PASSWORD. This endpoint mints an account-takeover primitive, and
//     without a step-up a caller holding a STOLEN admin session could mint one — for any account in
//     the tenant, including their own — and convert a session that expires in hours into a password
//     that does not. That is precisely what /me/password refuses to allow (it verifies the current
//     password rather than trusting the session it arrived on), so an administrative route that
//     did not would be a way around that refusal. The proof is metered on the SAME per-session key
//     as /me/password and the TOTP step-up, so a rider gets one budget for the password across
//     every endpoint that asks for it.
//   - SELF-TARGETING IS REFUSED. Minting for your own account is a password change, and there is
//     an endpoint for that which does the job properly: /me/password verifies the current password,
//     rejects a no-op, revokes every session and rotates the caller's. Allowing the same thing here
//     would be a second, weaker path to the same mutation — and before the step-up above existed it
//     was an unauthenticated-in-effect one. This is a 400 pointing at the right route, not a denial:
//     the caller is allowed to change their password, just not like this.
func (s *AuthService) HandleIssuePasswordReset(w http.ResponseWriter, r *http.Request) {
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
	// Compare CANONICALLY (sameUserID), not with a raw `==`: Postgres resolves a uuid case/format-
	// insensitively, so a self-targeting id re-spelled (uppercase/braces/dashless) would otherwise slip
	// past this redirect and mint an admin-path reset link for the caller's own account.
	if sameUserID(targetID, p.UserID) {
		writeError(w, http.StatusBadRequest,
			"use POST /me/password to change your own password; it verifies the current one")
		return
	}
	var req issuePasswordResetRequest
	// The body is optional at the transport level; the step-up below is what rejects an empty one.
	if err := decodeOptionalJSON(w, r, maxCredentialTokenBodyBytes, &req, "invalid request body"); err != nil {
		return
	}
	// The ceiling is compared in SECONDS, before the multiplication. Converting first overflows
	// int64 for ttl_seconds above ~9.2e9 (1e10 s is 1e19 ns against a 9.22e18 ceiling), and the
	// wrapped NEGATIVE duration then passes `ttl > MaxCredentialTokenTTL` — minting a link whose
	// expires_at is in the past, behind a 201, having already superseded the user's live one.
	const maxTTLSeconds = int(MaxCredentialTokenTTL / time.Second)
	ttl := DefaultCredentialTokenTTL
	switch {
	case req.TTLSeconds < 0:
		writeError(w, http.StatusBadRequest, "ttl_seconds must be positive")
		return
	case req.TTLSeconds > maxTTLSeconds:
		writeError(w, http.StatusBadRequest, "ttl_seconds exceeds the maximum credential-token lifetime")
		return
	case req.TTLSeconds > 0:
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	// The caller re-proves their own password before any of this touches somebody else's account.
	actor, err := s.Users.FindUserByID(r.Context(), p.TenantID, p.UserID)
	if err != nil || actor == nil {
		writeError(w, http.StatusInternalServerError, "could not resolve the calling user")
		return
	}
	if actor.PasswordHash == "" {
		// No credential to step up with — the same 409 /me/password and the TOTP enrollment give,
		// for the same reason: the session would be the only authority involved.
		writeError(w, http.StatusConflict, ErrNoLocalCredential.Error())
		return
	}
	th := s.throttle()
	stepUpKeys := []string{passwordThrottleKey(p)}
	if retry, ok := th.Allow(stepUpKeys...); !ok {
		writeThrottled(w, retry)
		return
	}
	ok, verr := VerifyPasswordCtx(r.Context(), actor.PasswordHash, req.Password)
	if IsHashCapacityError(verr) {
		// No argon2 capacity (docs/25 F01) — the step-up password was never examined, so it costs
		// no budget and files no denial event.
		WriteHashBusy(w)
		return
	}
	if verr != nil || !ok {
		th.Fail(stepUpKeys...)
		s.auditPasswordEvent(r, p, "auth.password_reset_denied",
			map[string]any{"target_user_id": targetID})
		writeError(w, http.StatusForbidden, "current password required to mint a credential-setup link")
		return
	}
	th.Reset(stepUpKeys...)

	// Resolve the target INSIDE the caller's tenant. FindUserByID is tenant-scoped, so an id from
	// another tenant is simply not found — the endpoint cannot be aimed across a tenant boundary.
	target, err := s.Users.FindUserByID(r.Context(), p.TenantID, targetID)
	if err != nil || target == nil {
		if err != nil && !errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusInternalServerError, "could not resolve user")
			return
		}
		writeError(w, http.StatusNotFound, "no such user")
		return
	}
	if target.Disabled {
		// Minting for a disabled account would produce a link that cannot be redeemed (the store
		// refuses one), so say so rather than handing over a dead secret.
		writeError(w, http.StatusConflict, "user is disabled")
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

	// firstProvision is captured BEFORE the mint so the audit event records which of the two things
	// this was: handing a brand-new account its first credential, or replacing a live one. They
	// have different blast radii and a reviewer reading the trail should not have to infer which.
	firstProvision := target.PasswordHash == ""
	plaintext, tok, err := s.CredentialTokens.Mint(r.Context(), p.TenantID, targetID, p.UserID, s.now().Add(ttl))
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusNotFound, "no such user")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not mint credential token")
		return
	}
	// An unauditable credential-lifecycle mutation must be loud. The token already exists at this
	// point, so failing the request is not enough on its own — it is revoked first, or the caller
	// would be told the mint failed while a live takeover link sat in the database.
	if err := s.recordAuthEventFor(r.Context(), p.TenantID, p.UserID, targetID, "auth.password_reset_issued",
		map[string]any{
			"token_id":        tok.ID,
			"first_provision": firstProvision,
			"expires_at":      tok.ExpiresAt.UTC().Format(time.RFC3339),
			"ip":              clientIP(r),
		}); err != nil {
		if _, rerr := s.CredentialTokens.RevokeForUser(r.Context(), p.TenantID, targetID); rerr != nil {
			log.Printf("credential token %s was minted, could not be audited, AND could not be revoked: %v", tok.ID, rerr)
		}
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	// The plaintext is shown ONCE, here; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":            plaintext,
		"credential_token": tok,
		"first_provision":  firstProvision,
	})
}

// HandleRevokePasswordReset is the protected DELETE /users/{id}/password-reset: cancel every
// outstanding setup link for a user.
//
// It exists because minting is the only other way to invalidate one, and minting produces a NEW
// live link — so without this, an administrator who sent a link to the wrong address had no way to
// take it back short of disabling the account. Idempotent: revoking when nothing is outstanding
// reports zero, not an error.
func (s *AuthService) HandleRevokePasswordReset(w http.ResponseWriter, r *http.Request) {
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
	// Resolve the target before touching anything. This handler used to revoke and AUDIT against
	// whatever string was in the path without ever establishing that it named a user, which had two
	// consequences: `DELETE /users/not-a-uuid/password-reset` reached app_user.id's `uuid` cast and
	// 500'd (pathid.go — the store now reports that as "no such user"), and every call wrote an
	// auth.password_reset_revoked event naming a subject that need not exist, so the trail could
	// assert a revocation that never had anything to revoke.
	//
	// Tenant-scoped, so an id from another tenant is simply not found and this cannot be aimed
	// across a tenant boundary — same argument as the mint path above.
	// The `target == nil` arm mirrors the mint path: both stores signal an unknown user with
	// ErrNoUser rather than a nil-nil return, but a store that did the latter must not be read here
	// as "the user exists".
	if target, err := s.Users.FindUserByID(r.Context(), p.TenantID, targetID); err != nil || target == nil {
		if err == nil || errors.Is(err, ErrNoUser) {
			writeError(w, http.StatusNotFound, "no such user")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not resolve user")
		return
	}
	// No canAdministerUser check here, deliberately: this only ever REMOVES an outstanding
	// credential, so it cannot escalate. Refusing it on hierarchy grounds would mean an Admin who
	// spotted a mis-sent link for the Owner had to watch it stay live.
	revoked, err := s.CredentialTokens.RevokeForUser(r.Context(), p.TenantID, targetID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke credential tokens")
		return
	}
	if err := s.recordAuthEventFor(r.Context(), p.TenantID, p.UserID, targetID, "auth.password_reset_revoked",
		map[string]any{"revoked": revoked, "ip": clientIP(r)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record audit event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": revoked})
}

type redeemPasswordResetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// HandleRedeemPasswordReset is the PUBLIC POST /auth/password/redeem: the user presents the
// single-use token and sets a password.
//
// Unauthenticated by construction — the whole point is that the caller has no usable credential —
// so, like /enroll/redeem, it sits outside the auth → tenant chain, the token in the body IS the
// authorization, and it is CSRF-exempt (there is no ambient session to ride).
//
// Order of operations, and why it is this order:
//
//	PEEK, don't consume   The policy check below needs the account's email/display name (it refuses
//	                      a password that echoes them), and consuming first would burn the user's
//	                      one-shot link every time they typed a password the policy rejects.
//	meter INVALID tokens  Metering happens AFTER the lookup and only when it fails, so a lockout can
//	                      never refuse a genuine link. Ordering it the other way — the obvious way,
//	                      and how this was first written — meant that behind the reverse proxy
//	                      docs/10 documents, where clientIP is the proxy for every caller, one
//	                      attacker's garbage tokens 429 account recovery for the whole deployment.
//	                      That is the same objection passwordThrottleKey already records against
//	                      per-IP keys, and it matters more here: this endpoint IS the recovery path.
//	                      The secret is 256 bits, so the throttle was never the real defence against
//	                      guessing — it bounds a flood, and it can do that without holding the door
//	                      shut on the people it exists to protect.
//	policy                Same ValidatePassword the change path applies. Failures are itemised —
//	                      the user must be told why — and cost neither the token nor throttle
//	                      budget.
//	CONSUME               The atomic gate. It re-checks everything Peek checked, so nothing is
//	                      trusted across the gap, and of two racing redemptions exactly one wins.
//	SetPassword           argon2id hash only; the store never sees a plaintext.
//	revoke all sessions   An account being reset is one whose owner may have lost control of it.
//
// Deliberately NOT done here:
//
//	compare against the CURRENT password. The change path rejects a no-op change so a user cannot
//	believe they retired a compromised password when they did not. Doing the same here would hand
//	whoever holds the link an oracle for the account's EXISTING password — submit a guess, and the
//	"must differ" error confirms it — and that password is very likely reused on other services.
//	A link-holder can already set the password; they must not also be able to LEARN it.
//
//	issuing a session. See the file header: possession of a link is not access.
func (s *AuthService) HandleRedeemPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req redeemPasswordResetRequest
	// Pre-auth (the token in the body IS the credential), so the 400 stays flat for the same reason
	// HandleLogin's does; an over-limit body is now a 413 instead of a 400 quoting the runtime.
	if err := decodeJSONBody(w, r, maxCredentialTokenBodyBytes, &req, "invalid request body"); err != nil {
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	th := s.throttle()
	keys := []string{ipKey("password_redeem", clientIP(r))}
	tok, err := s.CredentialTokens.Peek(r.Context(), req.Token)
	if err != nil {
		if errors.Is(err, ErrCredentialTokenInvalid) {
			// A failed lookup is the only thing metered, and the lockout is applied only to
			// FURTHER failures — see the ordering note above. A caller presenting a real link is
			// never answered 429, however much garbage anyone else sent from the same address.
			if retry, ok := th.Allow(keys...); !ok {
				writeThrottled(w, retry)
				return
			}
			th.Fail(keys...)
			writeError(w, http.StatusForbidden, ErrCredentialTokenInvalid.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not validate credential token")
		return
	}
	// Deliberately NO th.Reset here. Clearing the budget on a valid token would let anyone holding
	// one live link zero the counter on demand — present it, get the reset, guess again — and it
	// buys nothing now that a valid token is never blocked in the first place.

	// The tenant comes from the REDEEMED TOKEN, never from the request. This path has no bound
	// connection, so the store pins the tenant itself.
	u, err := s.Users.FindUserByID(r.Context(), tok.TenantID, tok.UserID)
	if err != nil || u == nil {
		// The token resolved but its user did not — a race with deletion, or an inconsistency.
		// Same opaque answer as an invalid token.
		writeError(w, http.StatusForbidden, ErrCredentialTokenInvalid.Error())
		return
	}
	if err := ValidatePassword(req.NewPassword, PasswordIdentity{
		Email: u.Email, DisplayName: u.DisplayName,
	}, DefaultPasswordPolicy); err != nil {
		var pe *PasswordPolicyError
		if errors.As(err, &pe) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":   pe.Error(),
				"reasons": pe.Reasons,
			})
			return
		}
		writeError(w, http.StatusBadRequest, "password does not meet policy")
		return
	}

	// Password history check: reject reuse of recently retired credentials. We DO NOT check
	// against the current hash (see the deliberate-NOT-done comment above — that would be an
	// oracle), but we do check against the history so that a reset link cannot be used to
	// cycle back to a recently used password. Uses the user row from Peek (tok.UserID/TenantID).
	//
	// ACCEPTED RESIDUAL RISK (SEC-001): a link-holder can use response time to distinguish
	// whether a guessed candidate matches a retired hash (each match runs one argon2id ~100 ms
	// longer). The risk is bounded — retired hashes are already replaced, and the attacker must
	// hold a valid link — and accepted rather than padded to a constant-time loop, because the
	// cost of padding (passwordHistoryDepth × argon2 always) on the recovery path outweighs the
	// limited information gain over already-retired credentials.
	if err := checkPasswordHistory(r.Context(), s.PasswordHistory, tok.TenantID, tok.UserID, req.NewPassword); err != nil {
		if IsHashCapacityError(err) {
			WriteHashBusy(w)
			return
		}
		if errors.Is(err, ErrPasswordReused) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not check password history")
		return
	}

	// Everything below acts on the row CONSUME returned, not on the peeked one. They name the same
	// account today — the hash is globally unique and neither column is ever updated — but the
	// peeked values were read before the gate and the consumed ones are what storage committed
	// through it, and this project's rule is to act on what storage returned.
	tok, err = s.CredentialTokens.Consume(r.Context(), req.Token)
	if err != nil {
		if errors.Is(err, ErrCredentialTokenInvalid) {
			writeError(w, http.StatusForbidden, ErrCredentialTokenInvalid.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "could not redeem credential token")
		return
	}
	// DELIBERATELY the WAITING variant, not HashPasswordCtx. The token was consumed on the line
	// above and is now spent; a 503 here would destroy a single-use reset link that the user
	// cannot get back without an administrator minting another one. Waiting for argon2 capacity
	// costs a slow response, refusing costs the account its recovery path — and an attacker who
	// could saturate the limiter would otherwise be able to burn every reset link in flight.
	// The process-wide memory bound still applies; only the fast refusal is given up. (docs/25 F01)
	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}
	oldHash := u.PasswordHash // captured before SetPassword; may be empty on first provision
	if _, err := s.Users.SetPassword(r.Context(), tok.TenantID, tok.UserID, hash); err != nil {
		// The token is already spent. Say so plainly: the user must ask for another link rather
		// than retry this one, and an operator reading the log needs to see a consumed token with
		// no credential behind it.
		log.Printf("credential token %s was consumed but the password could not be set: %v", tok.ID, err)
		writeError(w, http.StatusInternalServerError,
			"the reset link was consumed but the password could not be set; request a new link")
		return
	}
	// Push the retired credential into history so it cannot be immediately recycled via another
	// reset link. Skipped on first provision (no previous hash). Best-effort: failure is logged
	// but does not roll back the already-committed credential change.
	if s.PasswordHistory != nil && oldHash != "" {
		if err := s.PasswordHistory.RecordPassword(r.Context(), tok.TenantID, tok.UserID, oldHash); err != nil {
			log.Printf("password reset for user %s but history could not be recorded: %v", tok.UserID, err)
		}
	}
	// From here the password IS set.
	//
	// Revoking every session is what recovers an account whose owner may have lost control of it —
	// the case a reset exists for. It is belt-and-braces rather than the primary mechanism: the
	// credential epoch (migrations/0018) already refuses every session issued against the previous
	// credential version on its next request, INCLUDING one that raced this write. The explicit
	// revocation makes the eviction a fact in the database and a countable number in the audit
	// trail, instead of something that only happens when each stale session next shows up.
	revoked, rerr := s.Sessions.RevokeOtherSessions(r.Context(), tok.TenantID, tok.UserID, "")
	if rerr != nil {
		log.Printf("password was reset for user %s but sessions could not be revoked: %v", tok.UserID, rerr)
		writeError(w, http.StatusInternalServerError,
			"the password was set but existing sessions could not be revoked; revoke them manually")
		return
	}
	// The ACTOR is deliberately EMPTY. Whoever presented this link proved possession of a secret and
	// nothing else — they are not authenticated, and naming the account owner as the actor would
	// record a fact the request does not establish: a stolen link redeemed by an attacker would be
	// indistinguishable in the trail from the owner redeeming their own. handleRedeemEnrollment
	// takes the same position on the same reasoning. The TARGET is the account, which is what the
	// event is about; `issued_by` carries the administrator who created the link, so the trail still
	// joins the two halves.
	if err := s.recordAuthEventFor(r.Context(), tok.TenantID, "", tok.UserID, "auth.password_reset_redeemed",
		map[string]any{
			"token_id":         tok.ID,
			"issued_by":        tok.CreatedBy,
			"sessions_revoked": revoked,
			"ip":               clientIP(r),
		}); err != nil {
		writeError(w, http.StatusInternalServerError,
			"the password was set but the audit event could not be recorded")
		return
	}
	// No session, no cookies: the caller proved possession of a link, not of an identity. They log
	// in next, which is where TOTP is enforced.
	writeJSON(w, http.StatusOK, map[string]any{
		"changed":          true,
		"sessions_revoked": revoked,
	})
}

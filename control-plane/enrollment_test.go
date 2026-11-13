package controlplane

// Handler-level tests for the enrollment-token surface (M1) over the in-memory stores — the
// default no-DB path. The pgx twins live in enrollment_pgstore_test.go (DB-gated).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestMintEnrollmentTokenRejectsAnUnboundedTTL is the enrollment-token twin of
// TestIssueResetRejectsAnUnboundedTTL, and it exists for the same two reasons that one does.
//
// An enrollment token is a DISTRIBUTION CREDENTIAL: whoever holds the plaintext can plant a machine
// into the named group, and that machine's group is what every downstream authorization check
// scopes against. `ttl_seconds` was accepted unbounded, so one request minted a token that is
// effectively immortal — a standing right to enroll into the group, surviving the departure of the
// admin who minted it, and visible in the token listing only as a far-future date nobody reads.
//
// The overflow case is the sharper one and is NOT reached by the merely-over-cap value: the check
// has to compare the SECONDS, before `time.Duration(n) * time.Second` wraps.
func TestMintEnrollmentTokenRejectsAnUnboundedTTL(t *testing.T) {
	srv, _ := newTestServer(ownerPrincipal("u1"))

	// Declared locally on purpose (see TestExpiredCredentialTokenIsRefused): the premise is "more
	// than the cap", and reading the cap from the constant would make this test agree with any
	// future value of it, including no cap at all.
	const capUnderTest = 30 * 24 * time.Hour
	if MaxEnrollmentTokenTTL != capUnderTest {
		t.Fatalf("MaxEnrollmentTokenTTL is %v, this test was written against %v",
			MaxEnrollmentTokenTTL, capUnderTest)
	}

	mint := func(ttlSeconds int, out any) int {
		t.Helper()
		return apiJSON(t, srv, "POST", "/enrollment-tokens",
			fmt.Sprintf(`{"group_id":"g1","ttl_seconds":%d}`, ttlSeconds), out)
	}

	if code := mint(int((capUnderTest + time.Hour).Seconds()), nil); code != http.StatusBadRequest {
		t.Fatalf("over-cap ttl = %d, want 400", code)
	}

	// THE OVERFLOW CASE. 1e10 seconds is 1e19 nanoseconds against an int64 ceiling of ~9.22e18, so
	// the conversion wraps NEGATIVE; a ceiling compared on the Duration then reads "well under the
	// maximum" and mints a token whose expires_at is in the PAST, behind a 201 — the caller is told
	// they have a token and every redemption of it fails.
	//
	// A variable, not a constant: `const` makes the multiplication a compile-time expression Go
	// REFUSES to build ("overflows int64"). The handler's value arrives at runtime from JSON, where
	// the same expression silently wraps instead — which is the whole reason the bug existed.
	overflowSeconds := 10_000_000_000
	if time.Duration(overflowSeconds)*time.Second > 0 {
		t.Fatalf("premise broken: %d seconds no longer overflows time.Duration, so this case "+
			"tests nothing", overflowSeconds)
	}
	var overflowed struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := mint(overflowSeconds, &overflowed); code != http.StatusBadRequest {
		t.Fatalf("overflowing ttl = %d (expires_at %v), want 400",
			code, overflowed.EnrollmentToken.ExpiresAt)
	}

	if code := mint(-1, nil); code != http.StatusBadRequest {
		t.Fatalf("negative ttl = %d, want 400", code)
	}

	// The cap itself is allowed — a boundary that refuses its own value is a different bug, and the
	// over-cap case above cannot tell the two apart.
	var atCap struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := mint(int(capUnderTest.Seconds()), &atCap); code != http.StatusCreated {
		t.Fatalf("ttl exactly at the cap = %d, want 201", code)
	}
	if until := time.Until(atCap.EnrollmentToken.ExpiresAt); until < capUnderTest-time.Minute || until > capUnderTest+time.Minute {
		t.Fatalf("at-cap expires_at is %v out, want ~%v", until, capUnderTest)
	}
	// And an ordinary value still works, with an expiry in the FUTURE.
	var ok struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := mint(3600, &ok); code != http.StatusCreated {
		t.Fatalf("in-range ttl = %d, want 201", code)
	}
	if !ok.EnrollmentToken.ExpiresAt.After(time.Now()) {
		t.Fatalf("in-range mint produced a past expires_at: %v", ok.EnrollmentToken.ExpiresAt)
	}
}

func ownerPrincipal(userID string) *Principal {
	return &Principal{
		UserID:   userID,
		TenantID: "tenant-123",
		Grant:    NewGrant(userID, "tenant-123", NewMembership(RoleOwner, AllGroups())),
	}
}

// testPubkeyHex returns a fresh valid Ed25519 public key, hex-encoded.
func testPubkeyHex(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return hex.EncodeToString(pub)
}

// TestEnrollmentTokenMintListRevoke drives mint → list → revoke through the HTTP surface,
// checking the plaintext is returned exactly once, listings carry only metadata, revocation is
// idempotent, and each mutation is audited.
func TestEnrollmentTokenMintListRevoke(t *testing.T) {
	srv, _ := newTestServer(ownerPrincipal("u1"))

	var minted struct {
		Token           string          `json:"token"`
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens",
		`{"group_id":"g1","ttl_seconds":3600,"max_uses":5}`, &minted); code != http.StatusCreated {
		t.Fatalf("mint = %d", code)
	}
	if minted.Token == "" {
		t.Fatal("mint returned no plaintext token")
	}
	tok := minted.EnrollmentToken
	if tok.ID == "" || tok.TenantID != "tenant-123" || tok.GroupID != "g1" ||
		tok.CreatedBy != "u1" || tok.MaxUses != 5 || tok.Uses != 0 || tok.Revoked {
		t.Fatalf("minted metadata = %+v", tok)
	}
	if until := time.Until(tok.ExpiresAt); until < 55*time.Minute || until > 65*time.Minute {
		t.Fatalf("expires_at not ~1h out: %v", tok.ExpiresAt)
	}

	// Defaults: no ttl/max_uses → DefaultEnrollmentTokenTTL, single-use.
	var defMinted struct {
		Token           string          `json:"token"`
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens", `{"group_id":"g1"}`, &defMinted); code != http.StatusCreated {
		t.Fatalf("default mint = %d", code)
	}
	if defMinted.EnrollmentToken.MaxUses != 1 {
		t.Fatalf("default max_uses = %d, want 1", defMinted.EnrollmentToken.MaxUses)
	}

	// Validation failures.
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens", `{}`, nil); code != http.StatusBadRequest {
		t.Fatalf("missing group_id = %d, want 400", code)
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens", `{"group_id":"g1","ttl_seconds":-1}`, nil); code != http.StatusBadRequest {
		t.Fatalf("negative ttl = %d, want 400", code)
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens", `{"group_id":"g1","max_uses":-1}`, nil); code != http.StatusBadRequest {
		t.Fatalf("negative max_uses = %d, want 400", code)
	}

	// Listing carries metadata only — never a token or hash field.
	var listed struct {
		EnrollmentTokens []EnrollmentToken `json:"enrollment_tokens"`
	}
	if code := apiJSON(t, srv, "GET", "/enrollment-tokens", "", &listed); code != http.StatusOK {
		t.Fatalf("list = %d", code)
	}
	if len(listed.EnrollmentTokens) != 2 {
		t.Fatalf("listed %d tokens, want 2", len(listed.EnrollmentTokens))
	}
	var rawList map[string][]map[string]any
	if code := apiJSON(t, srv, "GET", "/enrollment-tokens", "", &rawList); code != http.StatusOK {
		t.Fatalf("raw list = %d", code)
	}
	for _, entry := range rawList["enrollment_tokens"] {
		for _, k := range []string{"token", "token_hash", "hash", "plaintext"} {
			if _, present := entry[k]; present {
				t.Fatalf("token listing leaks %q: %v", k, entry)
			}
		}
	}

	// Revoke: idempotent; unknown id 404; audited.
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens/"+tok.ID+"/revoke", "", nil); code != http.StatusOK {
		t.Fatalf("revoke = %d", code)
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens/"+tok.ID+"/revoke", "", nil); code != http.StatusOK {
		t.Fatalf("re-revoke = %d, want 200 (idempotent)", code)
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens/no-such-token/revoke", "", nil); code != http.StatusNotFound {
		t.Fatalf("revoke unknown = %d, want 404", code)
	}
	if code := apiJSON(t, srv, "GET", "/enrollment-tokens", "", &listed); code != http.StatusOK {
		t.Fatalf("post-revoke list = %d", code)
	}
	for _, e := range listed.EnrollmentTokens {
		if e.ID == tok.ID && !e.Revoked {
			t.Fatalf("revoked token listed unrevoked: %+v", e)
		}
	}

	var audit struct {
		Events []MgmtAuditEvent `json:"events"`
	}
	if code := apiJSON(t, srv, "GET", "/audit", "", &audit); code != http.StatusOK {
		t.Fatalf("list audit = %d", code)
	}
	// Newest first: revoke, revoke, mint, mint.
	want := []string{"enrollment_token.revoke", "enrollment_token.revoke", "enrollment_token.mint", "enrollment_token.mint"}
	if len(audit.Events) != len(want) {
		t.Fatalf("audit events = %d, want %d", len(audit.Events), len(want))
	}
	for i, e := range audit.Events {
		if e.Action != want[i] || e.ActorUserID != "u1" {
			t.Fatalf("audit[%d] = %+v, want action %s by u1", i, e, want[i])
		}
	}
}

// TestEnrollmentTokenRBAC: the token management surface is gated on CapManageEnrollment, which
// a Technician (who CAN redeem-enroll via enroll_machine) does not hold.
func TestEnrollmentTokenRBAC(t *testing.T) {
	tech := &Principal{
		UserID:   "u2",
		TenantID: "tenant-123",
		Grant:    NewGrant("u2", "tenant-123", NewMembership(RoleTechnician, AllGroups())),
	}
	srv, _ := newTestServer(tech)
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens", `{"group_id":"g1"}`, nil); code != http.StatusForbidden {
		t.Fatalf("technician mint = %d, want 403", code)
	}
	if code := apiJSON(t, srv, "GET", "/enrollment-tokens", "", nil); code != http.StatusForbidden {
		t.Fatalf("technician list = %d, want 403", code)
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens/x/revoke", "", nil); code != http.StatusForbidden {
		t.Fatalf("technician revoke = %d, want 403", code)
	}
}

// TestEnrollmentTokenGroupScoped is the group-scope security proof for the token surface. An
// enrollment token is a machine-planting credential: whatever group it names is the group the
// redeemed machine lands in, and a machine's group is what every downstream check scopes against
// (BackstageCapsFor, RequireMachine). Gating only on the TENANT-WIDE capability therefore let a
// group-scoped Admin mint a token for a group they hold no rights over — and then reach the machine
// that redeemed it. Minting, listing and revocation are all scoped to the token's REAL group.
func TestEnrollmentTokenGroupScoped(t *testing.T) {
	scoped := &Principal{
		UserID:   "u1",
		TenantID: "tenant-123",
		Grant:    NewGrant("u1", "tenant-123", NewMembership(RoleAdmin, Groups("g1"))),
	}
	srv, _ := newTestServer(scoped)
	ctx := context.Background()

	// Mint into the covered group: allowed.
	var mine struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens", `{"group_id":"g1"}`, &mine); code != http.StatusCreated {
		t.Fatalf("mint into the covered group = %d, want 201", code)
	}

	// THE BYPASS: minting into a group the caller's memberships do not cover must be denied, even
	// though the caller holds manage_enrollment tenant-wide-ish (scoped to g1).
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens", `{"group_id":"g2"}`, nil); code != http.StatusForbidden {
		t.Fatalf("mint into an uncovered group = %d, want 403", code)
	}
	// Nothing was created for g2 (the denial happens before the store is touched).
	all, err := srv.EnrollmentTokens.ListTokens(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	for _, tok := range all {
		if tok.GroupID == "g2" {
			t.Fatalf("a token was minted into the uncovered group: %+v", tok)
		}
	}

	// A token that exists in g2 (minted by someone who legitimately covers it) is invisible to
	// this caller and cannot be revoked by them.
	other := &EnrollmentToken{GroupID: "g2", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1}
	if _, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", other); err != nil {
		t.Fatalf("MintToken (g2): %v", err)
	}

	var listed struct {
		EnrollmentTokens []EnrollmentToken `json:"enrollment_tokens"`
	}
	if code := apiJSON(t, srv, "GET", "/enrollment-tokens", "", &listed); code != http.StatusOK {
		t.Fatalf("list = %d", code)
	}
	if len(listed.EnrollmentTokens) != 1 || listed.EnrollmentTokens[0].ID != mine.EnrollmentToken.ID {
		t.Fatalf("listing = %+v, want only the caller's own g1 token", listed.EnrollmentTokens)
	}

	// Out-of-scope revoke reports 404 rather than 403: the surface must not confirm that a token
	// the caller may not manage exists.
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens/"+other.ID+"/revoke", "", nil); code != http.StatusNotFound {
		t.Fatalf("revoke out-of-scope token = %d, want 404", code)
	}
	stillLive, err := srv.EnrollmentTokens.ListTokens(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	for _, tok := range stillLive {
		if tok.ID == other.ID && tok.Revoked {
			t.Fatal("an out-of-scope token was revoked")
		}
	}
	// In-scope revoke still works.
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens/"+mine.EnrollmentToken.ID+"/revoke", "", nil); code != http.StatusOK {
		t.Fatalf("revoke in-scope token = %d, want 200", code)
	}

	// A tenant-wide Owner is unaffected: both groups remain mintable, listable and revocable.
	ownerSrv, _ := newTestServer(ownerPrincipal("u2"))
	for _, g := range []string{"g1", "g2"} {
		if code := apiJSON(t, ownerSrv, "POST", "/enrollment-tokens", `{"group_id":"`+g+`"}`, nil); code != http.StatusCreated {
			t.Fatalf("owner mint into %s = %d, want 201", g, code)
		}
	}
	if code := apiJSON(t, ownerSrv, "GET", "/enrollment-tokens", "", &listed); code != http.StatusOK || len(listed.EnrollmentTokens) != 2 {
		t.Fatalf("owner list = %d %+v, want both tokens", code, listed.EnrollmentTokens)
	}
}

// TestRedeemEnrollment covers the PUBLIC redemption path: happy flow (machine created into the
// token's tenant + group, pubkey pinned, audited with an empty actor) and every failure mode.
// The server's authenticator carries a NIL principal, proving no auth is consulted.
func TestRedeemEnrollment(t *testing.T) {
	srv, _ := newTestServer(nil)
	ctx := context.Background()

	// Mint directly through the store (the HTTP mint surface is covered above; here the
	// nil-principal server must still redeem).
	tok := &EnrollmentToken{GroupID: "g1", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 2}
	plaintext, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", tok)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	pubHex := testPubkeyHex(t)
	var redeemed struct {
		Machine Machine `json:"machine"`
	}
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plaintext+`","device_id":"dev-redeem","pubkey":"`+pubHex+`","name":"KIOSK"}`,
		&redeemed); code != http.StatusCreated {
		t.Fatalf("redeem = %d", code)
	}
	m := redeemed.Machine
	// SECURITY: the caller-supplied device_id is IGNORED — the identity a session ticket
	// authorizes brokering to is minted server-side and handed back in the response.
	if m.ID == "" || m.DeviceID == "" || m.DeviceID == "dev-redeem" || m.TenantID != "tenant-123" ||
		m.GroupID != "g1" || m.Name != "KIOSK" || m.Pubkey != pubHex {
		t.Fatalf("redeemed machine = %+v", m)
	}
	// Nothing was enrolled under the name the redeemer asked for. (The fixture's machine store is
	// the PERMISSIVE dev one, which synthesizes unknown device ids, so assert over the ENROLLED
	// set rather than a lookup.)
	enrolled, err := srv.Machines.ListMachines(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	for _, e := range enrolled {
		if e.DeviceID == "dev-redeem" {
			t.Fatalf("caller-chosen device id was enrolled: %+v", e)
		}
	}
	// The key really is pinned in the store, under the minted identity.
	stored, err := srv.Machines.GetMachine(ctx, "tenant-123", m.DeviceID)
	if err != nil || stored.Pubkey != pubHex {
		t.Fatalf("stored machine pubkey = %+v, %v", stored, err)
	}
	// Audited with an EMPTY actor (no authenticated principal exists at redemption).
	events, err := srv.MgmtAudit.ListEvents(ctx, "tenant-123", 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("audit after redeem = %+v, %v", events, err)
	}
	if events[0].Action != "machine.enroll" || events[0].ActorUserID != "" || events[0].TargetID != m.ID {
		t.Fatalf("redeem audit event = %+v", events[0])
	}

	// Re-redeeming the same device_id can no longer collide: each redemption mints a fresh
	// identity, so the second use simply enrolls a second machine.
	var second struct {
		Machine Machine `json:"machine"`
	}
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plaintext+`","device_id":"dev-redeem","pubkey":"`+pubHex+`"}`, &second); code != http.StatusCreated {
		t.Fatalf("second redeem = %d, want 201", code)
	}
	if second.Machine.DeviceID == m.DeviceID {
		t.Fatalf("two redemptions minted the same device id %q", m.DeviceID)
	}

	// max_uses=2 is now exhausted → generic 403.
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plaintext+`","pubkey":"`+pubHex+`"}`, nil); code != http.StatusForbidden {
		t.Fatalf("exhausted redeem = %d, want 403", code)
	}

	// A redemption naming no device_id at all behaves identically.
	tok2 := &EnrollmentToken{GroupID: "g2", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1}
	plain2, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", tok2)
	if err != nil {
		t.Fatalf("MintToken 2: %v", err)
	}
	var fresh struct {
		Machine Machine `json:"machine"`
	}
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plain2+`","pubkey":"`+pubHex+`"}`, &fresh); code != http.StatusCreated {
		t.Fatalf("redeem without device_id = %d", code)
	}
	if fresh.Machine.DeviceID == "" || fresh.Machine.GroupID != "g2" {
		t.Fatalf("fresh-device machine = %+v", fresh.Machine)
	}
}

// TestRedeemEnrollmentPersistsReportedOS pins migrations/0017's `machine.os` to the REDEEM HANDLER.
//
// This is a regression test for a defect that shipped and survived: the column was added and READ by
// the console from day one, but nothing ever wrote it — the agent sent no `os` and neither enroll
// handler set one, so every enrolled machine displayed a blank OS. It went unnoticed because the
// presence tests set `OS:` on the Machine struct BY HAND and then asserted it round-tripped, which
// exercises the store and asserts a behaviour no production path performed.
//
// So this test deliberately drives the real HTTP path and reads the value back out of the store
// rather than off the response — the response marshals the same in-memory Machine the handler built.
//
// Be honest about its LIMIT, though: the fixture's store is an in-memory fake that keeps whatever
// struct it is handed, so it cannot drop a column and this test cannot prove PERSISTENCE. What it
// pins is the HANDLER (removing `OS: req.OS` fails it, which was verified by mutation). The
// storage half is pinned against real Postgres by TestPgRedeemEnrollChainAsAppRole, which re-reads
// machine.os as superuser after the actual INSERT.
func TestRedeemEnrollmentPersistsReportedOS(t *testing.T) {
	srv, _ := newTestServer(nil)
	ctx := context.Background()

	tok := &EnrollmentToken{GroupID: "g1", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 2}
	plaintext, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", tok)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	pubHex := testPubkeyHex(t)
	const reportedOS = "Windows 11 Pro 25H2 (build 26200)"

	var redeemed struct {
		Machine Machine `json:"machine"`
	}
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plaintext+`","pubkey":"`+pubHex+`","name":"KIOSK","os":"`+reportedOS+`"}`,
		&redeemed); code != http.StatusCreated {
		t.Fatalf("redeem = %d", code)
	}
	stored, err := srv.Machines.GetMachine(ctx, "tenant-123", redeemed.Machine.DeviceID)
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if stored.OS != reportedOS {
		t.Fatalf("stored machine OS = %q, want %q — the redeem handler is not persisting the agent's reported OS", stored.OS, reportedOS)
	}

	// The PREMISE the old code silently relied on: omitting `os` yields an empty column, not a
	// fabricated value. Without this, a handler that hard-coded some default would pass the check
	// above while reporting fiction for every agent that never sent one.
	var noOS struct {
		Machine Machine `json:"machine"`
	}
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plaintext+`","pubkey":"`+pubHex+`"}`, &noOS); code != http.StatusCreated {
		t.Fatalf("redeem without os = %d", code)
	}
	blank, err := srv.Machines.GetMachine(ctx, "tenant-123", noOS.Machine.DeviceID)
	if err != nil {
		t.Fatalf("GetMachine (no os): %v", err)
	}
	if blank.OS != "" {
		t.Fatalf("machine enrolled without an os has OS = %q, want empty", blank.OS)
	}
}

// TestRedeemEnrollmentBoundsReportedOS: `os` is attacker-controlled on this UNAUTHENTICATED
// endpoint and is echoed into listings, so it is length-bounded exactly like `name` rather than
// left to the database's unbounded text.
func TestRedeemEnrollmentBoundsReportedOS(t *testing.T) {
	srv, _ := newTestServer(nil)
	ctx := context.Background()

	tok := &EnrollmentToken{GroupID: "g1", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 2}
	plaintext, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", tok)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	pubHex := testPubkeyHex(t)
	tooLong := strings.Repeat("A", maxMachineNameLen+1)

	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plaintext+`","pubkey":"`+pubHex+`","os":"`+tooLong+`"}`, nil); code != http.StatusBadRequest {
		t.Fatalf("over-long os = %d, want 400", code)
	}
	// Rejected BEFORE the token is consumed: a malformed request must not burn a use.
	remaining, err := srv.EnrollmentTokens.ListTokens(ctx, "tenant-123")
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	for _, e := range remaining {
		if e.Uses != 0 {
			t.Fatalf("a 400 on an over-long os consumed a token use (uses=%d)", e.Uses)
		}
	}
}

// TestRedeemEnrollmentFailsClosed: every invalid-token shape is the same generic 403, and a
// missing/malformed pubkey is rejected before any token state is touched.
func TestRedeemEnrollmentFailsClosed(t *testing.T) {
	srv, _ := newTestServer(nil)
	ctx := context.Background()
	pubHex := testPubkeyHex(t)

	// Unknown token.
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"never-minted","pubkey":"`+pubHex+`"}`, nil); code != http.StatusForbidden {
		t.Fatalf("unknown token = %d, want 403", code)
	}

	// Expired token (minted directly with a past expiry).
	expired := &EnrollmentToken{GroupID: "g1", ExpiresAt: time.Now().Add(-time.Minute), MaxUses: 1}
	plainExpired, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", expired)
	if err != nil {
		t.Fatalf("MintToken expired: %v", err)
	}
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plainExpired+`","pubkey":"`+pubHex+`"}`, nil); code != http.StatusForbidden {
		t.Fatalf("expired token = %d, want 403", code)
	}

	// Revoked token.
	revoked := &EnrollmentToken{GroupID: "g1", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1}
	plainRevoked, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", revoked)
	if err != nil {
		t.Fatalf("MintToken revoked: %v", err)
	}
	if err := srv.EnrollmentTokens.RevokeToken(ctx, "tenant-123", revoked.ID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plainRevoked+`","pubkey":"`+pubHex+`"}`, nil); code != http.StatusForbidden {
		t.Fatalf("revoked token = %d, want 403", code)
	}

	// Pubkey validation: missing, non-hex, wrong length — all 400 before the token is checked.
	valid := &EnrollmentToken{GroupID: "g1", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 1}
	plainValid, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", valid)
	if err != nil {
		t.Fatalf("MintToken valid: %v", err)
	}
	for name, body := range map[string]string{
		"missing pubkey": `{"token":"` + plainValid + `"}`,
		"non-hex pubkey": `{"token":"` + plainValid + `","pubkey":"zz"}`,
		"short pubkey":   `{"token":"` + plainValid + `","pubkey":"abcd"}`,
		"missing token":  `{"pubkey":"` + pubHex + `"}`,
		"malformed body": `{`,
	} {
		if code := apiJSON(t, srv, "POST", "/enroll/redeem", body, nil); code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", name, code)
		}
	}
	// None of those consumed the valid token's use.
	if code := apiJSON(t, srv, "POST", "/enroll/redeem",
		`{"token":"`+plainValid+`","pubkey":"`+pubHex+`"}`, nil); code != http.StatusCreated {
		t.Fatalf("valid token after bad attempts = %d, want 201 (use must not be consumed by 400s)", code)
	}
}

// The public redeem endpoint is UNAUTHENTICATED, so its input has to be bounded before any
// credential is checked: an oversized body is refused by MaxBytesReader (never buffered whole), and
// the free-text display name is length-checked before it reaches the database.
func TestRedeemEnrollmentBoundsInput(t *testing.T) {
	srv, _ := newTestServer(nil)
	ctx := context.Background()
	pubHex := testPubkeyHex(t)

	tok := &EnrollmentToken{GroupID: "g1", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 3}
	plaintext, err := srv.EnrollmentTokens.MintToken(ctx, "tenant-123", tok)
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}

	// Over the body cap → 400, and the token's use is NOT consumed.
	huge := `{"token":"` + plaintext + `","pubkey":"` + pubHex + `","name":"` +
		strings.Repeat("A", maxRedeemBodyBytes) + `"}`
	if code := apiJSON(t, srv, "POST", "/enroll/redeem", huge, nil); code != http.StatusBadRequest {
		t.Fatalf("oversized body = %d, want 400", code)
	}
	// Within the body cap but with an over-long name → 400 as well.
	long := `{"token":"` + plaintext + `","pubkey":"` + pubHex + `","name":"` +
		strings.Repeat("A", maxMachineNameLen+1) + `"}`
	if code := apiJSON(t, srv, "POST", "/enroll/redeem", long, nil); code != http.StatusBadRequest {
		t.Fatalf("over-long name = %d, want 400", code)
	}
	// A name at the limit is accepted, so the bound is not off by one.
	var ok struct {
		Machine Machine `json:"machine"`
	}
	atLimit := `{"token":"` + plaintext + `","pubkey":"` + pubHex + `","name":"` +
		strings.Repeat("A", maxMachineNameLen) + `"}`
	if code := apiJSON(t, srv, "POST", "/enroll/redeem", atLimit, &ok); code != http.StatusCreated {
		t.Fatalf("name at the limit = %d, want 201", code)
	}
	if len(ok.Machine.Name) != maxMachineNameLen {
		t.Fatalf("stored name length = %d, want %d", len(ok.Machine.Name), maxMachineNameLen)
	}
	// Exactly one use was consumed — the rejections above never reached the token.
	list, err := srv.EnrollmentTokens.ListTokens(ctx, "tenant-123")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListTokens = %+v, %v", list, err)
	}
	if list[0].Uses != 1 {
		t.Fatalf("uses = %d, want 1 (rejected bodies must not consume a use)", list[0].Uses)
	}
}

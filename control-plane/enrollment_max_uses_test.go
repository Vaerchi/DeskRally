package controlplane

// `max_uses` on POST /enrollment-tokens must be bounded, for the reasons MaxEnrollmentTokenUses
// states. This is the companion to TestMintEnrollmentTokenRejectsAnUnboundedTTL: that one bounded
// how LONG an enrollment secret lives, this one bounds how MANY machines it can plant while it is
// alive — and the ttl cap alone left the second quantity wide open.
//
// It also covers a failure mode the ttl cap did not have: `enrollment_token.max_uses` is a
// PostgreSQL `int` (32-bit, migrations/0001) but the Go field is a 64-bit `int`, so an uncapped
// value can be one the storage cannot hold. The in-memory store accepts it happily; the pg twin
// below is what shows the difference.

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// aboveInt32 is a max_uses larger than a PostgreSQL `int` column can store. Declared as a var and
// not a const so it is an ordinary runtime value, exactly as one decoded from a JSON body.
var aboveInt32 = 2_147_483_648 // 2^31

func TestMintEnrollmentTokenRejectsAnUnboundedMaxUses(t *testing.T) {
	srv, _ := newTestServer(ownerPrincipal("u1"))

	// Declared locally on purpose (see TestExpiredCredentialTokenIsRefused): the premise is "more
	// than the cap", and reading the cap from the constant would make this test agree with any
	// future value of it, including no cap at all.
	const capUnderTest = 500
	if MaxEnrollmentTokenUses != capUnderTest {
		t.Fatalf("MaxEnrollmentTokenUses is %d, this test was written against %d",
			MaxEnrollmentTokenUses, capUnderTest)
	}

	mint := func(maxUses int, out any) int {
		t.Helper()
		return apiJSON(t, srv, "POST", "/enrollment-tokens",
			fmt.Sprintf(`{"group_id":"g1","max_uses":%d}`, maxUses), out)
	}

	var over struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := mint(capUnderTest+1, &over); code != http.StatusBadRequest {
		t.Fatalf("over-cap max_uses = %d (minted max_uses %d), want 400",
			code, over.EnrollmentToken.MaxUses)
	}

	// The unstorable case. This is the one the in-memory store cannot refuse on its own: its
	// EnrollmentToken.MaxUses is a Go int, so 2^31 round-trips fine there and only the real column
	// would have objected. The cap makes both paths answer the same 400.
	if aboveInt32 <= 1<<31-1 {
		t.Fatalf("premise broken: %d fits in a PostgreSQL int, so this case tests nothing", aboveInt32)
	}
	var huge struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := mint(aboveInt32, &huge); code != http.StatusBadRequest {
		t.Fatalf("max_uses beyond an int32 = %d (minted max_uses %d), want 400",
			code, huge.EnrollmentToken.MaxUses)
	}

	if code := mint(-1, nil); code != http.StatusBadRequest {
		t.Fatalf("negative max_uses = %d, want 400", code)
	}

	// The cap itself is allowed — a boundary that refuses its own value is a different bug, and the
	// over-cap case above cannot tell the two apart.
	var atCap struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := mint(capUnderTest, &atCap); code != http.StatusCreated {
		t.Fatalf("max_uses exactly at the cap = %d, want 201", code)
	}
	if atCap.EnrollmentToken.MaxUses != capUnderTest {
		t.Fatalf("at-cap mint stored max_uses %d, want %d", atCap.EnrollmentToken.MaxUses, capUnderTest)
	}

	// Omitting the field still means single-use, and an ordinary value is still honoured — the cap
	// must not have quietly become the default, nor clamped every request to itself.
	var omitted struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens", `{"group_id":"g1"}`, &omitted); code != http.StatusCreated {
		t.Fatalf("default mint = %d, want 201", code)
	}
	if omitted.EnrollmentToken.MaxUses != defaultEnrollmentMaxUses {
		t.Fatalf("default max_uses = %d, want %d", omitted.EnrollmentToken.MaxUses, defaultEnrollmentMaxUses)
	}
	var ordinary struct {
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := mint(5, &ordinary); code != http.StatusCreated {
		t.Fatalf("in-range max_uses = %d, want 201", code)
	}
	if ordinary.EnrollmentToken.MaxUses != 5 {
		t.Fatalf("in-range mint stored max_uses %d, want 5", ordinary.EnrollmentToken.MaxUses)
	}
}

// TestPgMintEnrollmentTokenRejectsAnUnboundedMaxUses is the assertion the in-memory twin above
// structurally cannot make: it drives the mint into the REAL `int` column as rmt_app.
//
// Without the cap the request does not merely store something unwise — the INSERT cannot represent
// the value at all, so the caller is answered by whatever the driver's range error becomes on its
// way out of the handler. With the cap it is a clean 400 that never reaches the database.
func TestPgMintEnrollmentTokenRejectsAnUnboundedMaxUses(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyEnrollmentMigration(t, suPool)
	applyMgmtAuditChainMigration(t, suPool)
	tid, uid := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, suPool, tid)

	appPool := newAppRolePool(t, context.Background())
	srv := NewServer(StubAuthenticator{Principal: &Principal{
		UserID:   uid,
		TenantID: tid,
		Grant:    NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups())),
	}}, NewPgBinder(appPool))
	srv.Machines = NewPgMachineStore(appPool)
	srv.MgmtAudit = NewPgMgmtAuditStore(appPool)
	srv.EnrollmentTokens = NewPgEnrollmentTokenStore(appPool)

	mint := func(maxUses int) int {
		t.Helper()
		return apiJSON(t, srv, "POST", "/enrollment-tokens",
			fmt.Sprintf(`{"group_id":"%s","max_uses":%d}`, gid, maxUses), nil)
	}

	if code := mint(aboveInt32); code != http.StatusBadRequest {
		t.Fatalf("max_uses beyond an int32 against the real column = %d, want 400", code)
	}
	if code := mint(MaxEnrollmentTokenUses + 1); code != http.StatusBadRequest {
		t.Fatalf("over-cap max_uses against the real column = %d, want 400", code)
	}

	// A token AT the cap is storable and comes back with the value it was minted with, which is what
	// makes the ceiling a real limit rather than a number the DB would have rejected anyway.
	var atCap struct {
		Token           string          `json:"token"`
		EnrollmentToken EnrollmentToken `json:"enrollment_token"`
	}
	if code := apiJSON(t, srv, "POST", "/enrollment-tokens",
		fmt.Sprintf(`{"group_id":"%s","max_uses":%d}`, gid, MaxEnrollmentTokenUses), &atCap); code != http.StatusCreated {
		t.Fatalf("max_uses at the cap against the real column = %d, want 201", code)
	}
	if atCap.EnrollmentToken.MaxUses != MaxEnrollmentTokenUses {
		t.Fatalf("at-cap mint stored max_uses %d, want %d",
			atCap.EnrollmentToken.MaxUses, MaxEnrollmentTokenUses)
	}
	// Read it back through the store rather than trusting the response echo.
	var stored int
	if err := suPool.QueryRow(context.Background(),
		"SELECT max_uses FROM enrollment_token WHERE id = $1::uuid", atCap.EnrollmentToken.ID).
		Scan(&stored); err != nil {
		t.Fatalf("superuser max_uses read: %v", err)
	}
	if stored != MaxEnrollmentTokenUses {
		t.Fatalf("enrollment_token.max_uses = %d, want %d", stored, MaxEnrollmentTokenUses)
	}
}

package controlplane

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestShortAttendCodeGenerationAndCollisionRetry(t *testing.T) {
	calls := 0
	code, err := mintAttendCode(func(code string, hash []byte) error {
		calls++
		if len(code) != 8 || !validAttendCodeShape(code) || !bytes.Equal(hash, HashToken(code)) {
			t.Fatalf("bad code shape/hash: %q", code)
		}
		if calls < 3 {
			return errAttendCodeCollision
		}
		return nil
	})
	if err != nil || calls != 3 || len(GroupAttendCode(code)) != 9 {
		t.Fatalf("mint: %q %d %v", code, calls, err)
	}
	calls = 0
	_, err = mintAttendCode(func(string, []byte) error { calls++; return errAttendCodeCollision })
	if !errors.Is(err, errAttendCodeCollision) || calls != 8 {
		t.Fatalf("unbounded retry: %d %v", calls, err)
	}
	failure := errors.New("store unavailable")
	calls = 0
	_, err = mintAttendCode(func(string, []byte) error { calls++; return failure })
	if !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("non-collision retried: %d %v", calls, err)
	}
	for _, code := range []string{"7K3M9R2T", "0123456789ABC"} {
		if !validAttendCodeShape(code) {
			t.Errorf("rejected %q", code)
		}
	}
	for _, code := range []string{"1234567", "123456789", "7K3M-9R2T", "7k3m9r2t", "1234567I", "1234567U"} {
		if validAttendCodeShape(code) {
			t.Errorf("accepted %q", code)
		}
	}
}

func TestShortAttendCodeHTTPRedeemSingleUseAndExpiry(t *testing.T) {
	srv, _ := newAttendedServer(t)
	store := srv.Attended.(*InMemoryAttendedStore)
	now := time.Now()
	store.Now = func() time.Time { return now }
	var created attendedCreateResp
	if status := apiJSON(t, srv, "POST", "/attended-sessions", `{"group_id":"`+attendTestGroup+`"}`, &created); status != 201 {
		t.Fatal(status)
	}
	if len(created.JoinCode) != 8 || created.Code != GroupAttendCode(created.JoinCode) || len(created.Code) != 9 {
		t.Fatalf("not short: %+v", created)
	}
	body := `{"code":"` + strings.ToLower(created.Code) + `","pubkey":"` + attendTestPubkey + `","name":"Guest"}`
	if status := apiJSON(t, srv, "POST", "/attended-sessions/redeem", body, nil); status != http.StatusCreated {
		t.Fatalf("short redeem: %d", status)
	}
	if status := apiJSON(t, srv, "POST", "/attended-sessions/redeem", body, nil); status != http.StatusForbidden {
		t.Fatalf("reuse: %d", status)
	}
	var expired AttendedSession
	expired.GroupID = attendTestGroup
	code, err := store.Create(context.Background(), created.Session.TenantID, &expired)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(AttendedCodeTTL + time.Second)
	if _, err := store.Redeem(context.Background(), code, attendTestPubkey, "Guest"); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("expiry: %v", err)
	}
}

func TestLegacyAttendCodeStillRedeems(t *testing.T) {
	srv, _ := newAttendedServer(t)
	store := srv.Attended.(*InMemoryAttendedStore)
	sess := AttendedSession{GroupID: attendTestGroup}
	if _, err := store.Create(context.Background(), "00000000-0000-0000-0000-0000000000bb", &sess); err != nil {
		t.Fatal(err)
	}
	const legacy = "0123456789ABC"
	store.mu.Lock()
	store.sessions[sess.ID].codeHash = hashKey(HashToken(legacy))
	store.mu.Unlock()
	if _, err := store.Redeem(context.Background(), "0123-4567-89ab-c", attendTestPubkey, "Guest"); err != nil {
		t.Fatal(err)
	}
}

func TestPgShortAndLegacyAttendCodes(t *testing.T) {
	pool := newTestPool(t)
	applyMachineDeviceUniqueMigration(t, pool)
	applyDeviceIdentityMigration(t, pool)
	applyAttendedMigration(t, pool)
	tid, uid := provisionUser(t, pool, "short-code", "short@example.test", "password-1234")
	gid := seedGroup(t, pool, tid)
	store := NewPgAttendedStore(newAppRolePool(t, context.Background()))
	ctx := context.Background()
	sess := AttendedSession{GroupID: gid, TechnicianID: uid}
	code, err := store.Create(ctx, tid, &sess)
	if err != nil || len(code) != 8 {
		t.Fatalf("create: %q %v", code, err)
	}
	if _, err = store.Redeem(ctx, GroupAttendCode(strings.ToLower(code)), attendTestPubkey, "Short guest"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Redeem(ctx, code, attendTestPubkey, "Again"); !errors.Is(err, ErrAttendedInvalid) {
		t.Fatalf("reused: %v", err)
	}
	legacy := AttendedSession{GroupID: gid, TechnicianID: uid}
	if _, err = store.Create(ctx, tid, &legacy); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE attended_session SET code_hash=$1 WHERE id=$2`, HashToken("0123456789ABC"), legacy.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Redeem(ctx, "0123-4567-89ab-c", attendTestPubkey, "Legacy guest"); err != nil {
		t.Fatal(err)
	}
}

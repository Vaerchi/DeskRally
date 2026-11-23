package controlplane

// The pg twin of attended_audit_test.go: the two GUEST audit events must land in the REAL chained
// `audit_event` table, written by the least-privilege `rmt_app` role.
//
// This is not redundant with the in-memory test, and the reason is specific rather than ceremonial.
// Both events are written from a PRE-TENANT public route — the guest holds a code or an attend
// token and no principal, so no tenant is pinned by the middleware and the tenant id comes from the
// row the store just resolved. Whether that works is a property of `withTenant` + RLS, and the
// in-memory fake keeps a slice under a mutex: it can show the handler CALLS RecordEvent, and cannot
// show the call succeeds against a policy-enforced table as `rmt_app`.
//
// Two facts here are visible only through the database:
//   - `actor_user_id` is genuinely NULL, not the empty string. The handler passes "" and the insert
//     maps it with NULLIF($3,'')::uuid; the fake stores "" and would look identical either way.
//   - The guest events join the SAME per-tenant hash chain as the technician's, with contiguous
//     `seq`. An event that broke or forked the chain would satisfy every assertion in the fake.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestPgAttendedGuestTransitionsAreAuditedAsAppRole(t *testing.T) {
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)             // 0005 — 0013 GRANTs to rmt_app, so the role must exist
	applyMachineDeviceUniqueMigration(t, suPool) // 0008
	applyDeviceIdentityMigration(t, suPool)      // 0010
	applyAttendedMigration(t, suPool)            // 0013
	applyMgmtAuditChainMigration(t, suPool)      // 0014
	applyFleetDirectiveMigration(t, suPool)      // 0068: the attended redeem asks cp_machine_key_removed (D-C9)
	tid, uid := provisionUser(t, suPool, "acme", "tech@acme.test", "password-1234")
	gid := seedGroup(t, suPool, tid)
	ctx := context.Background()

	appPool := newAppRolePool(t, ctx)
	srv := NewServer(StubAuthenticator{Principal: &Principal{
		UserID:   uid,
		TenantID: tid,
		Grant:    NewGrant(uid, tid, NewMembership(RoleOwner, AllGroups())),
	}}, NewPgBinder(appPool))
	srv.Machines = NewPgMachineStore(appPool)
	srv.MgmtAudit = NewPgMgmtAuditStore(appPool)
	srv.Attended = NewPgAttendedStore(appPool)

	var created attendedCreateResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions",
		`{"group_id":"`+gid+`","reason":"printer"}`, &created); code != http.StatusCreated {
		t.Fatalf("premise not met: create = %d, want 201", code)
	}
	var redeemed attendedRedeemResp
	if code := apiJSON(t, srv, "POST", "/attended-sessions/redeem",
		`{"code":"`+created.JoinCode+`","pubkey":"`+attendTestPubkey+`","name":"USER-PC"}`,
		&redeemed); code != http.StatusCreated {
		t.Fatalf("premise not met: redeem = %d, want 201", code)
	}
	if code := apiJSONAuth(t, srv, "POST", "/attended-sessions/consent", redeemed.AttendToken,
		`{"decision":"accept","consent_user":"alice"}`, nil); code != http.StatusOK {
		t.Fatalf("premise not met: consent = %d, want 200", code)
	}

	// Read the trail as SUPERUSER (RLS-bypassing), so this reports what STORAGE holds rather than
	// what the writing path is willing to show us.
	rows, err := suPool.Query(ctx, `
		SELECT action, actor_user_id::text, target_kind, target_id::text, metadata, seq
		  FROM audit_event
		 WHERE tenant_id = $1::uuid
		 ORDER BY seq
	`, tid)
	if err != nil {
		t.Fatalf("superuser audit read: %v", err)
	}
	defer rows.Close()

	type row struct {
		actor      *string
		targetKind string
		targetID   *string
		meta       []byte
		seq        int64
	}
	trail := map[string]row{}
	var order []string
	var seqs []int64
	for rows.Next() {
		var action string
		var r row
		if err := rows.Scan(&action, &r.actor, &r.targetKind, &r.targetID, &r.meta, &r.seq); err != nil {
			t.Fatalf("scan: %v", err)
		}
		trail[action] = r
		order = append(order, action)
		seqs = append(seqs, r.seq)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	// Control: the technician's event proves the chain and the tenant id are the ones being read.
	create, ok := trail["attended.create"]
	if !ok {
		t.Fatalf("premise not met: attended.create absent; trail = %v", order)
	}
	if create.actor == nil || *create.actor != uid {
		t.Fatalf("attended.create actor = %v, want the technician %s", create.actor, uid)
	}

	for _, action := range []string{"attended.redeem", "attended.consent"} {
		r, ok := trail[action]
		if !ok {
			t.Fatalf("%s did not reach the real audit_event table as rmt_app; trail = %v", action, order)
		}
		// NULL, not "". Only the column can tell these apart.
		if r.actor != nil {
			t.Errorf("%s actor_user_id = %q, want SQL NULL — the guest is not a principal", action, *r.actor)
		}
		if r.targetKind != "attended_session" || r.targetID == nil || *r.targetID != created.Session.ID {
			t.Errorf("%s target = %s/%v, want attended_session/%s", action, r.targetKind, r.targetID, created.Session.ID)
		}
	}

	var meta map[string]any
	if err := json.Unmarshal(trail["attended.consent"].meta, &meta); err != nil {
		t.Fatalf("consent metadata is not an object (%s): %v", trail["attended.consent"].meta, err)
	}
	if meta["decision"] != "accept" || meta["consent_user"] != "alice" {
		t.Errorf("consent metadata = %v, want decision=accept consent_user=alice", meta)
	}

	// The guest events joined the SAME chain rather than forking it: seq is contiguous across all
	// three. A per-tenant chain with a gap is a chain that no longer verifies.
	if len(seqs) != 3 {
		t.Fatalf("expected exactly 3 audit events (create, redeem, consent), got %d: %v", len(seqs), order)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			t.Fatalf("audit seq is not contiguous: %v (%v) — the guest events must extend the "+
				"tenant's existing chain", seqs, order)
		}
	}
}

package controlplane

import (
	"context"
	"encoding/json"
	"testing"
)

// observerCustomPrincipal builds a principal holding EXACTLY caps through a custom (non-preset) role, so
// a test can prove what observe_session and start_session each gate without the presets' migration-0058
// grant getting in the way.
func observerCustomPrincipal(userID, tenantID string, caps ...Capability) *Principal {
	m := Membership{Role: "custom-observer", Scope: AllGroups(), caps: newCapabilitySet(caps)}
	return &Principal{UserID: userID, TenantID: tenantID, SessionID: "sess-custom-" + userID,
		Grant: NewGrant(userID, tenantID, m)}
}

// observerSetTenantSessionCap installs the tenant session-policy schema, sets max_concurrent_sessions,
// and wires the real Postgres policy store into the owner's server, which is the server the seat-cap
// tests start sessions through.
func observerSetTenantSessionCap(t *testing.T, f *toolboxFixture, max int) {
	t.Helper()
	applyTenantSessionPolicyMigration(t, f.su)
	store := NewPgTenantSessionPolicyStore(f.app)
	if err := store.Set(context.Background(), f.tenant, SessionPolicy{MaxConcurrentSessions: max}); err != nil {
		t.Fatalf("set tenant session cap: %v", err)
	}
	f.ownerSrv.SessionPolicies = store
}

// observerAuditMetadata returns the persisted metadata of f.tenant's audit events for action (also
// matched with the "toolbox." namespace the toolbox run audit uses), optionally narrowed to targetID.
func observerAuditMetadata(t *testing.T, f *toolboxFixture, action, targetID string) []map[string]any {
	t.Helper()
	rows, err := f.su.Query(context.Background(), `
		SELECT metadata FROM audit_event
		WHERE tenant_id = $1 AND (action = $2 OR action = 'toolbox.' || $2)
		  AND ($3 = '' OR target_id::text = $3)
		ORDER BY occurred_at`, f.tenant, action, targetID)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

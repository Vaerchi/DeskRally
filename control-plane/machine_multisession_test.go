package controlplane

import (
	"context"
	"net/http"
	"testing"
)

// 2026-10-19: the console offers Observe only for machines whose multi_session_capable is true, and
// nothing set it, so Observe was offered for NO machine. It is now derived from the same
// observerAgentSupported gate POST /sessions enforces for access=view_only, on both the list and
// the single-machine response. 0.1.2 and "unknown" are the negative controls.
func TestMachinesCarryDerivedMultiSessionCapable(t *testing.T) {
	p := ownerPrincipal("u1")
	srv, _ := newTestServer(p)
	store := NewInMemoryMachineStore()
	srv.Machines = store
	ctx := context.Background()
	ids := map[string]string{}
	for dev, version := range map[string]string{"dev-new": "0.1.4+02dc43c", "dev-old": "0.1.2+548fc1c", "dev-unknown": ""} {
		m := &Machine{DeviceID: dev, GroupID: DevDefaultMachineGroupID, Name: dev}
		if err := store.EnrollMachine(ctx, p.TenantID, m); err != nil {
			t.Fatal(err)
		}
		ids[dev] = m.ID
		if version != "" {
			if _, err := store.RecordAgentVersion(ctx, p.TenantID, map[string]string{dev: version}); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := map[string]bool{"dev-new": true, "dev-old": false, "dev-unknown": false}

	var list struct {
		Machines []Machine `json:"machines"`
	}
	if code := apiJSON(t, srv, "GET", "/machines", "", &list); code != http.StatusOK {
		t.Fatalf("GET /machines = %d", code)
	}
	if len(list.Machines) != 3 {
		t.Fatalf("listed %d machines, want 3", len(list.Machines))
	}
	for _, m := range list.Machines {
		got := m.MultiSessionCapable != nil && *m.MultiSessionCapable
		if got != want[m.DeviceID] {
			t.Errorf("list: %s (%q) multi_session_capable=%v, want %v", m.DeviceID, m.AgentVersion, got, want[m.DeviceID])
		}
	}
	for dev, w := range want {
		var one struct {
			Machine Machine `json:"machine"`
		}
		if code := apiJSON(t, srv, "GET", "/machines/"+ids[dev], "", &one); code != http.StatusOK {
			t.Fatalf("GET /machines/%s = %d", ids[dev], code)
		}
		got := one.Machine.MultiSessionCapable != nil && *one.Machine.MultiSessionCapable
		if got != w {
			t.Errorf("one: %s multi_session_capable=%v, want %v", dev, got, w)
		}
	}
}

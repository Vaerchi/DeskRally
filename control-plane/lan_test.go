package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMemoryLanStore(t *testing.T) {
	testLanStore(t, newMemDirHarness(t))
}

func testLanStore(t *testing.T, h *dirHarness) {
	t.Helper()
	ctx := context.Background()
	store := h.machines.(LanStore)
	device := h.addMachineFn(h.group, MachineStatusActive)
	predecessor, replacement, late := newUUID(), newUUID(), newUUID()

	id, revision, err := store.GetSignalingIncarnation(ctx)
	if err != nil || id != nil || revision != 0 {
		t.Fatalf("initial incarnation = %v, revision %d, err %v", id, revision, err)
	}
	activate := func(id string, expected int64, wantOK bool, wantRevision int64) {
		t.Helper()
		ok, revision, err := store.ActivateSignalingIncarnation(ctx, id, expected)
		if err != nil || ok != wantOK || revision != wantRevision {
			t.Fatalf("activation = (%t, %d, %v), want (%t, %d, nil)", ok, revision, err, wantOK, wantRevision)
		}
	}
	allocate := func(deviceID, key, id string, generation, wantEpoch int64, want LanOutcome) {
		t.Helper()
		epoch, outcome, err := store.AllocateLanEpoch(ctx, deviceID, key, id, generation)
		if err != nil || outcome != want || epoch != wantEpoch {
			t.Fatalf("allocate = (%d, %q, %v), want (%d, %q, nil)", epoch, outcome, err, wantEpoch, want)
		}
	}
	gateway := "02:00:00:00:00:02"
	entries := []LanEntry{{MAC: "02:00:00:00:00:01", IPv4Network: "192.168.2.0/24", GatewayMAC: &gateway}}
	snapshot := sha256.Sum256([]byte("first snapshot"))
	empty := sha256.Sum256(nil)
	report := func(deviceID, key, id string, generation, epoch, seq int64, digest []byte, entries []LanEntry, want LanOutcome) {
		t.Helper()
		outcome, err := store.IngestLanReport(ctx, deviceID, key, id, generation, epoch, seq, digest, entries)
		if err != nil || outcome != want {
			t.Fatalf("ingest = (%q, %v), want (%q, nil)", outcome, err, want)
		}
	}
	activate(predecessor, 0, true, 1)
	activate(predecessor, 0, true, 1)
	activate(late, 0, false, 1)
	allocate(device.Device, device.Pub, predecessor, 2, 1, "")
	allocate(device.Device, device.Pub, predecessor, 1, 0, LanSuperseded)
	allocate(device.Device, device.Pub, predecessor, 2, 1, "")
	report(device.Device, device.Pub, predecessor, 2, 1, 9, snapshot[:], entries, LanApplied)
	allocate(device.Device, device.Pub, predecessor, 3, 2, "")
	report(device.Device, device.Pub, predecessor, 2, 1, 10, snapshot[:], entries, LanStaleEpoch)
	report(device.Device, device.Pub, predecessor, 3, 2, 1, snapshot[:], entries, LanApplied)
	allocate(device.Device, device.Pub, predecessor, 2, 0, LanSuperseded)
	report(device.Device, device.Pub, predecessor, 3, 2, 2, snapshot[:], entries, LanApplied)

	activate(replacement, 1, true, 2)
	activate(predecessor, 0, false, 2)
	activate(late, 1, false, 2)
	activate(replacement, 1, true, 2)
	id, revision, err = store.GetSignalingIncarnation(ctx)
	if err != nil || id == nil || *id != replacement || revision != 2 {
		t.Fatalf("replacement incarnation = %v, revision %d, err %v", id, revision, err)
	}
	allocate(device.Device, device.Pub, replacement, 1, 3, "")
	report(device.Device, device.Pub, replacement, 1, 3, 1, snapshot[:], entries, LanApplied)
	allocate(device.Device, device.Pub, predecessor, 10, 0, LanStaleIncarnation)
	report(device.Device, device.Pub, predecessor, 3, 2, 3, snapshot[:], entries, LanStaleIncarnation)
	report(device.Device, device.Pub, replacement, 1, 3, 2, snapshot[:], entries, LanApplied)

	checkLanCounts(t, h, device.ID, 1, 1)
	report(device.Device, device.Pub, replacement, 1, 3, 2, snapshot[:], nil, LanDuplicate)
	checkLanCounts(t, h, device.ID, 1, 1)
	report(device.Device, device.Pub, replacement, 1, 3, 2, empty[:], nil, LanSeqReused)
	report(device.Device, device.Pub, replacement, 1, 3, 1, snapshot[:], entries, LanDropped)
	report(device.Device, device.Pub, replacement, 1, 3, 3, empty[:], nil, LanApplied)
	checkLanCounts(t, h, device.ID, 0, 1)
	report(device.Device, device.Pub, replacement, 1, 3, 2, snapshot[:], entries, LanDropped)

	zero, multicast := "00:00:00:00:00:00", "01:00:00:00:00:01"
	for _, bad := range [][]LanEntry{
		{{MAC: "02:00:00:00:00:AB", IPv4Network: "192.168.2.0/24"}},
		{{MAC: zero, IPv4Network: entries[0].IPv4Network}},
		{{MAC: multicast, IPv4Network: entries[0].IPv4Network}},
		{{MAC: entries[0].MAC, IPv4Network: entries[0].IPv4Network, GatewayMAC: &zero}},
		{{MAC: entries[0].MAC, IPv4Network: entries[0].IPv4Network, GatewayMAC: &multicast}},
		{{MAC: entries[0].MAC, IPv4Network: "192.168.2.1/24"}},
		{{MAC: entries[0].MAC, IPv4Network: "192.168.2.0/31"}},
		{{MAC: entries[0].MAC, IPv4Network: "2001:db8::/24"}},
		{{MAC: entries[0].MAC, IPv4Network: entries[0].IPv4Network, GatewayMAC: new(string)}},
		{entries[0], entries[0]},
		make([]LanEntry, 5),
	} {
		report(device.Device, device.Pub, replacement, 1, 3, 4, snapshot[:], bad, LanBadRequest)
	}

	// Age one machine's facts while another machine has a fresh snapshot.
	report(device.Device, device.Pub, replacement, 1, 3, 4, snapshot[:], entries, LanApplied)
	ageLanFacts(t, h, device.ID)
	fresh := h.addMachineFn(h.group, MachineStatusActive)
	allocate(fresh.Device, fresh.Pub, replacement, 1, 1, "")
	freshEntries := append([]LanEntry(nil), entries...)
	freshEntries[0].GatewayMAC = nil
	report(fresh.Device, fresh.Pub, replacement, 1, 1, 1, snapshot[:], freshEntries, LanApplied)
	if deleted, err := store.PurgeStaleLanFacts(ctx, lanFactRetention); err != nil || deleted != 1 {
		t.Fatalf("purge = (%d, %v), want (1, nil)", deleted, err)
	}
	checkLanCounts(t, h, device.ID, 0, 1)
	checkLanCounts(t, h, fresh.ID, 1, 1)
	report(device.Device, device.Pub, replacement, 1, 3, 4, snapshot[:], entries, LanDuplicate)
	checkLanCounts(t, h, device.ID, 0, 1)
	report(device.Device, device.Pub, replacement, 1, 3, 5, snapshot[:], entries, LanApplied)

	for _, status := range []string{MachineStatusQuarantined, MachineStatusRetired} {
		ineligible := h.addMachineFn(h.group, status)
		allocate(ineligible.Device, ineligible.Pub, replacement, 1, 0, LanNotEligible)
		report(ineligible.Device, ineligible.Pub, replacement, 1, 1, 1, snapshot[:], entries, LanNotEligible)
	}
	ephemeral := h.addMachineFn(h.group, MachineStatusActive)
	markLanTestEphemeral(t, h, ephemeral)
	allocate(ephemeral.Device, ephemeral.Pub, replacement, 1, 0, LanNotEligible)
	report(ephemeral.Device, ephemeral.Pub, replacement, 1, 1, 1, snapshot[:], entries, LanNotEligible)
	allocate(device.Device, fresh.Pub, replacement, 1, 0, LanNotEligible)
	report(device.Device, fresh.Pub, replacement, 1, 3, 6, snapshot[:], entries, LanNotEligible)

	srv := NewServer(StubAuthenticator{}, NoopBinder{})
	srv.Machines, srv.DeviceIdentityToken = h.machines, deviceIdentityToken
	rec := getIdentity(t, srv, ephemeral.Device, "Bearer "+deviceIdentityToken)
	var identity map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &identity); err != nil || rec.Code != http.StatusOK || identity["ephemeral"] != true {
		t.Fatalf("ephemeral device identity = HTTP %d, %#v, %v", rec.Code, identity, err)
	}
	if err := h.machines.SetMachineStatus(ctx, h.tenant, fresh.ID, MachineStatusRetired); err != nil {
		t.Fatal(err)
	}
	if _, err := h.dirs.ForgetMachine(ctx, h.tenant, ForgetMachineInput{MachineID: fresh.ID, ActorID: h.owner, ExpectGroupID: h.group}); err != nil {
		t.Fatal(err)
	}
	checkLanCounts(t, h, fresh.ID, 0, 0)
}

func TestLanInternalRoutes(t *testing.T) {
	srv, store := identityServer(t)
	srv.LAN = store
	id := newUUID()
	device := &Machine{DeviceID: "lan-device", Pubkey: testPubkeyHex(t)}
	if err := store.EnrollMachine(context.Background(), "tenant", device); err != nil {
		t.Fatal(err)
	}
	// 1.3.35 release review (HIGH): with Wake-on-LAN OFF the LAN ingress and incarnation routes do not exist,
	// so signaling can never activate, never advertises lan_v1/wake_v1, and no agent uploads LAN facts.
	off := srv.Handler()
	for _, route := range []struct{ method, path string }{
		{"GET", "/internal/signaling/incarnation"}, {"POST", "/internal/signaling/incarnation"},
		{"POST", "/internal/devices/lan-epoch"}, {"POST", "/internal/devices/lan"},
	} {
		req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+deviceIdentityToken)
		rec := httptest.NewRecorder()
		off.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusUnauthorized {
			t.Fatalf("Wake-on-LAN off: %s %s = HTTP %d, want the route absent", route.method, route.path, rec.Code)
		}
	}
	srv.WakeOnLAN = true
	handler := srv.Handler()
	call := func(method, path string, payload any, token bool, wantCode int, want string) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		if token {
			req.Header.Set("Authorization", "Bearer "+deviceIdentityToken)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != wantCode || strings.TrimSpace(rec.Body.String()) != want {
			t.Fatalf("%s %s = HTTP %d %s, want %d %s", method, path, rec.Code, rec.Body, wantCode, want)
		}
	}
	const incarnationPath = "/internal/signaling/incarnation"
	call("GET", incarnationPath, nil, false, 401, `{"error":"unauthorized"}`)
	call("GET", incarnationPath, nil, true, 200, `{"id":null,"revision":0}`)
	call("POST", incarnationPath, map[string]any{"incarnation": id, "expected_revision": 0}, true, 200, `{"revision":1}`)
	call("POST", incarnationPath, map[string]any{"incarnation": newUUID(), "expected_revision": 0}, true, 409, `{"error":"revision_moved","revision":1}`)
	connection := map[string]any{"device_id": device.DeviceID, "device_pubkey": device.Pubkey, "incarnation": id, "generation": 1}
	call("POST", "/internal/devices/lan-epoch", connection, true, 200, `{"epoch":1}`)
	connection["epoch"], connection["seq"] = 1, 2
	digest := sha256.Sum256(nil)
	connection["digest"], connection["entries"] = hex.EncodeToString(digest[:]), []LanEntry{}
	call("POST", "/internal/devices/lan", connection, true, 200, `{"status":"applied"}`)
	call("POST", "/internal/devices/lan", connection, true, 200, `{"status":"duplicate"}`)
	connection["seq"] = 1
	call("POST", "/internal/devices/lan", connection, true, 200, `{"status":"dropped"}`)
	connection["tenant_id"] = "other-tenant"
	call("POST", "/internal/devices/lan", connection, true, 400, `{"error":"bad_request"}`)
}

func checkLanCounts(t *testing.T, h *dirHarness, machineID string, facts, watermarks int) {
	t.Helper()
	if h.pg {
		checkPgLanCounts(t, h, h.tenant, machineID, facts, watermarks)
		return
	}
	store := h.machines.(*InMemoryMachineStore)
	state, exists := store.lanStates[machineID]
	if len(state.entries) != facts || exists != (watermarks == 1) {
		t.Fatalf("fact count = %d, watermark present = %t, want %d and %d watermark(s)", len(state.entries), exists, facts, watermarks)
	}
}

func ageLanFacts(t *testing.T, h *dirHarness, machineID string) {
	t.Helper()
	if h.pg {
		h.rawSQL(`UPDATE machine_lan SET received_at = now() - interval '31 days' WHERE machine_id = $1`, machineID)
		return
	}
	store := h.machines.(*InMemoryMachineStore)
	state := store.lanStates[machineID]
	state.receivedAt = time.Now().Add(-31 * 24 * time.Hour)
	store.lanStates[machineID] = state
}

func markLanTestEphemeral(t *testing.T, h *dirHarness, machine dirMachine) {
	t.Helper()
	if h.pg {
		h.rawSQL(`UPDATE machine SET ephemeral = true WHERE id = $1`, machine.ID)
		return
	}
	h.machines.(*InMemoryMachineStore).machines[machineKey(h.tenant, machine.Device)].Ephemeral = true
}

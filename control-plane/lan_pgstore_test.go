package controlplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPgLanStore(t *testing.T) {
	h := newPgDirHarness(t)
	testLanStore(t, h)
}

func TestPgLanIsolationAndWakePresets(t *testing.T) {
	h := newPgDirHarness(t)
	ctx := context.Background()
	store := h.machines.(LanStore)
	device := h.addMachineFn(h.group, MachineStatusActive)
	id := newUUID()
	if ok, _, err := store.ActivateSignalingIncarnation(ctx, id, 0); err != nil || !ok {
		t.Fatalf("activate = %t, %v", ok, err)
	}
	epoch, outcome, err := store.AllocateLanEpoch(ctx, device.Device, device.Pub, id, 1)
	if err != nil || outcome != "" {
		t.Fatalf("allocate = %q, %v", outcome, err)
	}
	digest := sha256.Sum256([]byte("snapshot"))
	outcome, err = store.IngestLanReport(ctx, device.Device, device.Pub, id, 1, epoch, 1, digest[:],
		[]LanEntry{{MAC: "02:00:00:00:00:01", IPv4Network: "192.168.2.0/24"}})
	if err != nil || outcome != LanApplied {
		t.Fatalf("ingest = %q, %v", outcome, err)
	}
	checkPgLanCounts(t, h, h.tenant, device.ID, 1, 1)
	checkPgLanCounts(t, h, h.alien, device.ID, 0, 0)

	presets := queryStrings(t, h.su, `SELECT key FROM role WHERE tenant_id IS NULL
		AND 'wake_machine' = ANY(capabilities) ORDER BY key`)
	if len(presets) != 3 || presets[0] != "admin" || presets[1] != "owner" || presets[2] != "technician" {
		t.Fatalf("wake_machine migration presets = %v", presets)
	}
}

func checkPgLanCounts(t *testing.T, h *dirHarness, tenantID, machineID string, facts, watermarks int) {
	t.Helper()
	ctx := context.Background()
	var gotFacts, gotWatermarks int
	err := withTenant(ctx, h.app, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM machine_lan WHERE machine_id = $1),
			(SELECT count(*) FROM machine_lan_state WHERE machine_id = $1)`, machineID).Scan(&gotFacts, &gotWatermarks)
	})
	if err != nil || gotFacts != facts || gotWatermarks != watermarks {
		t.Fatalf("fact and watermark counts = (%d, %d, %v), want (%d, %d, nil)", gotFacts, gotWatermarks, err, facts, watermarks)
	}
}

func TestPgDelayedLanIngestLosesToForget(t *testing.T) {
	f := newPgWakeFixture(t)
	h, target := f.h, f.target
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := h.machines.SetMachineStatus(ctx, h.tenant, target.ID, MachineStatusRetired); err != nil {
		t.Fatal(err)
	}

	gate, gatePID := holdWakeAuditChain(t, f)
	forgotten := make(chan error, 1)
	go func() {
		_, err := h.dirs.ForgetMachine(ctx, h.tenant, ForgetMachineInput{
			MachineID: target.ID, ActorID: h.owner, ExpectGroupID: h.group,
		})
		forgotten <- err
	}()
	forgetPID := waitForWakeBlock(t, f, gatePID)
	type ingestResult struct {
		outcome LanOutcome
		err     error
	}
	ingested := make(chan ingestResult, 1)
	go func() {
		ref := f.issue.Dispatch.ConnRef
		fact := f.issue.Target.Facts[0]
		digest := sha256.Sum256([]byte("delayed snapshot"))
		outcome, err := h.machines.(LanStore).IngestLanReport(ctx, target.Device, target.Pub,
			ref.Incarnation, ref.Generation, f.issue.Dispatch.Epoch, 2, digest[:],
			[]LanEntry{{MAC: fact.MAC, IPv4Network: fact.Network, GatewayMAC: &fact.Gateway}})
		ingested <- ingestResult{outcome, err}
	}()
	waitForWakeBlock(t, f, forgetPID)
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-forgotten; err != nil {
		t.Fatalf("forget: %v", err)
	}
	if result := <-ingested; result.err != nil || result.outcome != LanNotEligible {
		t.Fatalf("delayed ingest = (%q, %v), want not eligible", result.outcome, result.err)
	}
	checkLanCounts(t, h, target.ID, 0, 0)
}

type observedLanRetention struct {
	LanStore
	purged chan error
}

func (s observedLanRetention) PurgeStaleLanFacts(ctx context.Context, olderThan time.Duration) (int64, error) {
	deleted, err := s.LanStore.PurgeStaleLanFacts(ctx, olderThan)
	s.purged <- err
	return deleted, err
}

func TestPgLanRetentionLoopDoesNotDependOnPresence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		presence fixedPresence
	}{
		{"unavailable", fixedPresence{err: errors.New("presence unavailable")}},
		{"zero online", fixedPresence{p: onlineAt(time.Now())}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPgWakeFixture(t)
			h := f.h
			ageLanFacts(t, h, f.target.ID)
			retention := observedLanRetention{LanStore: h.machines.(LanStore), purged: make(chan error, 1)}
			s := &Server{LAN: retention, Presence: tc.presence}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				s.RunLanRetention(ctx)
				close(done)
			}()
			select {
			case err := <-retention.purged:
				cancel()
				<-done
				if err != nil {
					t.Fatalf("retention loop purge: %v", err)
				}
			case <-ctx.Done():
				<-done
				t.Fatal("retention loop did not purge")
			}
			checkLanCounts(t, h, f.target.ID, 0, 1)
			checkLanCounts(t, h, f.relay.ID, 1, 1)
			ref := f.issue.Dispatch.ConnRef
			fact := f.issue.Target.Facts[0]
			digest := sha256.Sum256([]byte(fact.MAC))
			outcome, err := retention.IngestLanReport(context.Background(), f.target.Device, f.target.Pub,
				ref.Incarnation, ref.Generation, f.issue.Dispatch.Epoch, 1, digest[:],
				[]LanEntry{{MAC: fact.MAC, IPv4Network: fact.Network, GatewayMAC: &fact.Gateway}})
			if err != nil || outcome != LanDuplicate {
				t.Fatalf("report replay after retention = (%q, %v), want duplicate", outcome, err)
			}
			checkLanCounts(t, h, f.target.ID, 0, 1)
		})
	}
}

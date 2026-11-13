package controlplane

// The background presence sweep (presence_sweep.go, migrations/0079) against the in-memory stores. The
// database half (the definer function, its grants, cross-tenant reach) is in presence_sweep_pgstore_test.go.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// fixedPresence serves one snapshot (or one error) with a chosen AsOf, which InMemoryPresenceSource cannot.
type fixedPresence struct {
	p   *Presence
	err error
}

func (f fixedPresence) FetchPresence(context.Context) (*Presence, error) { return f.p, f.err }

func onlineAt(asOf time.Time, ids ...string) *Presence {
	p := &Presence{Online: map[string]time.Time{}, AsOf: asOf}
	for _, id := range ids {
		p.Online[id] = asOf
	}
	return p
}

func enrollIn(t *testing.T, store *InMemoryMachineStore, tenant, deviceID string) {
	t.Helper()
	m := &Machine{TenantID: tenant, DeviceID: deviceID, GroupID: "g-" + tenant, Name: deviceID}
	if err := store.EnrollMachine(context.Background(), tenant, m); err != nil {
		t.Fatalf("enroll %s/%s: %v", tenant, deviceID, err)
	}
}

func lastSeenOf(t *testing.T, store *InMemoryMachineStore, tenant, deviceID string) *time.Time {
	t.Helper()
	m, err := store.GetMachine(context.Background(), tenant, deviceID)
	if err != nil {
		t.Fatalf("get %s/%s: %v", tenant, deviceID, err)
	}
	return m.LastSeen
}

// The point of the sweep: machines in EVERY tenant are stamped with nobody listing anything, at the
// snapshot's time, and a machine the feed does not name is left alone.
func TestPresenceSweepStampsEveryTenantWithoutAConsole(t *testing.T) {
	machines := NewInMemoryMachineStore()
	enrollIn(t, machines, "tenant-a", "dev-a1")
	enrollIn(t, machines, "tenant-b", "dev-b1")
	enrollIn(t, machines, "tenant-b", "dev-b-off")
	asOf := time.Now().Add(-10 * time.Second).UTC().Truncate(time.Millisecond)

	srv := NewServer(StubAuthenticator{}, NoopBinder{})
	srv.Machines = machines
	// "dev-unknown" is online but enrolled nowhere: it must stamp nothing and not fail the sweep.
	srv.Presence = fixedPresence{p: onlineAt(asOf, "dev-a1", "dev-b1", "dev-unknown")}

	n, err := srv.SweepPresenceOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 2 {
		t.Fatalf("sweep stamped %d rows, want 2", n)
	}
	for _, c := range []struct{ tenant, id string }{{"tenant-a", "dev-a1"}, {"tenant-b", "dev-b1"}} {
		if got := lastSeenOf(t, machines, c.tenant, c.id); got == nil || !got.Equal(asOf) {
			t.Fatalf("%s/%s last_seen = %v, want the snapshot's AsOf %v", c.tenant, c.id, got, asOf)
		}
	}
	if got := lastSeenOf(t, machines, "tenant-b", "dev-b-off"); got != nil {
		t.Fatalf("an offline machine was stamped: %v", got)
	}

	// The same snapshot again moves nothing (forward-only), and an OLDER one never moves a stamp back.
	if n, err := srv.SweepPresenceOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("a repeat sweep stamped %d (err %v), want 0", n, err)
	}
	srv.Presence = fixedPresence{p: onlineAt(asOf.Add(-time.Hour), "dev-a1")}
	if n, err := srv.SweepPresenceOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("an older snapshot stamped %d (err %v), want 0", n, err)
	}
	if got := lastSeenOf(t, machines, "tenant-a", "dev-a1"); !got.Equal(asOf) {
		t.Fatalf("an older snapshot moved last_seen back to %v", got)
	}
}

// A signaling clock running ahead must not pin last_seen in the future, where the forward-only rule
// would then refuse every honest stamp until the clocks met again.
func TestPresenceSweepClampsAFutureSnapshot(t *testing.T) {
	machines := NewInMemoryMachineStore()
	enrollIn(t, machines, "tenant-a", "dev-a1")
	srv := NewServer(StubAuthenticator{}, NoopBinder{})
	srv.Machines = machines
	srv.Presence = fixedPresence{p: onlineAt(time.Now().Add(24*time.Hour), "dev-a1")}

	before := time.Now()
	if _, err := srv.SweepPresenceOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	got := lastSeenOf(t, machines, "tenant-a", "dev-a1")
	if got == nil || got.After(time.Now()) || got.Before(before) {
		t.Fatalf("last_seen = %v, want clamped to the sweep's own now (%v)", got, before)
	}
}

// A zero AsOf (a feed that sent no clock) falls back to now rather than stamping year 1.
func TestPresenceSweepZeroAsOfUsesNow(t *testing.T) {
	machines := NewInMemoryMachineStore()
	enrollIn(t, machines, "tenant-a", "dev-a1")
	srv := NewServer(StubAuthenticator{}, NoopBinder{})
	srv.Machines = machines
	srv.Presence = fixedPresence{p: onlineAt(time.Time{}, "dev-a1")}

	before := time.Now().Add(-time.Second)
	if n, err := srv.SweepPresenceOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("sweep stamped %d (err %v), want 1", n, err)
	}
	if got := lastSeenOf(t, machines, "tenant-a", "dev-a1"); got == nil || got.Before(before) {
		t.Fatalf("last_seen = %v, want about now", got)
	}
}

// No feed configured is not an error; an unavailable feed is reported (so the runner can log it once)
// and writes nothing.
func TestPresenceSweepWithoutAFeed(t *testing.T) {
	machines := NewInMemoryMachineStore()
	enrollIn(t, machines, "tenant-a", "dev-a1")
	srv := NewServer(StubAuthenticator{}, NoopBinder{})
	srv.Machines = machines

	if n, err := srv.SweepPresenceOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("no feed: stamped %d, err %v; want 0, nil", n, err)
	}
	srv.Presence = fixedPresence{err: ErrPresenceUnavailable}
	if _, err := srv.SweepPresenceOnce(context.Background()); !errors.Is(err, ErrPresenceUnavailable) {
		t.Fatalf("feed down: err = %v, want ErrPresenceUnavailable", err)
	}
	if got := lastSeenOf(t, machines, "tenant-a", "dev-a1"); got != nil {
		t.Fatalf("a failed sweep stamped %v", got)
	}
}

// batchRecorder records the size of every StampPresence call, and can fail the Nth.
type batchRecorder struct {
	*InMemoryMachineStore
	sizes  []int
	failAt int // 1-based call number to fail; 0 never
}

func (b *batchRecorder) StampPresence(ctx context.Context, ids []string, at time.Time) (int, error) {
	b.sizes = append(b.sizes, len(ids))
	if len(b.sizes) == b.failAt {
		return 0, errors.New("boom")
	}
	return b.InMemoryMachineStore.StampPresence(ctx, ids, at)
}

// A large fleet goes to the store in batches no bigger than presenceStampBatch (cp_presence_stamp refuses
// more than 100000), covering every id exactly once; a failing batch stops the sweep and is reported.
func TestPresenceSweepBatches(t *testing.T) {
	const total = 2*presenceStampBatch + 7
	ids := make([]string, total)
	for i := range ids {
		ids[i] = fmt.Sprintf("dev-%05d", i)
	}
	rec := &batchRecorder{InMemoryMachineStore: NewInMemoryMachineStore()}
	enrollIn(t, rec.InMemoryMachineStore, "tenant-a", ids[0])
	enrollIn(t, rec.InMemoryMachineStore, "tenant-a", ids[total-1])
	srv := NewServer(StubAuthenticator{}, NoopBinder{})
	srv.Machines = rec
	srv.Presence = fixedPresence{p: onlineAt(time.Now().Add(-time.Second), ids...)}

	n, err := srv.SweepPresenceOnce(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("sweep stamped %d (err %v), want 2", n, err)
	}
	if want := []int{presenceStampBatch, presenceStampBatch, 7}; fmt.Sprint(rec.sizes) != fmt.Sprint(want) {
		t.Fatalf("batch sizes %v, want %v", rec.sizes, want)
	}

	rec.sizes, rec.failAt = nil, 2
	if _, err := srv.SweepPresenceOnce(context.Background()); err == nil || len(rec.sizes) != 2 {
		t.Fatalf("a failing batch: err %v after %d calls, want an error after 2", err, len(rec.sizes))
	}
}

package controlplane

// Tests for the machine-presence feed (presence.go) and the GET /machines enrichment it drives.
// The DB-backed half — that last_seen really persists under RLS as rmt_app, and that a
// cross-tenant device id in the feed writes nothing — is TestPgMachinePresenceUnderRLS in
// machine_pgstore_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// presenceTestServer wires a Server with an in-memory machine store + presence source and an
// owner-tier principal, returning both so a test can vary presence.
func presenceTestServer(t *testing.T) (*Server, *InMemoryMachineStore, *InMemoryPresenceSource) {
	t.Helper()
	machines := NewInMemoryMachineStore()
	presence := NewInMemoryPresenceSource()
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-1",
		Grant:    NewGrant("u1", "tenant-1", NewMembership(RoleOwner, AllGroups())),
	}
	srv := NewServer(StubAuthenticator{Principal: p}, NoopBinder{})
	srv.Machines = machines
	srv.Presence = presence
	return srv, machines, presence
}

type machineListResponse struct {
	Machines      []Machine `json:"machines"`
	PresenceKnown bool      `json:"presence_known"`
}

func listMachines(t *testing.T, srv *Server) machineListResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/machines", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /machines = %d: %s", rec.Code, rec.Body.String())
	}
	var out machineListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func seedMachine(t *testing.T, store *InMemoryMachineStore, deviceID, name string) {
	t.Helper()
	m := &Machine{TenantID: "tenant-1", DeviceID: deviceID, GroupID: "g1", Name: name, OS: "Windows 11 Pro"}
	if err := store.EnrollMachine(context.Background(), "tenant-1", m); err != nil {
		t.Fatalf("enroll %s: %v", deviceID, err)
	}
}

// The listing reports online for the devices the feed names and offline for the rest, and records
// a last_seen for the online ones.
func TestListMachinesAnnotatesPresence(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	seedMachine(t, machines, "dev-up", "UP-01")
	seedMachine(t, machines, "dev-down", "DOWN-01")

	seen := time.Now().Add(-15 * time.Second).UTC().Truncate(time.Millisecond)
	presence.SetOnline("dev-up", seen)

	got := listMachines(t, srv)
	if !got.PresenceKnown {
		t.Fatal("presence_known = false, want true")
	}
	byDevice := map[string]Machine{}
	for _, m := range got.Machines {
		byDevice[m.DeviceID] = m
	}
	up, down := byDevice["dev-up"], byDevice["dev-down"]
	if up.Online == nil || !*up.Online {
		t.Fatalf("dev-up online = %v, want true", up.Online)
	}
	if down.Online == nil || *down.Online {
		t.Fatalf("dev-down online = %v, want false", down.Online)
	}
	if up.LastSeen == nil || !up.LastSeen.Equal(seen) {
		t.Fatalf("dev-up last_seen = %v, want %v", up.LastSeen, seen)
	}
	// The sighting is persisted, so "offline for 3h" stays answerable after the agent drops.
	stored, err := machines.GetMachine(context.Background(), "tenant-1", "dev-up")
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if stored.LastSeen == nil {
		t.Fatal("last_seen was not persisted for the online machine")
	}
	// An offline machine's last_seen must NOT be stamped — it was not seen.
	storedDown, err := machines.GetMachine(context.Background(), "tenant-1", "dev-down")
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if storedDown.LastSeen != nil {
		t.Fatalf("offline machine got a last_seen stamp: %v", storedDown.LastSeen)
	}
}

// The load-bearing isolation property: the feed is CROSS-TENANT, so it routinely names devices the
// caller does not own. Those must never appear in the listing, be counted, or be distinguishable
// from ids that do not exist.
func TestListMachinesNeverEchoesForeignPresence(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	seedMachine(t, machines, "dev-mine", "MINE-01")

	presence.SetOnline("dev-mine", time.Now())
	// Another MSP's fleet, live on the same signaling server.
	presence.SetOnline("dev-other-tenant-a", time.Now())
	presence.SetOnline("dev-other-tenant-b", time.Now())

	got := listMachines(t, srv)
	if len(got.Machines) != 1 || got.Machines[0].DeviceID != "dev-mine" {
		t.Fatalf("machines = %+v, want only dev-mine", got.Machines)
	}
	// Nothing about the foreign devices may reach the response body at all.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/machines", nil))
	for _, foreign := range []string{"dev-other-tenant-a", "dev-other-tenant-b"} {
		if bodyContains(rec.Body.String(), foreign) {
			t.Fatalf("response leaked a foreign device id %q: %s", foreign, rec.Body.String())
		}
	}
	// …and no foreign row was written by the last_seen stamp either.
	if _, err := machines.GetMachine(context.Background(), "tenant-1", "dev-other-tenant-a"); err != ErrMachineNotFound {
		t.Fatalf("a foreign device id materialized in the tenant's store: %v", err)
	}
}

// The listing REFRESHES machine.os from the feed's agent-asserted value — the column is otherwise
// write-once at enrollment, so an OS upgrade would never reach it (the defect this exists for:
// a fleet that upgraded to a new build forever displaying the enrollment-day os).
func TestListMachinesRefreshesObservedOS(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	seedMachine(t, machines, "dev-upgraded", "UP-01") // seeded os: "Windows 11 Pro"
	seedMachine(t, machines, "dev-same", "SAME-01")
	seedMachine(t, machines, "dev-silent", "OLD-01")

	now := time.Now().UTC()
	presence.SetOnlineWithOS("dev-upgraded", now, "Windows 11 Pro 26H1 (build 27000)")
	presence.SetOnlineWithOS("dev-same", now, "Windows 11 Pro") // identical to the stored value
	presence.SetOnline("dev-silent", now)                       // an older agent: no announcement
	// A foreign tenant's device announcing an os must not materialize or write anything here.
	presence.SetOnlineWithOS("dev-foreign", now, "Windows 11 Enterprise 26H1 (build 27000)")

	listMachines(t, srv)

	if m, _ := machines.GetMachine(context.Background(), "tenant-1", "dev-upgraded"); m.OS != "Windows 11 Pro 26H1 (build 27000)" {
		t.Fatalf("upgraded machine os = %q, want the freshly announced value", m.OS)
	}
	if m, _ := machines.GetMachine(context.Background(), "tenant-1", "dev-same"); m.OS != "Windows 11 Pro" {
		t.Fatalf("unchanged machine os = %q, want it left exactly as stored", m.OS)
	}
	// No announcement must never CLEAR a stored value — absence means "older agent", not "no OS".
	if m, _ := machines.GetMachine(context.Background(), "tenant-1", "dev-silent"); m.OS != "Windows 11 Pro" {
		t.Fatalf("silent machine os = %q, want the stored value preserved", m.OS)
	}
	if _, err := machines.GetMachine(context.Background(), "tenant-1", "dev-foreign"); err != ErrMachineNotFound {
		t.Fatalf("a foreign device id materialized via the os refresh: %v", err)
	}

	// The refresh is bounded even if signaling's own cap were bypassed: an oversized value is
	// dropped (not truncated here — the store is not in the business of rewriting what the agent
	// said), and the stored os stays. Printable padding, so the length bound is the ONLY thing
	// that can reject it.
	presence.SetOnlineWithOS("dev-upgraded", now.Add(time.Second), strings.Repeat("x", 300))
	listMachines(t, srv)
	if m, _ := machines.GetMachine(context.Background(), "tenant-1", "dev-upgraded"); m.OS != "Windows 11 Pro 26H1 (build 27000)" {
		t.Fatalf("oversized announcement overwrote os: %q", m.OS)
	}
}

// Presence fails SOFT: when the feed is unavailable the listing still succeeds, reports
// presence_known=false, and omits `online` — it must NOT claim every machine is offline, which
// would send a technician chasing a phantom outage.
func TestListMachinesDegradesWhenPresenceUnavailable(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	seedMachine(t, machines, "dev-up", "UP-01")
	presence.Err = ErrPresenceUnavailable

	got := listMachines(t, srv)
	if got.PresenceKnown {
		t.Fatal("presence_known = true with an unavailable feed")
	}
	if len(got.Machines) != 1 {
		t.Fatalf("machines = %+v, want the machine to still list", got.Machines)
	}
	if got.Machines[0].Online != nil {
		t.Fatalf("online = %v with an unavailable feed, want omitted (unknown)", *got.Machines[0].Online)
	}

	// Same when no source is wired at all.
	srv.Presence = nil
	if got := listMachines(t, srv); got.PresenceKnown || got.Machines[0].Online != nil {
		t.Fatalf("unwired presence: known=%v online=%v, want false/omitted", got.PresenceKnown, got.Machines[0].Online)
	}
}

// The HTTP client parses the signaling wire shape, sends the service token, caches, and maps every
// failure to ErrPresenceUnavailable.
func TestSignalingPresenceSource(t *testing.T) {
	var calls int
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		// Hand-written literal ON PURPOSE (see signaling's anti-drift note): dev-a announces an os,
		// dev-c is an older agent that sent none — its entry has no "os" key at all.
		_, _ = w.Write([]byte(`{"devices":[
			{"device_id":"dev-a","last_seen_unix_ms":1700000000000,"os":"Windows 11 Pro 25H2 (build 26200)"},
			{"device_id":"dev-c","last_seen_unix_ms":1700000000500}],
			"as_of_unix_ms":1700000001000}`))
	}))
	defer srv.Close()

	now := time.Unix(0, 0)
	src := &SignalingPresenceSource{
		URL: srv.URL, Token: "a-service-token-long-enough-to-be-real",
		CacheTTL: 5 * time.Second, Now: func() time.Time { return now },
	}
	p, err := src.FetchPresence(context.Background())
	if err != nil {
		t.Fatalf("FetchPresence: %v", err)
	}
	if gotAuth != "Bearer a-service-token-long-enough-to-be-real" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if !p.IsOnline("dev-a") || p.IsOnline("dev-b") {
		t.Fatalf("presence = %+v", p.Online)
	}
	if seen, ok := p.LastSeen("dev-a"); !ok || seen.UnixMilli() != 1700000000000 {
		t.Fatalf("last seen = %v (%v)", seen, ok)
	}
	if os, ok := p.ObservedOS("dev-a"); !ok || os != "Windows 11 Pro 25H2 (build 26200)" {
		t.Fatalf("observed os for dev-a = %q (%v), want the announced description", os, ok)
	}
	// An entry with no "os" key parses as "no announcement", not as an empty announcement — the
	// refresh path must be able to tell "agent said nothing" from "agent said something".
	if !p.IsOnline("dev-c") {
		t.Fatal("dev-c should be online")
	}
	if os, ok := p.ObservedOS("dev-c"); ok {
		t.Fatalf("dev-c announced no os but ObservedOS = %q, want absent", os)
	}

	// Within the TTL the snapshot is reused rather than re-fetched.
	if _, err := src.FetchPresence(context.Background()); err != nil {
		t.Fatalf("cached fetch: %v", err)
	}
	if calls != 1 {
		t.Fatalf("HTTP calls = %d, want 1 (second read must come from cache)", calls)
	}
	// Past the TTL it refetches.
	now = now.Add(6 * time.Second)
	if _, err := src.FetchPresence(context.Background()); err != nil {
		t.Fatalf("post-TTL fetch: %v", err)
	}
	if calls != 2 {
		t.Fatalf("HTTP calls = %d, want 2 after the TTL expired", calls)
	}
}

// Every failure mode is ErrPresenceUnavailable — never a partial or stale answer. In particular a
// FAILED fetch must not serve the previous snapshot: reporting a machine online because it was
// online five minutes ago sends the technician into a session that can never establish.
func TestSignalingPresenceSourceFailures(t *testing.T) {
	// Unauthorized (wrong token) → unavailable.
	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer unauthorized.Close()
	src := &SignalingPresenceSource{URL: unauthorized.URL, Token: "tok"}
	if _, err := src.FetchPresence(context.Background()); err == nil {
		t.Fatal("a 401 from signaling was not reported as unavailable")
	}

	// Unconfigured → unavailable, without any network call.
	for _, s := range []*SignalingPresenceSource{
		{URL: "", Token: "tok"},
		{URL: "http://127.0.0.1:1", Token: ""},
	} {
		if _, err := s.FetchPresence(context.Background()); err != ErrPresenceUnavailable {
			t.Fatalf("unconfigured source err = %v, want ErrPresenceUnavailable", err)
		}
	}

	// A source that succeeded once and then starts failing must NOT serve the stale snapshot.
	var fail bool
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[{"device_id":"dev-a","last_seen_unix_ms":1}],"as_of_unix_ms":1}`))
	}))
	defer flaky.Close()
	now := time.Unix(0, 0)
	s := &SignalingPresenceSource{URL: flaky.URL, Token: "tok", CacheTTL: time.Second,
		Now: func() time.Time { return now }}
	if p, err := s.FetchPresence(context.Background()); err != nil || !p.IsOnline("dev-a") {
		t.Fatalf("first fetch: %+v %v", p, err)
	}
	fail = true
	now = now.Add(2 * time.Second) // past the cache TTL
	if p, err := s.FetchPresence(context.Background()); err == nil {
		t.Fatalf("a failed refresh served stale presence: %+v", p.Online)
	}
}

// NEGATIVE CACHING — the property the "one slow request per TTL" comment promised and the code did
// not deliver. During a signaling black-hole, only the FIRST listing may pay the fetch; every other
// one inside the cooldown must short-circuit, because each one is holding a tenant-pinned pgx
// connection while it waits.
func TestPresenceFailuresAreCachedForTheCooldown(t *testing.T) {
	var calls int
	var mu sync.Mutex
	blackhole := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		// Slower than the source's Timeout: this is the black-hole shape, not a clean refusal.
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer blackhole.Close()

	now := time.Unix(0, 0)
	src := &SignalingPresenceSource{
		URL: blackhole.URL, Token: "tok",
		Timeout:         20 * time.Millisecond,
		FailureCooldown: 3 * time.Second,
		Now:             func() time.Time { return now },
	}

	start := time.Now()
	if _, err := src.FetchPresence(context.Background()); err == nil {
		t.Fatal("a timing-out signaling server was not reported as unavailable")
	}
	firstCall := time.Since(start)

	// Nine more listings inside the cooldown: all fail fast, and none of them reaches the network.
	start = time.Now()
	for i := 0; i < 9; i++ {
		if _, err := src.FetchPresence(context.Background()); err == nil {
			t.Fatalf("call %d succeeded against a black-holed signaling server", i)
		}
	}
	cachedCalls := time.Since(start)

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("HTTP calls = %d, want 1 — the failure must be cached like a success is", got)
	}
	// The nine cached failures together must cost far less than the one real attempt did.
	if cachedCalls >= firstCall {
		t.Fatalf("9 cached failures took %v, the single real attempt took %v — no short-circuit",
			cachedCalls, firstCall)
	}

	// Past the cooldown it tries again (and the sighting-free failure is still not stale data).
	now = now.Add(4 * time.Second)
	if _, err := src.FetchPresence(context.Background()); err == nil {
		t.Fatal("post-cooldown call succeeded against a black-holed server")
	}
	mu.Lock()
	got = calls
	mu.Unlock()
	if got != 2 {
		t.Fatalf("HTTP calls = %d after the cooldown expired, want 2", got)
	}
}

// A recovered feed must clear the negative cache immediately — an outage must not cost presence for
// a whole cooldown after signaling is healthy again.
func TestPresenceNegativeCacheClearsOnRecovery(t *testing.T) {
	var down bool
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		fail := down
		mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[{"device_id":"dev-a","last_seen_unix_ms":1}],"as_of_unix_ms":1}`))
	}))
	defer srv.Close()

	now := time.Unix(0, 0)
	src := &SignalingPresenceSource{
		URL: srv.URL, Token: "tok",
		CacheTTL: time.Second, FailureCooldown: time.Second,
		Now: func() time.Time { return now },
	}
	mu.Lock()
	down = true
	mu.Unlock()
	if _, err := src.FetchPresence(context.Background()); err == nil {
		t.Fatal("a 502 was not reported as unavailable")
	}
	mu.Lock()
	down = false
	mu.Unlock()
	// Still inside the cooldown → still unavailable (this is the point of the cooldown).
	if _, err := src.FetchPresence(context.Background()); err == nil {
		t.Fatal("the cooldown did not hold")
	}
	now = now.Add(2 * time.Second)
	p, err := src.FetchPresence(context.Background())
	if err != nil || !p.IsOnline("dev-a") {
		t.Fatalf("recovery fetch = %+v, %v — want the live snapshot", p, err)
	}
	// …and the success must have cleared the failure, not merely been layered over it: the very
	// next call inside the TTL is served from the POSITIVE cache.
	if p2, err := src.FetchPresence(context.Background()); err != nil || !p2.IsOnline("dev-a") {
		t.Fatalf("post-recovery cached read = %+v, %v", p2, err)
	}
}

// SINGLE FLIGHT — the burst case the negative cache alone cannot cover: N console page loads that
// all arrive during the FIRST slow fetch. Without collapsing them, N connections wait N × nothing.
func TestPresenceConcurrentFetchesCollapseIntoOne(t *testing.T) {
	var calls int
	var mu sync.Mutex
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release // hold every request open until the whole burst is in flight
		_, _ = w.Write([]byte(`{"devices":[{"device_id":"dev-a","last_seen_unix_ms":1}],"as_of_unix_ms":1}`))
	}))
	defer srv.Close()

	src := &SignalingPresenceSource{URL: srv.URL, Token: "tok", CacheTTL: -1} // caching OFF: only single-flight can collapse these

	const burst = 8
	var wg sync.WaitGroup
	results := make([]*Presence, burst)
	errs := make([]error, burst)
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = src.FetchPresence(context.Background())
		}(i)
	}
	// Give the burst time to pile up on the in-flight call, then let the server answer.
	time.Sleep(120 * time.Millisecond)
	close(release)
	wg.Wait()

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("HTTP calls = %d for %d concurrent fetches, want 1 (single-flight)", got, burst)
	}
	for i := range results {
		if errs[i] != nil || !results[i].IsOnline("dev-a") {
			t.Fatalf("waiter %d got %+v, %v — every waiter must receive the shared result", i, results[i], errs[i])
		}
	}
}

// A caller that gives up must not take the shared fetch down with it. The leader's request context
// being cancelled is routine (the technician closed the tab); every other waiter still needs the
// answer, and the cooldown must not be poisoned with an error about the browser rather than about
// signaling.
func TestPresenceLeaderCancellationDoesNotKillTheSharedFetch(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		_, _ = w.Write([]byte(`{"devices":[{"device_id":"dev-a","last_seen_unix_ms":1}],"as_of_unix_ms":1}`))
	}))
	defer srv.Close()

	src := &SignalingPresenceSource{URL: srv.URL, Token: "tok"}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := src.FetchPresence(leaderCtx)
		leaderDone <- err
	}()
	// A second caller joins the in-flight fetch, then the leader walks away.
	followerDone := make(chan *Presence, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		p, err := src.FetchPresence(context.Background())
		if err != nil {
			followerDone <- nil
			return
		}
		followerDone <- p
	}()
	time.Sleep(100 * time.Millisecond)
	cancelLeader()

	select {
	case err := <-leaderDone:
		if err == nil {
			t.Fatal("the cancelled leader must stop waiting, not block on the shared fetch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled leader kept waiting on the shared fetch")
	}

	close(release)
	select {
	case p := <-followerDone:
		if p == nil || !p.IsOnline("dev-a") {
			t.Fatalf("the follower lost its answer when the leader cancelled: %+v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the follower never got a result — the leader's cancellation killed the shared fetch")
	}
	// The successful fetch was cached, not recorded as a failure.
	if p, err := src.FetchPresence(context.Background()); err != nil || !p.IsOnline("dev-a") {
		t.Fatalf("post-cancel cached read = %+v, %v — a cancelled leader poisoned the cache", p, err)
	}
}

// An empty visible fleet with a HEALTHY feed reports presence_known=true. "You own no machines" and
// "we could not reach signaling" are different facts; conflating them made an empty tenant look
// like an outage in the console.
func TestListMachinesReportsPresenceKnownForAnEmptyFleet(t *testing.T) {
	srv, _, presence := presenceTestServer(t)
	presence.SetOnline("someone-elses-device", time.Now())

	got := listMachines(t, srv)
	if len(got.Machines) != 0 {
		t.Fatalf("machines = %+v, want none", got.Machines)
	}
	if !got.PresenceKnown {
		t.Fatal("presence_known = false for an empty fleet with a healthy feed")
	}

	// …and it is still false when the feed really is down, so the flag keeps its meaning.
	presence.Err = ErrPresenceUnavailable
	if got := listMachines(t, srv); got.PresenceKnown {
		t.Fatal("presence_known = true for an empty fleet with an unavailable feed")
	}
}

// last_seen is a fact about the TENANT's fleet, not about who happened to browse. A group-scoped
// technician's page load must record sightings for machines outside their scope too — otherwise
// "offline since 14:32" depends on which technician last opened the console.
func TestListMachinesRecordsSightingsOutsideTheViewersGroupScope(t *testing.T) {
	machines := NewInMemoryMachineStore()
	presence := NewInMemoryPresenceSource()
	// A viewer scoped to g1 only.
	p := &Principal{
		UserID:   "u1",
		TenantID: "tenant-1",
		Grant:    NewGrant("u1", "tenant-1", NewMembership(RoleOwner, Groups("g1"))),
	}
	srv := NewServer(StubAuthenticator{Principal: p}, NoopBinder{})
	srv.Machines = machines
	srv.Presence = presence

	mine := &Machine{TenantID: "tenant-1", DeviceID: "dev-in-scope", GroupID: "g1", Name: "IN"}
	theirs := &Machine{TenantID: "tenant-1", DeviceID: "dev-out-of-scope", GroupID: "g2", Name: "OUT"}
	for _, m := range []*Machine{mine, theirs} {
		if err := machines.EnrollMachine(context.Background(), "tenant-1", m); err != nil {
			t.Fatalf("enroll %s: %v", m.DeviceID, err)
		}
	}
	seen := time.Now().Add(-10 * time.Second).UTC().Truncate(time.Millisecond)
	presence.SetOnline("dev-in-scope", seen)
	presence.SetOnline("dev-out-of-scope", seen)

	got := listMachines(t, srv)
	// The RESPONSE is still confined to the caller's group scope — that part must not regress.
	if len(got.Machines) != 1 || got.Machines[0].DeviceID != "dev-in-scope" {
		t.Fatalf("machines = %+v, want only the in-scope machine", got.Machines)
	}
	for _, dev := range []string{"dev-in-scope", "dev-out-of-scope"} {
		stored, err := machines.GetMachine(context.Background(), "tenant-1", dev)
		if err != nil {
			t.Fatalf("GetMachine(%s): %v", dev, err)
		}
		if stored.LastSeen == nil {
			t.Fatalf("%s got no last_seen — a group-scoped page load skipped the rest of the tenant", dev)
		}
	}
}

// A nil Presence answers "nobody is online" rather than panicking, so a caller that skipped the
// lookup needs no nil check at every use.
func TestNilPresenceIsSafe(t *testing.T) {
	var p *Presence
	if p.IsOnline("anything") {
		t.Fatal("nil presence reported a device online")
	}
	if _, ok := p.LastSeen("anything"); ok {
		t.Fatal("nil presence reported a last-seen")
	}
}

func bodyContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// last_seen only ever moves FORWARD. Snapshots are cached for a TTL, so two concurrent listings can
// carry different-aged ones; letting the older win would move "offline since" into the past for no
// reason a technician could explain. Pinned on the fake here and on the real UPDATE's
// `last_seen < $2` guard in TestPgMachinePresenceUnderRLS — they must not disagree.
func TestTouchLastSeenNeverMovesBackwards(t *testing.T) {
	store := NewInMemoryMachineStore()
	ctx := context.Background()
	m := &Machine{TenantID: "tenant-1", DeviceID: "dev-1", GroupID: "g1", Name: "WS-1"}
	if err := store.EnrollMachine(ctx, "tenant-1", m); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	newer := time.Now().UTC().Truncate(time.Millisecond)
	older := newer.Add(-time.Minute)

	if n, err := store.TouchLastSeen(ctx, "tenant-1", []string{"dev-1"}, newer); err != nil || n != 1 {
		t.Fatalf("first stamp = (%d, %v), want (1, nil)", n, err)
	}
	// An older snapshot must write nothing and report nothing written.
	if n, err := store.TouchLastSeen(ctx, "tenant-1", []string{"dev-1"}, older); err != nil || n != 0 {
		t.Fatalf("backwards stamp = (%d, %v), want (0, nil)", n, err)
	}
	got, err := store.GetMachine(ctx, "tenant-1", "dev-1")
	if err != nil {
		t.Fatalf("GetMachine: %v", err)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(newer) {
		t.Fatalf("last_seen = %v, want it to have stayed at %v", got.LastSeen, newer)
	}
	// Re-stamping the SAME instant is also a no-op, so repeated console polls inside one cache TTL
	// stop writing entirely.
	if n, err := store.TouchLastSeen(ctx, "tenant-1", []string{"dev-1"}, newer); err != nil || n != 0 {
		t.Fatalf("same-instant stamp = (%d, %v), want (0, nil)", n, err)
	}
	// A genuinely newer snapshot still advances it.
	if n, err := store.TouchLastSeen(ctx, "tenant-1", []string{"dev-1"}, newer.Add(time.Second)); err != nil || n != 1 {
		t.Fatalf("forward stamp = (%d, %v), want (1, nil)", n, err)
	}
}

// The HTTP presence client must decode grant_key_pinned tri-state from signaling's JSON (audit #9).
func TestSignalingPresenceSourceDecodesGrantKeyPinned(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"as_of_unix_ms":1,"devices":[` +
			`{"device_id":"a","last_seen_unix_ms":1,"grant_key_pinned":true},` +
			`{"device_id":"b","last_seen_unix_ms":1,"grant_key_pinned":false},` +
			`{"device_id":"c","last_seen_unix_ms":1}]}`))
	}))
	defer ts.Close()
	src := &SignalingPresenceSource{URL: ts.URL, Token: "x", CacheTTL: -1}
	p, err := src.FetchPresence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := p.GrantKeyPinned("a"); !ok || !v {
		t.Fatalf("a: %v %v", v, ok)
	}
	if v, ok := p.GrantKeyPinned("b"); !ok || v {
		t.Fatalf("b: %v %v", v, ok)
	}
	if _, ok := p.GrantKeyPinned("c"); ok {
		t.Fatal("c reported nothing; must be unknown")
	}
}

func TestListMachinesSurfacesSessionPolicyRequired(t *testing.T) {
	srv, machines, presence := presenceTestServer(t)
	seedMachine(t, machines, "dev-req", "REQ-01")
	seedMachine(t, machines, "dev-old", "OLD-01")
	presence.SetOnlineWithPolicyRequired("dev-req", time.Now().UTC(), true)
	presence.SetOnline("dev-old", time.Now().UTC())
	got := map[string]*bool{}
	for _, m := range listMachines(t, srv).Machines {
		got[m.DeviceID] = m.SessionPolicyRequired
	}
	if p := got["dev-req"]; p == nil || !*p {
		t.Fatalf("dev-req: %v", p)
	}
	if got["dev-old"] != nil {
		t.Fatal("a silent agent must stay unknown")
	}
}

func TestSignalingPresenceSourceDecodesSessionPolicyRequired(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"as_of_unix_ms":1,"devices":[` +
			`{"device_id":"a","last_seen_unix_ms":1,"session_policy_required":true},` +
			`{"device_id":"b","last_seen_unix_ms":1}]}`))
	}))
	defer ts.Close()
	p, err := (&SignalingPresenceSource{URL: ts.URL, Token: "x", CacheTTL: -1}).FetchPresence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := p.SessionPolicyRequired("a"); !ok || !v {
		t.Fatalf("a: %v %v", v, ok)
	}
	if _, ok := p.SessionPolicyRequired("b"); ok {
		t.Fatal("b reported nothing")
	}
}

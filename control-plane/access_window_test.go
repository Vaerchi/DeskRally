package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// docs/57: scheduled access windows. windowVectors is evaluated by Go here AND by the SQL function in
// access_window_pgstore_test.go, so the two predicates cannot drift.

type windowVector struct {
	name  string
	days  uint8
	start int
	end   int
	zone  string
	at    string // RFC 3339, UTC
	open  bool
}

const (
	sun = 1 << iota
	mon
	tue
	wed
	thu
	fri
	sat
	weekdays = mon | tue | wed | thu | fri
	allDays  = 127
)

var windowVectors = []windowVector{
	// Europe/London is GMT (UTC+0) in November.
	{"london 8-18 before", weekdays, 480, 1080, "Europe/London", "2026-11-02T07:59:59Z", false},
	{"london 8-18 start inclusive", weekdays, 480, 1080, "Europe/London", "2026-11-02T08:00:00Z", true},
	{"london 8-18 seconds truncate", weekdays, 480, 1080, "Europe/London", "2026-11-02T17:59:59Z", true},
	{"london 8-18 end exclusive", weekdays, 480, 1080, "Europe/London", "2026-11-02T18:00:00Z", false},
	{"london 8-18 saturday", weekdays, 480, 1080, "Europe/London", "2026-10-31T12:00:00Z", false},
	// Crossing midnight: Fri 22:00 to Sat 06:00. The day names the START day.
	{"overnight fri start", fri, 1320, 360, "Europe/London", "2026-11-06T22:00:00Z", true},
	{"overnight into sat", fri, 1320, 360, "Europe/London", "2026-11-07T05:59:00Z", true},
	{"overnight sat end", fri, 1320, 360, "Europe/London", "2026-11-07T06:00:00Z", false},
	{"overnight sat night not listed", fri, 1320, 360, "Europe/London", "2026-11-07T23:00:00Z", false},
	{"overnight fri early is thu's", fri, 1320, 360, "Europe/London", "2026-11-06T05:00:00Z", false},
	{"overnight sat->sun wraps the week", sat, 1320, 360, "UTC", "2026-11-08T03:00:00Z", true},
	{"overnight sun early is sat's", sun, 1320, 360, "UTC", "2026-11-08T03:00:00Z", false},
	// 24:00 end.
	{"sunday all day late", sun, 0, 1440, "UTC", "2026-11-08T23:59:59Z", true},
	{"sunday all day ends", sun, 0, 1440, "UTC", "2026-11-09T00:00:00Z", false},
	// The LOCAL weekday, not the UTC one: Auckland (NZDT, UTC+13) Monday 09:00 is Sunday 20:00 UTC.
	{"auckland monday from utc sunday", mon, 480, 600, "Pacific/Auckland", "2026-11-01T20:00:00Z", true},
	{"auckland sunday not listed", sun, 480, 600, "Pacific/Auckland", "2026-11-01T20:00:00Z", false},
	// West of UTC, the local weekday lags: Los Angeles (PST, UTC-8) Monday 20:00 is Tuesday 04:00 UTC.
	{"los angeles monday from utc tuesday", mon, 1140, 1260, "America/Los_Angeles", "2026-11-03T04:00:00Z", true},
	{"los angeles tuesday not yet", tue, 1140, 1260, "America/Los_Angeles", "2026-11-03T04:00:00Z", false},
	{"new york 9-17 edt open", mon, 540, 1020, "America/New_York", "2026-10-26T13:00:00Z", true},
	{"new york 9-17 edt before", mon, 540, 1020, "America/New_York", "2026-10-26T12:59:00Z", false},
	// London spring forward 2026-03-29: local 01:00-01:59 never happens (01:00 UTC = 02:00 BST).
	{"gap window never opens before", sun, 75, 105, "Europe/London", "2026-03-29T00:59:00Z", false},
	{"gap window never opens after", sun, 75, 105, "Europe/London", "2026-03-29T01:00:00Z", false},
	{"gap start opens at first real minute", sun, 90, 180, "Europe/London", "2026-03-29T01:00:00Z", true},
	// London fall back 2026-10-25: local 01:00-01:59 happens twice (BST 00:00-00:59 UTC, GMT 01:00-01:59 UTC).
	{"repeat first 01:20", sun, 0, 90, "Europe/London", "2026-10-25T00:20:00Z", true},
	{"repeat first 01:40", sun, 0, 90, "Europe/London", "2026-10-25T00:40:00Z", false},
	{"repeat second 01:20 reopens", sun, 0, 90, "Europe/London", "2026-10-25T01:20:00Z", true},
	{"repeat second 01:40", sun, 0, 90, "Europe/London", "2026-10-25T01:40:00Z", false},
	// An overnight window spanning the fall-back transition.
	{"overnight across fall back", sat, 1380, 120, "Europe/London", "2026-10-25T01:30:00Z", true},
	{"overnight across fall back ends", sat, 1380, 120, "Europe/London", "2026-10-25T02:00:00Z", false},
}

func TestAccessWindowVectors(t *testing.T) {
	for _, v := range windowVectors {
		w, err := NewAccessWindow(v.days, v.start, v.end, v.zone)
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		at, _ := time.Parse(time.RFC3339, v.at)
		if got := w.OpenAt(at); got != v.open {
			t.Errorf("%s: OpenAt(%s) = %v, want %v", v.name, v.at, got, v.open)
		}
	}
	if !(*AccessWindow)(nil).OpenAt(time.Now()) {
		t.Fatal("no window is always open")
	}
	// A zone the evaluator cannot load denies (fail closed), never UTC/Local.
	if (&AccessWindow{Days: allDays, Start: 0, End: 1440, Zone: "Mars/Olympus"}).OpenAt(time.Now()) {
		t.Fatal("an unknown zone must deny")
	}
}

func TestParseAccessWindow(t *testing.T) {
	w, err := ParseAccessWindow(json.RawMessage(`{"days":["fri","mon"],"start":"22:00","end":"06:00","time_zone":"Europe/London"}`))
	if err != nil || w.Days != mon|fri || w.Start != 1320 || w.End != 360 || w.Zone != "Europe/London" {
		t.Fatalf("parse = %+v %v", w, err)
	}
	b, _ := json.Marshal(w)
	if string(b) != `{"days":["mon","fri"],"start":"22:00","end":"06:00","time_zone":"Europe/London"}` {
		t.Fatalf("marshal = %s", b)
	}
	if w, err := ParseAccessWindow(json.RawMessage(`{"days":["sun"],"start":"00:00","end":"24:00","time_zone":"UTC"}`)); err != nil || w.End != 1440 {
		t.Fatalf("24:00 end = %+v %v", w, err)
	}
	if w, _ := ParseAccessWindow(json.RawMessage(`{"days":["sun"],"start":"00:00","end":"24:00","time_zone":"Etc/GMT+5"}`)); w == nil {
		t.Fatal("a real tz database name (Etc/GMT+5) is accepted")
	}
	for name, raw := range map[string]string{
		"no days":        `{"days":[],"start":"08:00","end":"18:00","time_zone":"UTC"}`,
		"bad day":        `{"days":["monday"],"start":"08:00","end":"18:00","time_zone":"UTC"}`,
		"duplicate day":  `{"days":["mon","mon"],"start":"08:00","end":"18:00","time_zone":"UTC"}`,
		"start 24:00":    `{"days":["mon"],"start":"24:00","end":"18:00","time_zone":"UTC"}`,
		"end 00:00":      `{"days":["mon"],"start":"08:00","end":"00:00","time_zone":"UTC"}`,
		"equal":          `{"days":["mon"],"start":"08:00","end":"08:00","time_zone":"UTC"}`,
		"bad clock":      `{"days":["mon"],"start":"8:00","end":"18:00","time_zone":"UTC"}`,
		"minute 60":      `{"days":["mon"],"start":"08:60","end":"18:00","time_zone":"UTC"}`,
		"24:30":          `{"days":["mon"],"start":"08:00","end":"24:30","time_zone":"UTC"}`,
		"Local":          `{"days":["mon"],"start":"08:00","end":"18:00","time_zone":"Local"}`,
		"empty zone":     `{"days":["mon"],"start":"08:00","end":"18:00","time_zone":""}`,
		"offset":         `{"days":["mon"],"start":"08:00","end":"18:00","time_zone":"+05"}`,
		"posix rule":     `{"days":["mon"],"start":"08:00","end":"18:00","time_zone":"EST5EDT,M3.2.0,M11.1.0"}`,
		"unknown zone":   `{"days":["mon"],"start":"08:00","end":"18:00","time_zone":"Mars/Olympus"}`,
		"path traversal": `{"days":["mon"],"start":"08:00","end":"18:00","time_zone":"../etc/passwd"}`,
		"extra field":    `{"days":["mon"],"start":"08:00","end":"18:00","time_zone":"UTC","x":1}`,
		"not an object":  `"mon 8-18"`,
	} {
		if _, err := ParseAccessWindow(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: accepted %s", name, raw)
		}
	}
}

// openWindow is open at any time; closedWindow is closed right now (only a weekday that is neither
// today nor yesterday in UTC, all day).
func openWindow() *AccessWindow {
	w, _ := NewAccessWindow(allDays, 0, 1440, "UTC")
	return w
}

func closedWindow() *AccessWindow {
	d := (int(time.Now().UTC().Weekday()) + 3) % 7
	w, _ := NewAccessWindow(1<<uint(d), 0, 1440, "UTC")
	return w
}

func TestInMemoryWindowGrantsOnlyWhenOpen(t *testing.T) {
	s := NewInMemoryUserStore()
	ctx := context.Background()
	if err := s.CreateUserAssignment(ctx, "t1", "u1", "a@x.test", "A", Assignment{Role: RoleTechnician, Window: openWindow()}); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.GrantFor(ctx, "t1", "u1"); !g.Allows(CapStartSession) {
		t.Fatal("an open window grants")
	}
	if err := s.SetUserAssignment(ctx, "t1", "u1", Assignment{Role: RoleTechnician, Window: closedWindow()}); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.GrantFor(ctx, "t1", "u1"); len(g.Members) != 0 {
		t.Fatal("a closed window grants nothing")
	}
	if stored, _ := s.StoredGrantFor(ctx, "t1", "u1"); len(stored.Members) != 1 || stored.Members[0].Window == nil {
		t.Fatal("the stored grant keeps the windowed row")
	}
	sum, err := s.AccessSummary(ctx, "t1", "u1")
	if err != nil || sum.AccessWindow == nil || sum.AccessWindowVaries || !sum.AccessOutsideWindow || sum.AccessExpired {
		t.Fatalf("summary = %+v %v", sum, err)
	}
}

// The fake's write contract matches pg's: a SUPPLIED unknown zone is refused before any change; a
// PRESERVED one is written as stored and keeps denying.
func TestInMemorySuppliedZoneIsChecked(t *testing.T) {
	s := NewInMemoryUserStore()
	ctx := context.Background()
	bad := &AccessWindow{Days: allDays, Start: 0, End: 1440, Zone: "Mars/Olympus"}
	if err := s.CreateUserAssignment(ctx, "t1", "u1", "a@x.test", "A", Assignment{Role: RoleTechnician, Window: bad, WindowSupplied: true}); err != ErrUnknownTimeZone {
		t.Fatalf("invite with an unknown supplied zone = %v, want ErrUnknownTimeZone", err)
	}
	if _, err := s.AccessSummary(ctx, "t1", "u1"); err != ErrNoUser {
		t.Fatal("the refused invite must not have created the user")
	}
	if err := s.CreateUserAssignment(ctx, "t1", "u1", "a@x.test", "A", Assignment{Role: RoleTechnician}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAssignment(ctx, "t1", "u1", Assignment{Role: RoleReadOnly, Window: bad, WindowSupplied: true}); err != ErrUnknownTimeZone {
		t.Fatalf("set with an unknown supplied zone = %v, want ErrUnknownTimeZone", err)
	}
	if g, _ := s.GrantFor(ctx, "t1", "u1"); !g.Allows(CapStartSession) {
		t.Fatal("the refused set must leave the technician grant unchanged")
	}
	if err := s.SetUserAssignment(ctx, "t1", "u1", Assignment{Role: RoleReadOnly, Window: bad}); err != nil {
		t.Fatalf("a PRESERVED unknown zone is written as stored: %v", err)
	}
	if g, _ := s.GrantFor(ctx, "t1", "u1"); len(g.Members) != 0 {
		t.Fatal("the preserved unknown zone keeps denying")
	}
}

func TestWindowAggregates(t *testing.T) {
	now := time.Now()
	open, closed := openWindow(), closedWindow()
	plain := NewMembership(RoleReadOnly, AllGroups())
	cases := []struct {
		name           string
		members        []Membership
		window, varies bool
		outside        bool
	}{
		{"none", nil, false, false, false},
		{"unrestricted", []Membership{plain}, false, false, false},
		{"one closed", []Membership{plain.WithWindow(closed)}, true, false, true},
		{"same window twice", []Membership{plain.WithWindow(closed), plain.WithWindow(closed)}, true, false, true},
		{"different windows, one open", []Membership{plain.WithWindow(closed), plain.WithWindow(open)}, false, true, false},
		{"windowed + unrestricted varies", []Membership{plain.WithWindow(closed), plain}, false, true, false},
		// docs/57 r2: an EXPIRED unrestricted row plus a live closed window: outside, window null, varies.
		{"expired unrestricted + live closed", []Membership{plain.WithExpiry(past()), plain.WithWindow(closed)}, false, true, true},
		{"all expired is not outside", []Membership{plain.WithWindow(closed).WithExpiry(past())}, true, false, false},
	}
	for _, c := range cases {
		g := NewGrant("u", "t", c.members...)
		w, v := g.AccessWindowSummary()
		if (w != nil) != c.window || v != c.varies || g.OutsideWindow(now) != c.outside {
			t.Errorf("%s: window=%v varies=%v outside=%v, want %v %v %v", c.name, w != nil, v, g.OutsideWindow(now), c.window, c.varies, c.outside)
		}
	}
	if NewGrant("u", "t", plain.WithWindow(open), plain.WithWindow(closed)).Homogeneous() {
		t.Fatal("rows differing only in window are heterogeneous")
	}
}

func TestInMemoryOwnerWithWindowIsNotPermanent(t *testing.T) {
	s := NewInMemoryUserStore()
	ctx := context.Background()
	if err := s.CreateUserAssignment(ctx, "t1", "o1", "o1@x.test", "O", Assignment{Role: RoleOwner}); err != nil {
		t.Fatal(err)
	}
	// The store backstop: an Owner row with a window does not count as the permanent Owner.
	if err := s.SetUserAssignment(ctx, "t1", "o1", Assignment{Role: RoleOwner, Window: openWindow()}); err != ErrLastOwner {
		t.Fatalf("windowing the last permanent Owner = %v, want ErrLastOwner", err)
	}
}

// --- handlers ---

type windowResp struct {
	code   int
	window json.RawMessage
	body   string
}

func setWindowAs(t *testing.T, f *authFixture, cookie, csrf *http.Cookie, tok, target string, body map[string]any) windowResp {
	t.Helper()
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/users/"+target+"/role", body, tok, cookie, csrf)
	var resp struct {
		AccessWindow json.RawMessage `json:"access_window"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return windowResp{code: rec.Code, window: resp.AccessWindow, body: rec.Body.String()}
}

var londonDays = map[string]any{"days": []string{"mon", "tue", "wed", "thu", "fri"}, "start": "08:00", "end": "18:00", "time_zone": "Europe/London"}

const londonDaysJSON = `{"days":["mon","tue","wed","thu","fri"],"start":"08:00","end":"18:00","time_zone":"Europe/London"}`

func TestAccessWindowSetPreserveClearAndValidate(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUser(t, "tenant-1", "tech", "tech@acme.test", uaPw, RoleTechnician)
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	set := func(body map[string]any) windowResp { return setWindowAs(t, f, cookie, csrf, tok, "tech", body) }

	if r := set(map[string]any{"role": "technician", "access_window": londonDays}); r.code != 200 || string(r.window) != londonDaysJSON {
		t.Fatalf("set window = %d %s (%s)", r.code, r.window, r.body)
	}
	if ev := f.lastAuditEvent(t, "user.role_set"); ev["access_window"] == nil {
		t.Fatalf("audit must carry the window: %v", ev)
	}
	// ABSENT → preserved across a role change.
	if r := set(map[string]any{"role": "readonly"}); r.code != 200 || string(r.window) != londonDaysJSON {
		t.Fatalf("absent window must be preserved: %d %s", r.code, r.window)
	}
	stored, _ := f.users.StoredGrantFor(context.Background(), "tenant-1", "tech")
	if stored.Members[0].Role != RoleReadOnly || stored.Members[0].Window == nil {
		t.Fatalf("stored after preserve: %+v", stored.Members)
	}
	// null → any time.
	if r := set(map[string]any{"role": "readonly", "access_window": nil}); r.code != 200 || string(r.window) != "null" {
		t.Fatalf("null must clear the window: %d %s", r.code, r.window)
	}
	for name, v := range map[string]any{
		"bad day":     map[string]any{"days": []string{"funday"}, "start": "08:00", "end": "18:00", "time_zone": "UTC"},
		"bad zone":    map[string]any{"days": []string{"mon"}, "start": "08:00", "end": "18:00", "time_zone": "Mars/Olympus"},
		"equal":       map[string]any{"days": []string{"mon"}, "start": "08:00", "end": "08:00", "time_zone": "UTC"},
		"a string":    "weekdays",
		"a number":    7,
		"extra field": map[string]any{"days": []string{"mon"}, "start": "08:00", "end": "18:00", "time_zone": "UTC", "holidays": true},
	} {
		if r := set(map[string]any{"role": "readonly", "access_window": v}); r.code != http.StatusBadRequest {
			t.Errorf("access_window %s = %d, want 400", name, r.code)
		}
	}
}

func TestOwnerAccessCannotHaveAWindow(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	f.addUserWithGrant(t, "tenant-1", "tech", "tech@acme.test", uaPw,
		NewGrant("tech", "tenant-1", NewMembership(RoleTechnician, AllGroups()).WithWindow(openWindow())))
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	set := func(body map[string]any) windowResp { return setWindowAs(t, f, cookie, csrf, tok, "tech", body) }
	if r := set(map[string]any{"role": "owner", "access_window": londonDays}); r.code != http.StatusBadRequest {
		t.Fatalf("owner with a supplied window = %d, want 400", r.code)
	}
	// A PRESERVED window blocks the promotion too, until it is explicitly cleared.
	if r := set(map[string]any{"role": "owner"}); r.code != http.StatusBadRequest {
		t.Fatalf("owner with a preserved window = %d, want 400", r.code)
	}
	if r := set(map[string]any{"role": "owner", "access_window": nil}); r.code != 200 {
		t.Fatalf("owner with the window cleared = %d %s, want 200", r.code, r.body)
	}
	// The invite path refuses it as well.
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/users", map[string]any{
		"email": "o2@acme.test", "role": "owner", "access_window": londonDays}, tok, cookie, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invite an owner with a window = %d, want 400", rec.Code)
	}
}

func TestInviteCarriesTheWindow(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	rec := doJSONWith(t, f.srv.Handler(), "POST", "/users", map[string]any{
		"email": "c@acme.test", "role": "technician", "access_window": londonDays}, tok, cookie, csrf)
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite with a window = %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		User struct {
			ID           string          `json:"id"`
			AccessWindow json.RawMessage `json:"access_window"`
		} `json:"user"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if string(out.User.AccessWindow) != londonDaysJSON {
		t.Fatalf("invite response window = %s", out.User.AccessWindow)
	}
	stored, _ := f.users.StoredGrantFor(context.Background(), "tenant-1", out.User.ID)
	if len(stored.Members) != 1 || stored.Members[0].Window == nil {
		t.Fatal("the invited user was created WITH the window (never unrestricted first)")
	}
	if ev := f.lastAuditEvent(t, "user.created"); ev["access_window"] == nil {
		t.Fatalf("user.created audit must carry the window: %v", ev)
	}
}

func TestWindowOnlyHeterogeneityNeedsAllThreeFields(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	// Same scope, same (no) expiry, different windows.
	f.addUserWithGrant(t, "tenant-1", "mix", "mix@acme.test", uaPw, NewGrant("mix", "tenant-1",
		NewMembership(RoleTechnician, AllGroups()).WithWindow(openWindow()),
		NewMembership(RoleTechnician, AllGroups()).WithWindow(closedWindow())))
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	set := func(body map[string]any) windowResp { return setWindowAs(t, f, cookie, csrf, tok, "mix", body) }
	all := map[string]any{"scoped_group_ids": []string{}, "expires_at": nil, "access_window": londonDays}
	for omit := range all {
		body := map[string]any{"role": "technician"}
		for k, v := range all {
			if k != omit {
				body[k] = v
			}
		}
		if r := set(body); r.code != http.StatusBadRequest {
			t.Errorf("omitting %s for a window-heterogeneous user = %d, want 400", omit, r.code)
		}
	}
	body := map[string]any{"role": "technician"}
	for k, v := range all {
		body[k] = v
	}
	if r := set(body); r.code != 200 {
		t.Fatalf("all three explicit = %d %s, want 200", r.code, r.body)
	}
}

func TestPreservedUnsupportedZoneSurvivesAnUnrelatedEdit(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUser(t, "tenant-1", "owner", "owner@acme.test", uaPw, RoleOwner)
	bad := &AccessWindow{Days: allDays, Start: 0, End: 1440, Zone: "Mars/Olympus"} // stored, no longer loadable
	f.addUserWithGrant(t, "tenant-1", "tech", "tech@acme.test", uaPw,
		NewGrant("tech", "tenant-1", NewMembership(RoleTechnician, AllGroups()).WithWindow(bad)))
	cookie, csrf, tok := loginFor(t, f, "owner@acme.test", uaPw)
	if r := setWindowAs(t, f, cookie, csrf, tok, "tech", map[string]any{"role": "readonly"}); r.code != 200 {
		t.Fatalf("an unrelated edit must not fail on a preserved zone: %d %s", r.code, r.body)
	}
	if g, _ := f.users.GrantFor(context.Background(), "tenant-1", "tech"); len(g.Members) != 0 {
		t.Fatal("the preserved unsupported zone keeps denying")
	}
}

func TestMeReportsOutsideWindow(t *testing.T) {
	f := newUserAdminFixture(t)
	f.addUserWithGrant(t, "tenant-1", "late", "late@acme.test", uaPw,
		NewGrant("late", "tenant-1", NewMembership(RoleTechnician, AllGroups()).WithWindow(closedWindow())))
	f.addUserWithGrant(t, "tenant-1", "mixed", "mixed@acme.test", uaPw, NewGrant("mixed", "tenant-1",
		NewMembership(RoleTechnician, AllGroups()).WithExpiry(past()),
		NewMembership(RoleTechnician, AllGroups()).WithWindow(closedWindow())))
	type meResp struct {
		AccessExpired       bool            `json:"access_expired"`
		AccessWindow        json.RawMessage `json:"access_window"`
		AccessWindowVaries  bool            `json:"access_window_varies"`
		AccessOutsideWindow bool            `json:"access_outside_window"`
	}
	me := func(email string) (int, meResp, string) {
		cookie, csrf, tok := loginFor(t, f, email, uaPw)
		rec := doJSONWith(t, f.srv.Handler(), "GET", "/me", nil, tok, cookie, csrf)
		var m meResp
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		if code := doJSONWith(t, f.srv.Handler(), "GET", "/users", nil, tok, cookie, csrf).Code; code != http.StatusForbidden {
			t.Errorf("%s outside their window listing users = %d, want 403", email, code)
		}
		return rec.Code, m, rec.Body.String()
	}
	if code, m, body := me("late@acme.test"); code != 200 || !m.AccessOutsideWindow || m.AccessExpired || string(m.AccessWindow) == "null" || m.AccessWindowVaries {
		t.Fatalf("/me outside one window = %d %s", code, body)
	}
	if code, m, body := me("mixed@acme.test"); code != 200 || !m.AccessOutsideWindow || m.AccessExpired || string(m.AccessWindow) != "null" || !m.AccessWindowVaries {
		t.Fatalf("/me expired-unrestricted + closed window = %d %s", code, body)
	}
}

// A live unattended session ends when its holder's window closes: the renewal re-resolves the grant.
func TestRenewIsRefusedOutsideTheWindow(t *testing.T) {
	f := newLeaseFixture(t)
	sess, csrfCookie, csrfTok := loginFor(t, f.authFixture, "tech@acme.test", leasePw)
	if err := f.users.SetUserAssignment(context.Background(), leaseTenant, leaseTechID,
		Assignment{Role: RoleTechnician, Window: openWindow()}); err != nil {
		t.Fatal(err)
	}
	if got := f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok); got.code != http.StatusOK {
		t.Fatalf("renewal inside the window: %d %s", got.code, got.body)
	}
	if err := f.users.SetUserAssignment(context.Background(), leaseTenant, leaseTechID,
		Assignment{Role: RoleTechnician, Window: closedWindow()}); err != nil {
		t.Fatal(err)
	}
	if got := f.renewWith(t, f.rec.ID, sess, csrfCookie, csrfTok); got.code != http.StatusForbidden {
		t.Fatalf("renewal outside the window = %d, want 403: %s", got.code, got.body)
	}
}

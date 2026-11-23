package controlplane

// GET /directives?state=active and the additive GET /me fields (user_id, capabilities) - the two routes the
// console uses to decide what to OFFER (docs/65 sec. 6). Both backends run the same scenarios.

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// scopedOwner creates an Owner whose membership is limited to the given groups, in either backend.
func (h *dirHarness) scopedOwner(name string, groups ...string) string {
	h.t.Helper()
	if !h.pg {
		id := newUUID()
		h.users.(*InMemoryUserStore).AddUser(&AuthUser{ID: id, TenantID: h.tenant, Email: name + "@test.example"},
			NewGrant(id, h.tenant, NewMembership(RoleOwner, Groups(groups...))))
		return id
	}
	var id string
	if err := h.su.QueryRow(context.Background(), "SELECT gen_random_uuid()::text").Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	h.rawSQL(`INSERT INTO app_user (id, tenant_id, email) VALUES ($1, $2, $3)`, id, h.tenant, name+"@acme.test")
	h.rawSQL(`INSERT INTO membership (tenant_id, user_id, role_id, scoped_group_ids)
		VALUES ($1, $2, (SELECT id FROM role WHERE key='owner' AND tenant_id IS NULL), $3::uuid[])`, h.tenant, id, groups)
	return id
}

func (h *dirHarness) activeList(user, query string) (int, []string, map[string]any) {
	h.t.Helper()
	code, out := h.do(user, "GET", "/directives"+query, "")
	var ids []string
	if rows, ok := out["directives"].([]any); ok {
		for _, r := range rows {
			ids = append(ids, str(r.(map[string]any), "id"))
		}
	}
	return code, ids, out
}

func sortedIDs(s []string) []string { c := append([]string(nil), s...); sort.Strings(c); return c }

func sameIDs(a, b []string) bool {
	a, b = sortedIDs(a), sortedIDs(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestListActiveDirectivesIsScopedToTheMachinesCurrentGroup(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		m2 := h.addMachineFn(h.otherGroup, MachineStatusRetired)
		m3 := h.addMachineFn(h.group, MachineStatusRetired)
		d1 := h.mustRequestUninstall(h.owner, h.m) // group
		d2 := h.mustRequestUninstall(h.owner, m2)  // otherGroup
		d3 := h.mustRequestUninstall(h.owner, m3)  // group, then cancelled: not active
		if code, out := h.do(h.owner, "POST", "/directives/"+d3+"/cancel", ""); code != http.StatusOK {
			t.Fatalf("cancel = %d %v", code, out)
		}
		a := h.scopedOwner("scoped-a", h.group)
		b := h.scopedOwner("scoped-b", h.otherGroup)

		// The asymmetric case: each scoped owner sees ONLY the directive on a machine in their own group.
		for _, c := range []struct {
			who  string
			want []string
		}{
			{h.owner, []string{d1, d2}},
			{h.owner2, []string{d1, d2}},
			{a, []string{d1}},
			{b, []string{d2}},
		} {
			code, ids, out := h.activeList(c.who, "?state=active")
			if code != http.StatusOK || !sameIDs(ids, c.want) {
				t.Fatalf("list as %s = %d %v (%v), want %v", c.who, code, ids, out, c.want)
			}
		}

		// Row content: the machine's display facts ride along; no artifact or nonce.
		_, _, out := h.activeList(h.owner, "?state=active")
		first := out["directives"].([]any)[0].(map[string]any)
		if str(first, "machine_name") == "" || str(first, "machine_status") != MachineStatusRetired || str(first, "state") != "requested" {
			t.Fatalf("row lacks machine facts: %v", first)
		}
		if _, leak := first["artifact"]; leak {
			t.Fatalf("a list row leaks the artifact: %v", first)
		}

		// The machine's CURRENT group decides, not the group the directive was recorded under: move m2 into
		// group; scoped-a now sees it, scoped-b no longer does.
		h.bypassGuard(func() {
			if err := h.machines.SetMachineGroup(context.Background(), h.tenant, m2.ID, h.group); err != nil {
				t.Fatal(err)
			}
		})
		if _, ids, _ := h.activeList(a, "?state=active"); !sameIDs(ids, []string{d1, d2}) {
			t.Fatalf("scoped-a after the machine moved into their group = %v, want both", ids)
		}
		if _, ids, _ := h.activeList(b, "?state=active"); len(ids) != 0 {
			t.Fatalf("scoped-b after the machine moved out of their group = %v, want none", ids)
		}

		// Callers without remove_agent are refused; another tenant sees nothing of this one.
		for _, who := range []string{h.admin, h.tech, h.ro} {
			if code, _, _ := h.activeList(who, "?state=active"); code != http.StatusForbidden {
				t.Fatalf("list without remove_agent (%s) = %d, want 403", who, code)
			}
		}
		if code, ids, _ := h.activeList(h.erin, "?state=active"); code != http.StatusOK || len(ids) != 0 {
			t.Fatalf("other tenant list = %d %v, want 200 and empty", code, ids)
		}
	})
}

func TestListActiveDirectivesStatesAndParameters(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		id := h.mustRequestUninstall(h.owner, h.m)
		for _, q := range []string{"", "?state=all", "?state=complete", "?state=active&limit=0", "?state=active&limit=201", "?state=active&limit=x", "?state=active&before=yesterday&before_id=00000000-0000-0000-0000-000000000001", "?state=active&before=2026-01-01T00:00:00Z", "?state=active&before_id=00000000-0000-0000-0000-000000000001", "?state=active&before=2026-01-01T00:00:00Z&before_id=nope"} {
			if code, _, out := h.activeList(h.owner, q); code != http.StatusBadRequest {
				t.Fatalf("GET /directives%s = %d %v, want 400", q, code, out)
			}
		}
		// Postgres: a really issued directive is still listed (the other states need columns only the agent writes).
		if h.pg {
			h.issueNow(id)
			if _, ids, _ := h.activeList(h.owner, "?state=active"); len(ids) != 1 || ids[0] != id {
				t.Fatalf("issued directive list = %v", ids)
			}
			return
		}
		// Memory: every active state is listed; every finished state is not.
		for _, c := range []struct {
			state  DirectiveState
			listed bool
		}{
			{DirectiveRequested, true}, {DirectiveIssued, true}, {DirectiveAccepted, true}, {DirectiveExecuting, true},
			{DirectiveRebootPending, true}, {DirectiveRemovalUnconfirmed, true},
			{DirectiveComplete, false}, {DirectiveFailed, false}, {DirectiveCancelled, false}, {DirectiveExpired, false},
			{DirectiveForgotten, false},
		} {
			if got := h.setStateForList(t, id, c.state); got != c.listed {
				t.Fatalf("state %s listed = %v, want %v", c.state, got, c.listed)
			}
		}
	})
}

// setStateForList forces the row into a state (a seam with no HTTP route) and reports whether the owner's
// active list shows it.
func (h *dirHarness) setStateForList(t *testing.T, id string, st DirectiveState) bool {
	t.Helper()
	if true {
		d := h.dirs.(*InMemoryDirectiveStore)
		d.mu.Lock()
		d.get(h.tenant, id).State = st
		d.mu.Unlock()
	}
	_, ids, _ := h.activeList(h.owner, "?state=active")
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestListActiveDirectivesPaginates(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		var want []string
		want = append(want, h.mustRequestUninstall(h.owner, h.m))
		for i := 0; i < 2; i++ {
			time.Sleep(5 * time.Millisecond) // distinct requested_at
			want = append(want, h.mustRequestUninstall(h.owner, h.addMachineFn(h.group, MachineStatusRetired)))
		}
		var got []string
		cursor, cursorID := "", ""
		for page := 0; page < 5; page++ {
			q := "?state=active&limit=1"
			if cursor != "" {
				q += "&before=" + url.QueryEscape(cursor) + "&before_id=" + cursorID
			}
			code, ids, out := h.activeList(h.owner, q)
			if code != http.StatusOK || len(ids) > 1 {
				t.Fatalf("page %d = %d %v", page, code, out)
			}
			got = append(got, ids...)
			next, _ := out["next_before"].(string)
			if len(ids) == 0 || next == "" {
				break
			}
			cursor = next
			cursorID, _ = out["next_before_id"].(string)
		}
		if !sameIDs(got, want) || len(got) != 3 {
			t.Fatalf("paged ids = %v, want %v", got, want)
		}
	})
}

func TestMeReportsTheUserAndTruthfulCapabilities(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		scoped := h.scopedOwner("scoped-me", h.group)
		ctx := context.Background()
		for _, who := range []string{h.owner, h.admin, h.tech, h.ro, scoped} {
			code, out := h.do(who, "GET", "/me", "")
			if code != http.StatusOK {
				t.Fatalf("GET /me as %s = %d %v", who, code, out)
			}
			if str(out, "user_id") != who || str(out, "email") == "" {
				t.Fatalf("me = %v, want user_id %s and the existing email field", out, who)
			}
			if _, ok := out["access_expired"]; !ok {
				t.Fatalf("an existing /me field vanished: %v", out)
			}
			grant, err := h.users.GrantFor(ctx, h.tenant, who)
			if err != nil {
				t.Fatal(err)
			}
			listed := map[string]map[string]any{}
			for _, e := range out["capabilities"].([]any) {
				m := e.(map[string]any)
				listed[str(m, "capability")] = m
			}
			// Truthful against the server's own checks, for every capability and both groups.
			for _, c := range AllCapabilities {
				e, has := listed[string(c)]
				if has != grant.Allows(c) {
					t.Fatalf("%s: capability %s listed=%v, grant allows=%v", who, c, has, grant.Allows(c))
				}
				if !has {
					continue
				}
				covers := func(group string) bool {
					if all, _ := e["all_groups"].(bool); all {
						return true
					}
					for _, g := range e["group_ids"].([]any) {
						if g.(string) == group {
							return true
						}
					}
					return false
				}
				for _, g := range []string{h.group, h.otherGroup} {
					if covers(g) != grant.AllowsInGroup(c, g) {
						t.Fatalf("%s: %s covers group %s = %v, server AllowsInGroup = %v", who, c, g, covers(g), grant.AllowsInGroup(c, g))
					}
				}
			}
		}
		// And the headline: only the owner roles hold remove_agent; the scoped owner holds it for its group only.
		_, out := h.do(scoped, "GET", "/me", "")
		var ra map[string]any
		for _, e := range out["capabilities"].([]any) {
			if str(e.(map[string]any), "capability") == string(CapRemoveAgent) {
				ra = e.(map[string]any)
			}
		}
		if ra == nil || ra["all_groups"] != false || len(ra["group_ids"].([]any)) != 1 || ra["group_ids"].([]any)[0] != h.group {
			t.Fatalf("scoped owner remove_agent entry = %v", ra)
		}
		_, out = h.do(h.admin, "GET", "/me", "")
		for _, e := range out["capabilities"].([]any) {
			if str(e.(map[string]any), "capability") == string(CapRemoveAgent) {
				t.Fatalf("an Admin is told it holds remove_agent: %v", e)
			}
		}
	})
}

// TestActiveListSQLMatchesActiveStates pins the pg query's state list to DirectiveState.active().
func TestActiveListSQLMatchesActiveStates(t *testing.T) {
	all := []DirectiveState{DirectiveRequested, DirectiveIssued, DirectiveAccepted, DirectiveExecuting, DirectiveRebootPending,
		DirectiveComplete, DirectiveFailed, DirectiveRemovalUnconfirmed, DirectiveCancelled, DirectiveExpired, DirectiveForgotten}
	for _, st := range all {
		if inQuery := strings.Contains(listActiveDirectives, "'"+string(st)+"'"); inQuery != st.active() {
			t.Fatalf("state %s: SQL active list says %v, DirectiveState.active() says %v", st, inQuery, st.active())
		}
	}
}

// TestForgetQuerySQLMatchesActiveStates pins the forget query's state list (the directives a forget must close)
// to DirectiveState.active() as well: a state added to one list and not the other would leave an active
// directive on a tombstoned machine (or close one that was already over).
func TestForgetQuerySQLMatchesActiveStates(t *testing.T) {
	all := []DirectiveState{DirectiveRequested, DirectiveIssued, DirectiveAccepted, DirectiveExecuting, DirectiveRebootPending,
		DirectiveComplete, DirectiveFailed, DirectiveRemovalUnconfirmed, DirectiveCancelled, DirectiveExpired, DirectiveForgotten}
	for _, st := range all {
		if inQuery := strings.Contains(forgetActiveDirectivesQuery, "'"+string(st)+"'"); inQuery != st.active() {
			t.Fatalf("state %s: forget query says %v, DirectiveState.active() says %v", st, inQuery, st.active())
		}
	}
}

// TestListActiveDirectivesKeysetPagesKeepRowsSharingATimestamp: several active directives share ONE
// requested_at across every page boundary; the (requested_at, id) cursor must return each exactly once, in
// requested_at DESC, id ASC order, identically in both backends and for every page size.
func TestListActiveDirectivesKeysetPagesKeepRowsSharingATimestamp(t *testing.T) {
	forEachDirBackend(t, func(t *testing.T, h *dirHarness) {
		var ids []string
		for i := 0; i < 5; i++ {
			ids = append(ids, h.mustRequestUninstall(h.owner, h.addMachineFn(h.group, MachineStatusRetired)))
		}
		older := h.mustRequestUninstall(h.owner, h.addMachineFn(h.group, MachineStatusRetired))
		shared := time.Date(2026, 10, 31, 12, 0, 0, 123456000, time.UTC) // microsecond precision
		earlier := shared.Add(-time.Hour)
		if h.pg {
			for _, id := range ids {
				h.rawSQL(`UPDATE agent_directive SET requested_at = $2 WHERE id = $1`, id, shared)
			}
			h.rawSQL(`UPDATE agent_directive SET requested_at = $2 WHERE id = $1`, older, earlier)
		} else {
			d := h.dirs.(*InMemoryDirectiveStore)
			d.mu.Lock()
			for _, id := range ids {
				d.get(h.tenant, id).RequestedAt = shared
			}
			d.get(h.tenant, older).RequestedAt = earlier
			d.mu.Unlock()
		}
		sortedShared := sortedIDs(ids)
		want := append(append([]string(nil), sortedShared...), older)
		for _, limit := range []int{1, 2, 3, 4} {
			var got []string
			cursor, cursorID := "", ""
			for page := 0; page < 20; page++ {
				q := "?state=active&limit=" + strconv.Itoa(limit)
				if cursor != "" {
					q += "&before=" + url.QueryEscape(cursor) + "&before_id=" + cursorID
				}
				code, pageIDs, out := h.activeList(h.owner, q)
				if code != http.StatusOK {
					t.Fatalf("limit %d page %d = %d %v", limit, page, code, out)
				}
				got = append(got, pageIDs...)
				next, _ := out["next_before"].(string)
				if len(pageIDs) == 0 || next == "" {
					break
				}
				cursor = next
				cursorID, _ = out["next_before_id"].(string)
			}
			if len(got) != len(want) {
				t.Fatalf("limit %d: paged %d rows %v, want %d %v", limit, len(got), got, len(want), want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("limit %d: paged order %v, want %v", limit, got, want)
				}
			}
		}
	})
}

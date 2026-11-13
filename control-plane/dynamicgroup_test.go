package controlplane

import (
	"context"
	"errors"
	"testing"
)

func TestInMemoryDynamicGroupStore(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryDynamicGroupStore()

	// Empty tenant → empty list.
	if got, err := s.ListDynamicGroups(ctx, "t1"); err != nil || len(got) != 0 {
		t.Fatalf("empty list = %v, %v; want [], nil", got, err)
	}

	// Create assigns a fresh id and rejects a duplicate NAME (case-insensitive).
	g1 := &DynamicGroup{Name: "HQ", PropertyKey: "site", PropertyValue: "HQ"}
	if err := s.CreateDynamicGroup(ctx, "t1", g1); err != nil || g1.ID == "" {
		t.Fatalf("create g1 = %v, id=%q; want ok with an id", err, g1.ID)
	}
	g2 := &DynamicGroup{Name: "Any-site", PropertyKey: "site", PropertyValue: ""}
	if err := s.CreateDynamicGroup(ctx, "t1", g2); err != nil {
		t.Fatalf("create g2: %v", err)
	}
	if err := s.CreateDynamicGroup(ctx, "t1", &DynamicGroup{Name: "hq", PropertyKey: "x"}); !errors.Is(err, ErrDynamicGroupNameTaken) {
		t.Fatalf("duplicate name = %v, want ErrDynamicGroupNameTaken", err)
	}

	// List is ordered by name (Any-site before HQ).
	got, _ := s.ListDynamicGroups(ctx, "t1")
	if len(got) != 2 || got[0].Name != "Any-site" || got[1].Name != "HQ" {
		t.Fatalf("list = %+v, want [Any-site, HQ] (name-sorted)", got)
	}

	// Get by id round-trips the predicate; an unknown id is not-found.
	if g, err := s.GetDynamicGroup(ctx, "t1", g1.ID); err != nil || g.PropertyKey != "site" || g.PropertyValue != "HQ" {
		t.Fatalf("get g1 = %+v, %v", g, err)
	}
	if _, err := s.GetDynamicGroup(ctx, "t1", "nope"); !errors.Is(err, ErrDynamicGroupNotFound) {
		t.Fatalf("get unknown = %v, want ErrDynamicGroupNotFound", err)
	}

	// Tenant isolation: t2 sees nothing t1 created.
	if got, _ := s.ListDynamicGroups(ctx, "t2"); len(got) != 0 {
		t.Fatalf("t2 list = %v, want [] (isolated)", got)
	}

	// Delete removes it; a second delete is not-found.
	if err := s.DeleteDynamicGroup(ctx, "t1", g1.ID); err != nil {
		t.Fatalf("delete g1: %v", err)
	}
	if got, _ := s.ListDynamicGroups(ctx, "t1"); len(got) != 1 || got[0].Name != "Any-site" {
		t.Fatalf("after delete = %+v, want [Any-site]", got)
	}
	if err := s.DeleteDynamicGroup(ctx, "t1", g1.ID); !errors.Is(err, ErrDynamicGroupNotFound) {
		t.Fatalf("re-delete = %v, want ErrDynamicGroupNotFound", err)
	}
}

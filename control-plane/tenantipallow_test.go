package controlplane

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeCIDR(t *testing.T) {
	ok := []struct{ in, want string }{
		{"10.0.0.5", "10.0.0.5/32"},        // bare v4 → /32
		{"10.0.0.0/8", "10.0.0.0/8"},       // network stays
		{"10.0.0.5/8", "10.0.0.0/8"},       // masked to the base address (canonical)
		{"192.168.1.7/24", "192.168.1.0/24"},
		{"2001:db8::1", "2001:db8::1/128"}, // bare v6 → /128
		{"2001:db8::/32", "2001:db8::/32"},
		{"  10.0.0.1  ", "10.0.0.1/32"},    // trimmed
	}
	for _, c := range ok {
		got, err := normalizeCIDR(c.in)
		if err != nil || got != c.want {
			t.Fatalf("normalizeCIDR(%q) = %q, %v; want %q, nil", c.in, got, err, c.want)
		}
	}
	// A malformed entry is a hard error — never silently accepted (a typo must not enter an ACL).
	for _, bad := range []string{"", "   ", "not-an-ip", "10.0.0.0/33", "10.0.0.0/999", "banana/24"} {
		if got, err := normalizeCIDR(bad); err == nil {
			t.Fatalf("normalizeCIDR(%q) = %q, nil; want an error", bad, got)
		}
	}
}

func TestInMemoryTenantIPAllowlistStore(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryTenantIPAllowlistStore()

	// Empty tenant → empty list (open), never an error.
	if got, err := s.ListCIDRs(ctx, "t1"); err != nil || len(got) != 0 {
		t.Fatalf("empty ListCIDRs = %v, %v; want [], nil", got, err)
	}

	// Add is idempotent and List is sorted.
	for _, c := range []string{"10.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"} {
		if err := s.AddCIDR(ctx, "t1", c); err != nil {
			t.Fatalf("AddCIDR(%q): %v", c, err)
		}
	}
	got, _ := s.ListCIDRs(ctx, "t1")
	if want := []string{"10.0.0.0/8", "192.168.0.0/16"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ListCIDRs = %v, want %v (deduped + sorted)", got, want)
	}

	// Tenant isolation: t2 sees nothing t1 added.
	if got, _ := s.ListCIDRs(ctx, "t2"); len(got) != 0 {
		t.Fatalf("t2 ListCIDRs = %v, want [] (isolated from t1)", got)
	}

	// Remove present → gone; remove absent → sentinel (the handler maps it to 404).
	if err := s.RemoveCIDR(ctx, "t1", "10.0.0.0/8"); err != nil {
		t.Fatalf("RemoveCIDR present: %v", err)
	}
	if got, _ := s.ListCIDRs(ctx, "t1"); !reflect.DeepEqual(got, []string{"192.168.0.0/16"}) {
		t.Fatalf("after remove = %v, want [192.168.0.0/16]", got)
	}
	if err := s.RemoveCIDR(ctx, "t1", "10.0.0.0/8"); !errors.Is(err, ErrTenantIPAllowlistEntryNotFound) {
		t.Fatalf("RemoveCIDR absent = %v, want ErrTenantIPAllowlistEntryNotFound", err)
	}
}

// TestTenantIPAllowlistGuardedStore proves the anti-lockout is enforced INSIDE the guarded mutations
// (the atomic read-check-write), not by the handler: a mutation whose RESULTING list fails the `safe`
// predicate makes NO change and returns ErrWouldLockOut. Models "the caller is covered only by keep".
func TestTenantIPAllowlistGuardedStore(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryTenantIPAllowlistStore()
	const keep = "192.0.2.0/24"
	// safe: an empty list is open (safe); otherwise the caller is covered only when `keep` is present.
	safe := func(resulting []string) bool { return len(resulting) == 0 || contains(resulting, keep) }

	// First add from empty: adding a NON-covering CIDR would strand the caller → refused, nothing written.
	if err := s.AddCIDRGuarded(ctx, "t1", "10.0.0.0/8", safe); !errors.Is(err, ErrWouldLockOut) {
		t.Fatalf("guarded add of a non-covering first entry = %v, want ErrWouldLockOut", err)
	}
	if got, _ := s.ListCIDRs(ctx, "t1"); len(got) != 0 {
		t.Fatalf("rejected add must not have written: %v", got)
	}
	// Adding the covering entry is allowed; then a broad entry is allowed (keep still covers).
	if err := s.AddCIDRGuarded(ctx, "t1", keep, safe); err != nil {
		t.Fatalf("guarded add of the covering entry: %v", err)
	}
	if err := s.AddCIDRGuarded(ctx, "t1", "10.0.0.0/8", safe); err != nil {
		t.Fatalf("guarded add while keep present: %v", err)
	}
	// Removing the covering entry (leaving only 10.0.0.0/8) would strand the caller → refused, keep stays.
	if err := s.RemoveCIDRGuarded(ctx, "t1", keep, safe); !errors.Is(err, ErrWouldLockOut) {
		t.Fatalf("guarded remove of the covering entry = %v, want ErrWouldLockOut", err)
	}
	if got, _ := s.ListCIDRs(ctx, "t1"); !contains(got, keep) {
		t.Fatalf("rejected remove must not have written: %v", got)
	}
	// Removing the non-covering entry (leaving keep) is allowed; removing keep last (→ empty/open) is allowed.
	if err := s.RemoveCIDRGuarded(ctx, "t1", "10.0.0.0/8", safe); err != nil {
		t.Fatalf("guarded remove of the non-covering entry: %v", err)
	}
	if err := s.RemoveCIDRGuarded(ctx, "t1", keep, safe); err != nil {
		t.Fatalf("guarded remove down to empty (open) must be allowed: %v", err)
	}
	// Removing an absent entry is not-found (no lockout risk).
	if err := s.RemoveCIDRGuarded(ctx, "t1", keep, safe); !errors.Is(err, ErrTenantIPAllowlistEntryNotFound) {
		t.Fatalf("guarded remove of an absent entry = %v, want ErrTenantIPAllowlistEntryNotFound", err)
	}
}

package controlplane

import (
	"strings"
	"testing"
)

func findingCodes(fs []HostFinding) string {
	var c []string
	for _, f := range fs {
		c = append(c, f.Code)
	}
	return strings.Join(c, ",")
}

func TestLabelSkeletonFoldsLookalikes(t *testing.T) {
	for _, pair := range [][2]string{
		{"micr0soft", "microsoft"}, {"rnicrosoft", "microsoft"}, {"micro-soft", "microsoft"},
		{"g00gle", "google"}, {"vvindows", "windows"}, {"paypa1", "paypal"}, {"Paypal", "paypal"},
	} {
		if LabelSkeleton(pair[0]) != LabelSkeleton(pair[1]) {
			t.Errorf("skeleton(%q)=%q != skeleton(%q)=%q", pair[0], LabelSkeleton(pair[0]), pair[1], LabelSkeleton(pair[1]))
		}
	}
	if LabelSkeleton("acme") == LabelSkeleton("acne") {
		t.Error("distinct names collapsed")
	}
}

func TestCheckHostLabelRefusalsAndWarnings(t *testing.T) {
	ctx := HostLabelContext{ReservedLabels: []string{"main", "loam"}, ExistingLabels: []string{"acme", "rnyco"}}

	for _, bad := range []string{"", "ab", "www", "api", "Main", "has space", "-lead", "trail-", "main", "loam", "a.b", strings.Repeat("a", 64)} {
		if ref, _ := CheckHostLabel(bad, ctx); len(ref) == 0 {
			t.Errorf("label %q must be refused", bad)
		}
	}
	if ref, w := CheckHostLabel("widgetworks", ctx); len(ref) != 0 || len(w) != 0 {
		t.Errorf("a clean label produced findings: %v %v", ref, w)
	}
	// Denylisted brand and a lookalike of one: warnings (acknowledgeable), not refusals.
	for _, label := range []string{"microsoft", "micr0soft", "rnicrosoft", "microsoft-support", "my-paypal-help"} {
		ref, w := CheckHostLabel(label, ctx)
		if len(ref) != 0 {
			t.Errorf("%q: a brand collision must be a warning, not a refusal: %v", label, ref)
		}
		if !strings.Contains(findingCodes(w), "brand_denylist") {
			t.Errorf("%q: no brand_denylist warning: %v", label, w)
		}
	}
	// IDN / double hyphen.
	if _, w := CheckHostLabel("xn--acme-abc", ctx); !strings.Contains(findingCodes(w), "idn_label") {
		t.Errorf("xn-- label: %v", w)
	}
	// Skeleton collision with another assignment's label.
	if _, w := CheckHostLabel("acrne", HostLabelContext{ExistingLabels: []string{"acme"}}); !strings.Contains(findingCodes(w), "skeleton_collision") {
		t.Errorf("acrne vs acme: %v", w)
	}
	if _, w := CheckHostLabel("rnyco", HostLabelContext{ExistingLabels: []string{"myco"}}); !strings.Contains(findingCodes(w), "skeleton_collision") {
		t.Errorf("rnyco vs myco: %v", w)
	}
	// A label never collides with ITSELF (an identical label is the uniqueness constraint's business).
	if _, w := CheckHostLabel("acme", HostLabelContext{ExistingLabels: []string{"acme"}}); len(w) != 0 {
		t.Errorf("self collision: %v", w)
	}
	// A lookalike of a reserved name is flagged.
	if _, w := CheckHostLabel("upd4te", HostLabelContext{}); len(w) != 0 {
		// 4 is not in the doc's fold table: documented limitation, not a finding
		t.Logf("note: %v", w)
	}
	if _, w := CheckHostLabel("rnail", HostLabelContext{}); !strings.Contains(findingCodes(w), "reserved_lookalike") {
		t.Errorf("rnail vs mail: %v", w)
	}
}

func TestBrandDenylistFileIsWellFormed(t *testing.T) {
	list := brandDenylist()
	if len(list) < 20 {
		t.Fatalf("denylist suspiciously small: %d", len(list))
	}
	seen := map[string]bool{}
	for _, e := range list {
		if e != strings.ToLower(e) || strings.ContainsAny(e, " \t.") {
			t.Errorf("entry %q must be one lowercase token", e)
		}
		if seen[e] {
			t.Errorf("duplicate entry %q", e)
		}
		seen[e] = true
	}
}

package controlplane

import (
	"strings"
	"testing"
)

func TestBrandSkeletonFoldsLookalikes(t *testing.T) {
	same := [][2]string{
		{"Microsoft", "M1cr0soft"},
		{"Microsoft", "Micro-soft"},
		{"Microsoft", "Rnicrosoft"},
		{"Microsoft", "MICROSOFT"},
		{"PayPal", "PaypaI"},                        // capital i for l
		{"Apple", "Appl" + U(0x435)},                // Cyrillic e
		{"Acme", U(0x410, 0x441, 0x43c, 0x435)},     // all Cyrillic look-alikes
		{"Acme", U(0xff21, 0xff43, 0xff4d, 0xff45)}, // fullwidth
	}
	for _, p := range same {
		if BrandSkeleton(p[0]) != BrandSkeleton(p[1]) {
			t.Errorf("%q and %q should collide: %q vs %q", p[0], p[1], BrandSkeleton(p[0]), BrandSkeleton(p[1]))
		}
	}
	if BrandSkeleton("Acme") == BrandSkeleton("Acne") {
		t.Errorf("distinct names collide")
	}
}

func TestBrandFindings(t *testing.T) {
	ctx := BrandReviewContext{
		OtherBrandNames: []string{"Northwind Traders"},
		OtherHostLabels: []string{"contoso"},
	}
	if got := findingCodes(ReviewBrandFindings("Acme Support", ctx)); got != "" {
		t.Errorf("clean name has findings: %s", got)
	}
	cases := []struct{ name, in, want string }{
		{"brand collision", "N0rthwind Traders", "skeleton_collision_brand"},
		{"hostname collision", "C0ntoso", "skeleton_collision_hostname"},
		{"denylist exact", "Micr0soft", "brand_denylist"},
		{"denylist contains", "Microsoft Helpdesk Pro", "brand_denylist"},
		{"mixed word", "Pay" + U(0x440) + "al Help", "script_mixed_name,script_mixed_word"},
		{"cyrillic word beside latin word", U(0x41f, 0x440, 0x438, 0x432, 0x435, 0x442) + " Ltd", "script_mixed_name"},
		{"cjk with latin allowed", "Acme " + U(0x79d1, 0x6280), ""},
		{"hira kata han latin allowed", "Acme " + U(0x30c6, 0x30b9, 0x30c8, 0x3067, 0x3059, 0x79d1), ""},
		{"greek plus latin", "Alpha " + U(0x3b2, 0x3b7, 0x3c4, 0x3b1), "script_mixed_name"},
	}
	for _, c := range cases {
		got := findingCodes(ReviewBrandFindings(c.in, ctx))
		if !strings.Contains(got, strings.Split(c.want+",", ",")[0]) || (c.want == "" && got != "") {
			t.Errorf("%s: %q -> %q want %q", c.name, c.in, got, c.want)
		}
	}
	// Findings are deterministic and sorted.
	a := ReviewBrandFindings("Micr0soft "+U(0x440), ctx)
	b := ReviewBrandFindings("Micr0soft "+U(0x440), ctx)
	if findingCodes(a) != findingCodes(b) {
		t.Error("unstable order")
	}
}

// B3: scripts outside the old enumerated set keep their identity.
func TestUnlistedScriptsAreDistinguished(t *testing.T) {
	hebrew := U(0x5d0, 0x5d1, 0x5d2)
	arabic := U(0x627, 0x628, 0x62c)
	thai := U(0xe01, 0xe02, 0xe03)
	devanagari := U(0x915, 0x916, 0x917)
	ctx := BrandReviewContext{}
	// Whole-name mix of two unlisted scripts (each word single-script).
	if got := findingCodes(ReviewBrandFindings(hebrew+" "+arabic, ctx)); got != "script_mixed_name" {
		t.Errorf("hebrew word + arabic word: %q", got)
	}
	// Per-word mix inside ONE word.
	if got := findingCodes(ReviewBrandFindings(thai+devanagari, ctx)); !strings.Contains(got, "script_mixed_word") || !strings.Contains(got, "script_mixed_name") {
		t.Errorf("thai+devanagari in one word: %q", got)
	}
	// A name in ONE unlisted script is clean, and digits/punctuation/combining marks stay neutral.
	if got := findingCodes(ReviewBrandFindings(hebrew+" "+hebrew+"-1", ctx)); got != "" {
		t.Errorf("single unlisted script flagged: %q", got)
	}
	if s := scriptOf('1'); s != "" {
		t.Errorf("digit script %q", s)
	}
	if scriptOf(0x5d0) == scriptOf(0x627) || scriptOf(0x5d0) == "" {
		t.Errorf("hebrew/arabic identity: %q %q", scriptOf(0x5d0), scriptOf(0x627))
	}
}

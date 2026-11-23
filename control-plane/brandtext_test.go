package controlplane

// docs/66 2.2, 2a.7: validation of the PUBLIC branding fields. Every refusal class has its own case so a
// mutation of one rule cannot hide behind another.

import (
	"fmt"
	"strings"
	"testing"
)

func TestBrandNameAccepts(t *testing.T) {
	for _, in := range []string{"Acme Support", "  Acme   Support  ", "M" + U(0xfc) + "ller IT", "" + U(0xdc) + "n" + U(0xef) + "code Ltd", "" + U(0x682a) + "" + U(0x5f0f) + "" + U(0x4f1a) + "" + U(0x793e) + "" + U(0x30c6) + "" + U(0x30b9) + "" + U(0x30c8) + "", "A1B", "ACME" + U(0xa0) + "Support"} {
		got, err := NormalizeBrandName(in)
		if err != nil {
			t.Errorf("%q refused: %v", in, err)
			continue
		}
		if strings.Contains(got, "  ") || strings.Contains(got, ""+U(0xa0)+"") || got != strings.TrimSpace(got) {
			t.Errorf("%q not collapsed: %q", in, got)
		}
	}
	// NFC: e + combining acute becomes one precomposed rune.
	got, err := NormalizeBrandName("Cafe" + U(0x301) + " IT")
	if err != nil || got != "Caf"+U(0xe9)+" IT" {
		t.Errorf("NFC: %q %v", got, err)
	}
}

func TestBrandNameRefusals(t *testing.T) {
	cases := map[string]string{
		"bidi override":          "Acme" + U(0x202e) + "Support",
		"bidi isolate":           "Acme" + U(0x2066) + "Support",
		"zero width space":       "Acme" + U(0x200b) + "Support",
		"zero width joiner":      "Acme" + U(0x200d) + "Support",
		"word joiner":            "Acme" + U(0x2060) + "Support",
		"byte order mark":        "" + U(0xfeff) + "Acme Support",
		"soft hyphen":            "Acme" + U(0xad) + "Support",
		"NUL":                    "Acme\x00Support",
		"tab":                    "Acme\tSupport",
		"newline":                "Acme\nSupport",
		"line separator":         "Acme" + U(0x2028) + "Support",
		"private use":            "Acme" + U(0xe000) + "Support",
		"unassigned":             "Acme" + U(0x378) + "Support",
		"replacement char":       "Acme" + U(0xfffd) + "Support",
		"invalid utf8":           "Acme\xffSupport",
		"too short":              "Ab",
		"only symbols":           "!!!",
		"only spaces":            "     ",
		"empty":                  "",
		"too long":               strings.Repeat("ab", 51),
		"five identical":         "Acmeeeeee Support",
		"too wide":               strings.Repeat(""+U(0x682a)+"", 61),
		"combining flood":        "A" + strings.Repeat(""+U(0x301)+"", 5) + "cme",
		"combining total":        strings.Repeat("x"+U(0x303)+""+U(0x302)+" ", 5),
		"digits only? (allowed)": "",
	}
	delete(cases, "digits only? (allowed)")
	for name, in := range cases {
		if got, err := NormalizeBrandName(in); err == nil {
			t.Errorf("%s: %q accepted as %q", name, in, got)
		}
	}
	// Boundary: four identical is fine, 100 runes is fine, 101 is not.
	if _, err := NormalizeBrandName("Acmeeee Support"); err != nil {
		t.Errorf("four identical refused: %v", err)
	}
	if _, err := NormalizeBrandName(strings.Repeat("ab", 50)); err != nil {
		t.Errorf("100 runes refused: %v", err)
	}
	if _, err := NormalizeBrandName(strings.Repeat("ab", 50) + "c"); err == nil {
		t.Errorf("101 runes accepted")
	}
	// Exactly 3 marks in a row and 8 in all are the limits.
	if _, err := NormalizeBrandName("k" + U(0x301) + "" + U(0x302) + "" + U(0x303) + " b"); err != nil {
		t.Errorf("3 marks in a row refused: %v", err)
	}
}

func TestBrandSupportText(t *testing.T) {
	got, err := NormalizeBrandSupportText("Call us\r\nOpen 9-5\n\nMon-Fri")
	if err != nil || got != "Call us\nOpen 9-5\n\nMon-Fri" {
		t.Fatalf("multi-line: %q %v", got, err)
	}
	if got, err := NormalizeBrandSupportText("  \n  "); err != nil || got != "" {
		t.Fatalf("empty: %q %v", got, err)
	}
	for name, in := range map[string]string{
		"five lines":   "a\nb\nc\nd\ne",
		"bidi":         "hello" + U(0x202e) + "world",
		"zero width":   "hel" + U(0x200b) + "lo",
		"too long":     strings.Repeat("abcd ", 57),
		"NUL":          "a\x00b",
		"tab":          "a\tb",
		"vertical tab": "a\vb",
	} {
		if got, err := NormalizeBrandSupportText(in); err == nil {
			t.Errorf("%s accepted as %q", name, got)
		}
	}
	if _, err := NormalizeBrandSupportText(strings.Repeat("abcd ", 55) + "abcde"); err != nil {
		t.Errorf("280 runes refused: %v", err)
	}
	if _, err := NormalizeBrandSupportText("a\nb\nc\nd"); err != nil {
		t.Errorf("four lines refused: %v", err)
	}
}

// Contrast: find colours straddling each threshold exactly and assert the gate flips there.
func TestAccentContrastBoundaries(t *testing.T) {
	// Walk the grey ramp: the first grey that passes the label rule is the boundary; its predecessor fails.
	firstPass := func(against string, min float64) int {
		for v := 255; v >= 0; v-- {
			c := fmt.Sprintf("#%02x%02x%02x", v, v, v)
			if r, _ := ContrastRatio(c, against); r >= min {
				return v
			}
		}
		return -1
	}
	v := firstPass(ContrastLabelBackground, ContrastLabelMin)
	pass := fmt.Sprintf("#%02x%02x%02x", v, v, v)
	fail := fmt.Sprintf("#%02x%02x%02x", v+1, v+1, v+1)
	if got, err := NormalizeBrandAccent(pass); err != nil || got != pass {
		t.Errorf("label boundary %s refused: %v", pass, err)
	}
	if _, err := NormalizeBrandAccent(fail); err == nil || !strings.Contains(err.Error(), "needs 4.5:1") {
		t.Errorf("label boundary-1 %s accepted or unhelpful: %v", fail, err)
	}
	// 3:1 against the surface only bites for colours that already pass 4.5 vs white, which the label rule
	// dominates for greys; prove the surface rule independently with a colour that passes white but not paper:
	// none exists for darker colours, so assert the pair table directly instead.
	if r, _ := ContrastRatio("#35654a", ContrastLabelBackground); r < 4.5 {
		t.Errorf("the brand forest fails its own gate: %.2f", r)
	}
	if r, _ := ContrastRatio("#35654a", ContrastSurface); r < 3 {
		t.Errorf("the brand forest fails the surface gate: %.2f", r)
	}
	// The measured ratio is in the message, truncated (never rounded up into a pass).
	_, err := NormalizeBrandAccent("#888888")
	if err == nil || !strings.Contains(err.Error(), "contrast 3.54:1") {
		t.Errorf("message: %v", err)
	}
	for _, bad := range []string{"red", "#fff", "#12345g", "#1234567", "#FFFFFF"} {
		if _, err := NormalizeBrandAccent(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := NormalizeBrandAccent("#35654A"); err != nil || got != "#35654a" {
		t.Errorf("uppercase not lowered: %q %v", got, err)
	}
	if got, err := NormalizeBrandAccent(""); err != nil || got != "" {
		t.Errorf("empty accent: %q %v", got, err)
	}
	// A very light colour passes neither rule.
	if _, err := NormalizeBrandAccent("#f3f0e8"); err == nil {
		t.Errorf("the surface colour itself accepted")
	}
}

// The 3:1 surface rule must be reachable: a colour passing white at 4.5 but failing paper at 3 does not exist,
// so the rule is pinned by the constants and by this check that paper is darker than white.
func TestSurfaceRuleIsStricterOrEqualNever(t *testing.T) {
	rw, _ := ContrastRatio("#000000", ContrastLabelBackground)
	rp, _ := ContrastRatio("#000000", ContrastSurface)
	if !(rw > rp) {
		t.Fatalf("paper should be darker than white: %.2f vs %.2f", rw, rp)
	}
}

func TestBrandContact(t *testing.T) {
	ok := []BrandContact{
		{"phone", "+1 (555) 010-0199"}, {"phone", "020 7946 0958"}, {"email", "help@Example.COM"},
		{"email", "first.last+tag@sub.example.org"}, {"url", "https://support.example.com/help?x=1"},
		{"url", "HTTPS://Example.com/"}, {"", ""},
	}
	for _, c := range ok {
		if _, err := NormalizeBrandContact(c); err != nil {
			t.Errorf("%+v refused: %v", c, err)
		}
	}
	if got, _ := NormalizeBrandContact(BrandContact{"email", "help@Example.COM"}); got.Value != "help@example.com" {
		t.Errorf("domain not lowered: %+v", got)
	}
	bad := []BrandContact{
		{"phone", "12"}, {"phone", "abc-defg"}, {"phone", "+1 (555) 010-0199 ext 5555555"}, {"phone", "555+0100199"},
		{"phone", "1234567890123456"},
		{"email", "nobody"}, {"email", "a@b"}, {"email", "a b@example.com"}, {"email", "a@exa mple.com"},
		{"email", "..@example.com"}, {"email", "a@example.com:25"}, {"email", "" + U(0xe9) + "@example.com"},
		{"url", "http://example.com"}, {"url", "https://user:pw@example.com"}, {"url", "https://192.168.0.1/"},
		{"url", "https://[::1]/"}, {"url", "https://example.com:8443/"}, {"url", "https://localhost/"},
		{"url", "https://exa mple.com"}, {"url", "https://example.com/#frag"}, {"url", "https://b" + U(0xfc) + "cher.example/"},
		{"url", "https://example.com\\evil"}, {"url", "javascript:alert(1)"}, {"url", "https://" + strings.Repeat("a", 200) + ".com"},
		{"url", "https://example.com/a\x00"}, {"fax", "123456"}, {"phone", ""}, {"", "x"},
		{"url", "https://0x7f.1/"}, {"url", "https://127.1/"},
	}
	for _, c := range bad {
		if got, err := NormalizeBrandContact(c); err == nil {
			t.Errorf("%+v accepted as %+v", c, got)
		}
	}
}

func TestBrandingRevisionHashIsCanonical(t *testing.T) {
	h := func(a ...string) string { return BrandingRevisionHash(a[0], a[1], a[2], a[3], a[4], a[5]) }
	base := h("Acme", "#35654a", "t", "phone", "+1 555 01", "")
	if base != h("Acme", "#35654a", "t", "phone", "+1 555 01", "") || len(base) != 64 {
		t.Fatal("not deterministic")
	}
	// Field boundaries are length-prefixed, so shifting a byte between fields changes the hash.
	if base == h("Acm", "e#35654a", "t", "phone", "+1 555 01", "") || base == h("Acme", "#35654a", "", "tphone", "+1 555 01", "") {
		t.Fatal("ambiguous serialisation")
	}
	// Every field is covered.
	for i := 0; i < 6; i++ {
		args := []string{"Acme", "#35654a", "t", "phone", "+1 555 01", ""}
		args[i] += "x"
		if h(args...) == base {
			t.Errorf("field %d not covered by the hash", i)
		}
	}
}

// U builds a string from code points (source files never carry the invisible characters themselves).
func U(cps ...rune) string { return string(cps) }

// B4: the stored phone is digits only.
func TestBrandPhoneIsStoredAsPlainDigits(t *testing.T) {
	for in, want := range map[string]string{
		"+1 (555) 010-0199": "15550100199", "020 7946 0958": "02079460958", "555.010.0199": "5550100199",
		"12345": "12345", "123456789012345": "123456789012345", "(555)0100": "5550100",
	} {
		got, err := NormalizeBrandContact(BrandContact{Kind: "phone", Value: in})
		if err != nil || got.Value != want {
			t.Errorf("%q -> %q %v, want %q", in, got.Value, err, want)
		}
	}
	for _, in := range []string{"((12345", "12)345(", "(12345", "12345)", "(123)(456)", "1234", "1234567890123456", "12+345",
		"123 45 x", "1-2-3-4-5 ext 9", "tel:12345", "123" + U(0xa0) + "45", U(0xff11, 0xff12, 0xff13, 0xff14, 0xff15), "+", "()", "12\n345"} {
		if got, err := NormalizeBrandContact(BrandContact{Kind: "phone", Value: in}); err == nil {
			t.Errorf("%q accepted as %q", in, got.Value)
		}
	}
	if got, _ := NormalizeBrandContact(BrandContact{Kind: "phone", Value: "15550100199"}); got.Value != "15550100199" {
		t.Errorf("not a fixed point: %q", got.Value)
	}
	pub := &PublishedBranding{ProductName: "Acme Support", AccentColor: "#35654a", Contact: BrandContact{"phone", "+1 555 010 0199"}}
	if renderPublishedBranding(pub, false, "") != neutralBrandingResponse {
		t.Error("a punctuated stored phone is published")
	}
}

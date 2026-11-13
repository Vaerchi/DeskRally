package controlplane

// Validation and normalisation of the PUBLIC branding fields (docs/66 2.2, 2a.7, 2a.8, 2b.2).
//
// These strings are shown to anonymous guests on a page whose lede warns about impersonation, so they are held
// to a stricter standard than the console branding of tenantbranding.go (which stays as it is: it themes the
// authenticated console only). The rules, all enforced server-side and shared by the in-memory fake and the
// Postgres store (the standing "fake and pg must agree" rule, because the validation is not in the store):
//
//   - every text field is NFC-normalised; any character of Unicode category C (Cc, Cf, Co, Cs) and any
//     unassigned code point is refused, which covers bidi overrides and isolates, zero-width characters,
//     NUL and the private-use area; U+FFFD and invalid UTF-8 are refused too;
//   - whitespace (Zs) is collapsed to one ASCII space, line and paragraph separators are refused, leading and
//     trailing space is trimmed;
//   - at most 3 combining marks in a row, 8 per product name (24 per support text), and no more than 4
//     identical characters in a row (a flood of one character or accent is how a name is made to render huge);
//   - product name 3 to 100 runes with at least one letter or digit; support text at most 280 runes and 4
//     lines; a server-side estimate of the rendered width (East Asian wide characters count double) refuses
//     strings that CSS would have to clip;
//   - the accent must keep white label text at 4.5:1 and the page surface at 3:1;
//   - the one support contact is a phone, an email or an https URL, each validated to a strict ASCII shape.
//
// Rendering is the viewer's job (every string in a <bdi dir="auto"> text node); the server never emits markup.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Public branding bounds.
const (
	BrandNameMinRunes     = 3
	BrandNameMaxRunes     = 100
	BrandTextMaxRunes     = 280
	BrandTextMaxLines     = 4
	BrandContactMaxLen    = 200
	brandNameMaxCells     = 120
	brandTextMaxCells     = 400
	brandMaxMarksInARow   = 3
	brandNameMaxMarks     = 8
	brandTextMaxMarks     = 24
	brandMaxIdenticalRuns = 4
)

// Contrast surfaces (docs/66 2.2: "the gate is a table of the two foreground/background pairs so a theme change
// updates one constant"). The join page's primary button fill carries white text; link text and the button
// boundary sit on the warm-paper surface (--dr-paper in web/viewer/src/index.css).
const (
	ContrastLabelBackground = "#ffffff" // label text on the accent fill: 4.5:1 (WCAG AA normal text)
	ContrastSurface         = "#f3f0e8" // accent against the page surface: 3:1 (WCAG non-text UI)
	ContrastLabelMin        = 4.5
	ContrastSurfaceMin      = 3.0
)

// BrandFieldError names the field a refusal is about so a console can put the message in the right place.
type BrandFieldError struct {
	Field string `json:"field"`
	Msg   string `json:"error"`
}

func (e *BrandFieldError) Error() string { return e.Field + ": " + e.Msg }

func fieldErr(field, format string, a ...any) *BrandFieldError {
	return &BrandFieldError{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// assignedRune reports whether r is an assigned code point (Go's category tables contain no Cn).
func assignedRune(r rune) bool {
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.C)
}

func isMark(r rune) bool { return unicode.Is(unicode.M, r) }

// cellWidth is the width estimate of one rune: combining marks 0, East Asian wide and emoji 2, the rest 1.
func cellWidth(r rune) int {
	switch {
	case isMark(r):
		return 0
	case r >= 0x1100 && r <= 0x115F, r >= 0x2E80 && r <= 0xA4CF, r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF, r >= 0xFE30 && r <= 0xFE6F, r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6, r >= 0x1F300 && r <= 0x1FAFF, r >= 0x20000 && r <= 0x3FFFD:
		return 2
	}
	return 1
}

type brandTextRules struct {
	field     string
	multiline bool
	minRunes  int
	maxRunes  int
	maxLines  int
	maxCells  int
	maxMarks  int
	needAlnum bool
	allowNone bool // the empty string is acceptable
}

// normalizeBrandText applies the rules above and returns the canonical string.
func normalizeBrandText(in string, o brandTextRules) (string, *BrandFieldError) {
	if !utf8.ValidString(in) {
		return "", fieldErr(o.field, "must be valid UTF-8 text")
	}
	s := norm.NFC.String(in)
	if o.multiline {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	}
	var b strings.Builder
	prevSpace, run, marksRow, marks, cells := false, 0, 0, 0, 0
	var prev rune
	alnum := false
	lines := 1
	runes := 0
	for _, r := range s {
		switch {
		case r == '\n' && o.multiline:
			lines++
			b.WriteRune(r)
			prevSpace, run, marksRow, prev = false, 0, 0, 0
			continue
		case r == utf8.RuneError || !assignedRune(r) || unicode.Is(unicode.C, r) || r == 0x2028 || r == 0x2029:
			return "", fieldErr(o.field, "contains a control, formatting (bidirectional or zero-width), private-use or unassigned character (U+%04X)", r)
		case unicode.Is(unicode.Zs, r):
			if !prevSpace {
				b.WriteByte(' ')
			}
			prevSpace, prev, run, marksRow = true, ' ', 0, 0
			continue
		}
		prevSpace = false
		if r == prev {
			run++
			if run >= brandMaxIdenticalRuns+1 {
				return "", fieldErr(o.field, "repeats one character more than %d times in a row", brandMaxIdenticalRuns)
			}
		} else {
			prev, run = r, 1
		}
		if isMark(r) {
			marksRow++
			marks++
			if marksRow > brandMaxMarksInARow || marks > o.maxMarks {
				return "", fieldErr(o.field, "has too many combining marks (at most %d in a row, %d in all)", brandMaxMarksInARow, o.maxMarks)
			}
		} else {
			marksRow = 0
		}
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			alnum = true
		}
		cells += cellWidth(r)
		runes++
		b.WriteRune(r)
	}
	out := b.String()
	if o.multiline {
		ls := strings.Split(out, "\n")
		for i := range ls {
			ls[i] = strings.TrimSpace(ls[i])
		}
		out = strings.TrimSpace(strings.Join(ls, "\n"))
		lines = strings.Count(out, "\n") + 1
		runes = utf8.RuneCountInString(out)
		if out == "" {
			lines = 0
		}
	} else {
		out = strings.TrimSpace(out)
		runes = utf8.RuneCountInString(out)
	}
	if out == "" && o.allowNone {
		return "", nil
	}
	if runes < o.minRunes || runes > o.maxRunes {
		return "", fieldErr(o.field, "must be %d to %d characters", o.minRunes, o.maxRunes)
	}
	if o.multiline && lines > o.maxLines {
		return "", fieldErr(o.field, "must be at most %d lines", o.maxLines)
	}
	if o.needAlnum && !alnum {
		return "", fieldErr(o.field, "must contain a letter or digit")
	}
	if estimateCells(out) > o.maxCells {
		return "", fieldErr(o.field, "is too wide to display (estimated %d cells, at most %d)", estimateCells(out), o.maxCells)
	}
	return out, nil
}

func estimateCells(s string) int {
	n := 0
	for _, r := range s {
		n += cellWidth(r)
	}
	return n
}

// NormalizeBrandName: 3 to 100 runes, a letter or digit, one line.
func NormalizeBrandName(s string) (string, *BrandFieldError) {
	return normalizeBrandText(s, brandTextRules{field: "product_name", minRunes: BrandNameMinRunes, maxRunes: BrandNameMaxRunes,
		maxCells: brandNameMaxCells, maxMarks: brandNameMaxMarks, needAlnum: true})
}

// NormalizeBrandSupportText: empty, or up to 280 runes over at most 4 lines.
func NormalizeBrandSupportText(s string) (string, *BrandFieldError) {
	return normalizeBrandText(s, brandTextRules{field: "support_text", multiline: true, maxRunes: BrandTextMaxRunes,
		maxLines: BrandTextMaxLines, maxCells: brandTextMaxCells, maxMarks: brandTextMaxMarks, allowNone: true})
}

// ---- accent contrast ------------------------------------------------------------------------------------

func srgbChannel(v uint8) float64 {
	c := float64(v) / 255
	if c <= 0.03928 {
		return c / 12.92
	}
	return math.Pow((c+0.055)/1.055, 2.4)
}

func parseHex6(s string) (r, g, b uint8, ok bool) {
	if len(s) != 7 || s[0] != '#' {
		return 0, 0, 0, false
	}
	raw, err := hex.DecodeString(s[1:])
	if err != nil || len(raw) != 3 {
		return 0, 0, 0, false
	}
	return raw[0], raw[1], raw[2], true
}

// relativeLuminance is the WCAG 2.x relative luminance of a #rrggbb colour.
func relativeLuminance(hexColor string) (float64, bool) {
	r, g, b, ok := parseHex6(hexColor)
	if !ok {
		return 0, false
	}
	return 0.2126*srgbChannel(r) + 0.7152*srgbChannel(g) + 0.0722*srgbChannel(b), true
}

// ContrastRatio is the WCAG contrast ratio of two #rrggbb colours (1 to 21).
func ContrastRatio(a, b string) (float64, bool) {
	la, ok1 := relativeLuminance(a)
	lb, ok2 := relativeLuminance(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05), true
}

func floor2(f float64) float64 { return math.Floor(f*100) / 100 }

// NormalizeBrandAccent lowercases a `#rrggbb` accent and applies the contrast gate. Empty = theme default.
// A failing colour is refused with the measured ratio; nothing is adjusted silently.
func NormalizeBrandAccent(s string) (string, *BrandFieldError) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	if _, _, _, ok := parseHex6(s); !ok {
		return "", fieldErr("accent_color", "must be empty or a #rrggbb hex colour")
	}
	for _, c := range []struct {
		against string
		min     float64
		what    string
	}{{ContrastLabelBackground, ContrastLabelMin, "white button label"}, {ContrastSurface, ContrastSurfaceMin, "page surface"}} {
		ratio, _ := ContrastRatio(s, c.against)
		if ratio < c.min {
			return "", fieldErr("accent_color", "contrast %.2f:1 against the %s, needs %.1f:1", floor2(ratio), c.what, c.min)
		}
	}
	return s, nil
}

// ---- support contact ------------------------------------------------------------------------------------

// BrandContact is the one support contact: a kind and its value.
type BrandContact struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

var (
	emailLocalRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+)*$`)
)

// NormalizeBrandContact validates and canonicalises the contact. An empty kind with an empty value is "no
// contact". The value is ASCII only (a URL host must already be punycode) and is shown literally.
func NormalizeBrandContact(c BrandContact) (BrandContact, *BrandFieldError) {
	c.Kind, c.Value = strings.ToLower(strings.TrimSpace(c.Kind)), strings.TrimSpace(c.Value)
	if c.Kind == "" && c.Value == "" {
		return BrandContact{}, nil
	}
	if c.Kind == "" || c.Value == "" {
		return BrandContact{}, fieldErr("support_contact", "needs both a kind and a value")
	}
	if len(c.Value) > BrandContactMaxLen {
		return BrandContact{}, fieldErr("support_contact", "is at most %d characters", BrandContactMaxLen)
	}
	for i := 0; i < len(c.Value); i++ {
		if c.Value[i] < 0x20 || c.Value[i] >= 0x7f {
			return BrandContact{}, fieldErr("support_contact", "must be plain ASCII without control characters (use punycode for a domain)")
		}
	}
	switch c.Kind {
	case "phone":
		d, ok := canonicalPhone(c.Value)
		if !ok {
			return BrandContact{}, fieldErr("support_contact", "a phone number is 5 to 15 digits; spaces, dashes, dots, one balanced pair of parentheses and a leading + are accepted and removed")
		}
		c.Value = d
	case "email":
		at := strings.LastIndexByte(c.Value, '@')
		if at < 1 || at > 64 {
			return BrandContact{}, fieldErr("support_contact", "is not a valid email address")
		}
		local, domain := c.Value[:at], strings.ToLower(c.Value[at+1:])
		if !emailLocalRE.MatchString(local) {
			return BrandContact{}, fieldErr("support_contact", "is not a valid email address")
		}
		if h, ok := NormalizeAuthority(domain); !ok || h != domain || strings.Contains(c.Value[at+1:], ":") {
			return BrandContact{}, fieldErr("support_contact", "is not a valid email address")
		}
		c.Value = local + "@" + domain
	case "url":
		if !strings.HasPrefix(strings.ToLower(c.Value), "https://") {
			return BrandContact{}, fieldErr("support_contact", "a URL must start with https://")
		}
		if strings.ContainsAny(c.Value, " \\") {
			return BrandContact{}, fieldErr("support_contact", "is not a valid URL")
		}
		u, err := url.Parse(c.Value)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.Host == "" {
			return BrandContact{}, fieldErr("support_contact", "must be a plain https URL on a public host (no user-info, no fragment)")
		}
		host, ok := NormalizeAuthority(u.Host)
		if !ok || strings.Contains(u.Host, ":") || host != strings.ToLower(u.Hostname()) {
			return BrandContact{}, fieldErr("support_contact", "must name a public DNS host (no port, no IP literal)")
		}
		u.Host = host
		c.Value = u.String()
		if len(c.Value) > BrandContactMaxLen {
			return BrandContact{}, fieldErr("support_contact", "is at most %d characters", BrandContactMaxLen)
		}
	default:
		return BrandContact{}, fieldErr("support_contact", "kind must be phone, email or url")
	}
	return c, nil
}

// ---- the revision hash ----------------------------------------------------------------------------------

// BrandingRevisionHash is the SHA-256 over the canonical serialisation of every public field plus the logo's
// hash (docs/66 2a.3): a version tag, then each field as a uvarint length and its bytes, in fixed order.
func BrandingRevisionHash(name, accent, supportText, contactKind, contactValue, logoSHA string) string {
	h := sha256.New()
	put := func(s string) {
		var n [binary.MaxVarintLen64]byte
		h.Write(n[:binary.PutUvarint(n[:], uint64(len(s)))])
		h.Write([]byte(s))
	}
	put("deskrally-branding-revision-v1")
	for _, f := range []string{name, accent, supportText, contactKind, contactValue, logoSHA} {
		put(f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalPhone reduces a typed phone number to its stored form: exactly 5 to 15 ASCII digits (repair B4; the
// contract is "plain digits"). Separators are dropped: spaces, dashes, dots, one leading +, and AT MOST ONE
// balanced pair of parentheses (so "((12345" and "12)345(" are refused, not silently repaired). Anything else,
// including a + anywhere but the front, is refused.
func canonicalPhone(in string) (string, bool) {
	if len(in) > 40 {
		return "", false
	}
	var b strings.Builder
	open, closed := false, false
	for i := 0; i < len(in); i++ {
		switch ch := in[i]; {
		case ch >= '0' && ch <= '9':
			b.WriteByte(ch)
		case ch == ' ' || ch == '-' || ch == '.':
		case ch == '+' && i == 0:
		case ch == '(' && !open && !closed:
			open = true
		case ch == ')' && open && !closed:
			closed = true
		default:
			return "", false
		}
	}
	if open != closed || b.Len() < 5 || b.Len() > 15 {
		return "", false
	}
	return b.String(), true
}

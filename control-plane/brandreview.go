package controlplane

// Automated findings shown to the platform operator with the rendered identity under review (docs/66 2a.7).
//
// Findings are WARNINGS the operator must acknowledge, with a reason, before approval; they are never an
// automatic refusal and an Owner edit cannot bypass review (nothing publishes without an operator CAS). The
// checks:
//
//   - a confusable SKELETON (a reduced UTS #39 skeleton, below) compared against every other published brand
//     name, every other tenant's hostname label and the in-repo denylist (brand_denylist.txt, changed by PR);
//   - mixed scripts, per word and for the whole name, under the "highly restrictive" profile (Latin may mix
//     only with Han plus Hiragana and Katakana, Han plus Bopomofo, or Han plus Hangul).
//
// The confusables table is a deliberately SMALL, checked-in subset (the Latin look-alikes in Cyrillic and Greek
// that are visually identical in common fonts, plus the ASCII digit and letter collisions). The full
// confusables.txt is a data file the repository does not carry; this is the 'a checked-in list, not a service'
// of 2a.7 and a collision it misses is caught by the operator's own review of the rendered name.

import (
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// confusableLatin maps look-alike letters of other scripts to the Latin letter they imitate.
var confusableLatin = map[rune]rune{
	// Cyrillic
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h',
	'к': 'k', 'м': 'm', 'т': 't', 'н': 'h', 'ԁ': 'd', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'в': 'b', 'г': 'r',
	'А': 'a', 'В': 'b', 'Е': 'e', 'К': 'k', 'М': 'm', 'Н': 'h', 'О': 'o', 'Р': 'p', 'С': 'c', 'Т': 't', 'Х': 'x', 'У': 'y', 'І': 'i', 'Ј': 'j', 'Ѕ': 's',
	// Greek
	'ο': 'o', 'ν': 'v', 'α': 'a', 'ρ': 'p', 'ι': 'i', 'τ': 't', 'κ': 'k', 'χ': 'x', 'υ': 'u', 'ε': 'e',
	'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h', 'Ι': 'i', 'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'Ο': 'o', 'Ρ': 'p', 'Τ': 't', 'Υ': 'y', 'Χ': 'x',
	// Latin small capital / dotless forms
	'ı': 'i', 'ɡ': 'g', 'ɑ': 'a',
}

// BrandSkeleton folds a display name to the string two look-alike names share: NFKC, then letters of other
// scripts that imitate Latin ones, then lowercase and the ASCII collisions (i, l, the digit one and the vertical
// bar are one class, so capital I and lowercase L collide; zero and o are one), everything that is not a letter or digit dropped,
// and finally rn to m and vv to w.
func BrandSkeleton(s string) string {
	s = norm.NFKC.String(s)
	var b strings.Builder
	for _, r := range s {
		if m, ok := confusableLatin[r]; ok {
			r = m
		}
		r = unicode.ToLower(r)
		switch r {
		case 'i', '1', '|', 'l', 0x131:
			r = 'l' // i, l, 1, capital I and the bar are one class
		case '0':
			r = 'o'
		}
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			b.WriteRune(r)
		}
	}
	out := b.String()
	out = strings.ReplaceAll(out, "rn", "m")
	out = strings.ReplaceAll(out, "vv", "w")
	return out
}

// scriptOf is the Unicode script of r by name, from the complete unicode.Scripts table (repair B3: an unlisted
// script keeps its own identity, so Hebrew and Arabic are two scripts, not one "Other"). Common and Inherited
// (punctuation, digits, combining marks) are neutral and return "".
func scriptOf(r rune) string {
	for name, tab := range unicode.Scripts {
		if unicode.Is(tab, r) {
			if name == "Common" || name == "Inherited" {
				return ""
			}
			return name
		}
	}
	return "" // unassigned: refused earlier by the text rules
}

func subsetOf(set map[string]bool, allowed ...string) bool {
	a := map[string]bool{}
	for _, s := range allowed {
		a[s] = true
	}
	for s := range set {
		if !a[s] {
			return false
		}
	}
	return true
}

// restrictiveScripts reports whether a set of scripts passes the highly restrictive profile.
func restrictiveScripts(set map[string]bool) bool {
	if len(set) <= 1 {
		return true
	}
	return subsetOf(set, "Latin", "Han", "Hiragana", "Katakana") ||
		subsetOf(set, "Latin", "Han", "Bopomofo") || subsetOf(set, "Latin", "Han", "Hangul")
}

func scriptSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, r := range s {
		if sc := scriptOf(r); sc != "" {
			out[sc] = true
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BrandReviewContext is what a revision is compared against. Everything here is about OTHER tenants.
type BrandReviewContext struct {
	// OtherBrandNames: product names currently published by other tenants.
	OtherBrandNames []string
	// OtherHostLabels: the first DNS label of every other tenant's hostname (any state: a quarantined name still
	// looks like itself).
	OtherHostLabels []string
}

// ReviewBrandFindings returns the warnings for a product name, in stable order.
func ReviewBrandFindings(name string, ctx BrandReviewContext) []HostFinding {
	var out []HostFinding
	add := func(code, msg string) { out = append(out, HostFinding{Code: code, Message: msg}) }
	if all := scriptSet(name); !restrictiveScripts(all) {
		add("script_mixed_name", "the name mixes scripts ("+strings.Join(sortedKeys(all), ", ")+")")
	}
	words := strings.FieldsFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsMark(r) && !unicode.IsNumber(r) })
	for _, w := range words {
		if set := scriptSet(w); !restrictiveScripts(set) {
			add("script_mixed_word", "the word "+w+" mixes scripts ("+strings.Join(sortedKeys(set), ", ")+")")
			break
		}
	}
	sk := BrandSkeleton(name)
	if sk != "" {
		for _, other := range ctx.OtherBrandNames {
			if BrandSkeleton(other) == sk {
				add("skeleton_collision_brand", "the name is confusable with the published brand "+other)
				break
			}
		}
		for _, lab := range ctx.OtherHostLabels {
			if BrandSkeleton(lab) == sk {
				add("skeleton_collision_hostname", "the name is confusable with the hostname label "+lab)
				break
			}
		}
		for _, entry := range brandDenylist() {
			es := BrandSkeleton(entry)
			if es != "" && (es == sk || (len(es) >= 5 && strings.Contains(sk, es))) {
				add("brand_denylist", "the name resembles the denylisted name "+entry)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Message < out[j].Message
	})
	return out
}

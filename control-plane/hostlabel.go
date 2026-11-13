package controlplane

// Hostname label vetting for platform operators (docs/66 section 3 item 3, 2a.7, 2a.10).
//
// Two kinds of finding:
//
//	refusal  the label can never be a tenant host (wrong shape, reserved, too short, a default or legacy host
//	         label). Not overridable.
//	warning  a lookalike risk the operator must ACKNOWLEDGE WITH A REASON: an IDN (xn--) label, a confusable
//	         skeleton collision with another hostname, a reserved name or a denylisted brand. The override and
//	         its reason go on both audit chains. A collision is a warning, never an automatic refusal.

import (
	_ "embed"
	"sort"
	"strings"
)

//go:embed brand_denylist.txt
var brandDenylistRaw string

// HostLabelMinLen is the shortest label a tenant host may use.
const HostLabelMinLen = 3

// HostFinding is one warning the operator can acknowledge.
type HostFinding struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// LabelSkeleton folds the common look-alike substitutions so "micr0soft", "rnicrosoft" and "micro-soft" all
// collapse to the same string: lowercase, hyphens removed, then rn->m, vv->w, 0->o, 1->l.
func LabelSkeleton(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "rn", "m")
	s = strings.ReplaceAll(s, "vv", "w")
	s = strings.NewReplacer("0", "o", "1", "l").Replace(s)
	return s
}

// brandDenylist parses the embedded list once per call site (it is small); entries are skeleton-folded.
func brandDenylist() []string {
	var out []string
	for _, line := range strings.Split(brandDenylistRaw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	return out
}

// HostLabelContext is what a label is compared against.
type HostLabelContext struct {
	// ReservedLabels: the labels of the default and legacy hosts (refused outright).
	ReservedLabels []string
	// ExistingLabels: labels of every other assignment (pending, active or quarantined) for skeleton collision.
	ExistingLabels []string
}

// CheckHostLabel vets one label. It returns hard refusals (non-empty means refused) and acknowledgeable
// warnings, both in stable order.
func CheckHostLabel(label string, ctx HostLabelContext) (refusals []string, warnings []HostFinding) {
	if !ValidTenantSlug(label) {
		refusals = append(refusals, "label must be a valid, non-reserved tenant slug (1-63 lowercase letters, digits or hyphens)")
	}
	if len(label) < HostLabelMinLen {
		refusals = append(refusals, "label must be at least 3 characters")
	}
	for _, r := range ctx.ReservedLabels {
		if label == r {
			refusals = append(refusals, "label belongs to a default or legacy host")
			break
		}
	}
	if len(refusals) > 0 {
		return refusals, nil
	}
	if strings.HasPrefix(label, "xn--") || strings.Contains(label, "--") {
		warnings = append(warnings, HostFinding{Code: "idn_label", Message: "label is an IDN (punycode) or contains a double hyphen"})
	}
	sk := LabelSkeleton(label)
	for name := range reservedTenantSlugs {
		if LabelSkeleton(name) == sk {
			warnings = append(warnings, HostFinding{Code: "reserved_lookalike", Message: "label looks like the reserved name " + name})
		}
	}
	for _, entry := range brandDenylist() {
		es := LabelSkeleton(entry)
		if es == sk || (len(es) >= 5 && strings.Contains(sk, es)) {
			warnings = append(warnings, HostFinding{Code: "brand_denylist", Message: "label resembles the denylisted name " + entry})
		}
	}
	seen := map[string]bool{}
	for _, other := range ctx.ExistingLabels {
		if other == label || seen[other] {
			continue
		}
		seen[other] = true
		if LabelSkeleton(other) == sk {
			warnings = append(warnings, HostFinding{Code: "skeleton_collision", Message: "label is confusable with the existing label " + other})
		}
	}
	sort.SliceStable(warnings, func(i, j int) bool {
		if warnings[i].Code != warnings[j].Code {
			return warnings[i].Code < warnings[j].Code
		}
		return warnings[i].Message < warnings[j].Message
	})
	return nil, warnings
}

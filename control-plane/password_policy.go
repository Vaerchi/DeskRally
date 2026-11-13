package controlplane

// Password complexity policy (docs/01-feature-parity.md §10 P0 — "Password complexity and login
// lockout policies"). Lockout/throttle already existed (throttle.go); THIS is the complexity half.
//
// This module is deliberately pure: it takes a candidate password plus the identity context it
// must not echo, and returns the unmet requirements. It performs no I/O and no hashing, so it is
// exhaustively unit-testable and can be reused by any future provisioning/reset path, not just
// POST /me/password.
//
// A note on the rules, because they are a considered trade-off rather than a default:
//
//   - NIST SP 800-63B §5.1.1.2 argues AGAINST composition rules (they push users toward
//     "Password1!") and FOR length plus a breach/blocklist check. docs/01 explicitly asks for
//     "min-length/charset" enforcement, so both are implemented, but the weighting reflects the
//     modern advice: the length floor is the load-bearing rule (12, well above the NIST 8
//     minimum), the class rule asks for 3 of 4 rather than all 4, and a LONG passphrase satisfies
//     the class rule outright (PassphraseExemptLen) precisely so the policy does not punish the
//     strongest thing a user can choose.
//   - A real breach-corpus check (k-anonymity against HIBP) is NOT done here: it is a network
//     call from the credential path, which is a availability/privacy decision an operator must
//     make, not something to switch on silently. The small embedded blocklist below catches the
//     handful of passwords that dominate every credential-stuffing list and nothing more — it is
//     not claimed to be a substitute. See docs/01 §10.
//   - Password HISTORY (reuse across N previous passwords) needs a schema change
//     (user_credential keeps exactly one hash). The change endpoint enforces the one case it can
//     see without new storage: the new password must differ from the CURRENT one.
//   - KNOWN TRADE-OFF, pinned by TestValidatePasswordSingleScriptNeedsPassphraseLength: a password
//     written entirely in a non-cased script (CJK, for one) can only ever reach ONE character
//     class, so between MinLen and PassphraseExemptLen the class rule is unsatisfiable for it and
//     the passphrase exemption is the only route. That is accepted rather than special-cased —
//     the alternative (per-script class rules) is a lot of machinery for a rule NIST already
//     argues against, and the exemption gives such users a strictly better password anyway.

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PasswordPolicy is the tunable rule set. DefaultPasswordPolicy is what the HTTP layer uses; the
// struct exists so tests (and, later, a per-tenant policy) can vary it without forking the logic.
type PasswordPolicy struct {
	// MinLen is the minimum length in RUNES (not bytes), so a non-ASCII passphrase is not
	// penalised for its encoding.
	MinLen int
	// MaxLen bounds the input in BYTES. This is a denial-of-service control, not a strength
	// rule: argon2id hashes the password with a fixed memory cost, but the caller still controls
	// how many bytes the server reads, copies and feeds to Blake2b on a path that is by design
	// expensive. Bounded here, at the policy, so every future credential path inherits it.
	MaxLen int
	// MinClasses is how many of {lowercase, uppercase, digit, other} must appear.
	MinClasses int
	// PassphraseExemptLen is the length at or above which MinClasses is waived — a long
	// passphrase is stronger than a short password that ticks every character-class box.
	// 0 disables the exemption.
	PassphraseExemptLen int
}

// DefaultPasswordPolicy is the shipped profile: 12 runes minimum, 3 of 4 character classes
// (waived at 20+ runes), 256 bytes maximum.
var DefaultPasswordPolicy = PasswordPolicy{
	MinLen:              12,
	MaxLen:              256,
	MinClasses:          3,
	PassphraseExemptLen: 20,
}

// PasswordIdentity is the account context a password must not simply restate. All fields are
// optional; empty ones are skipped.
type PasswordIdentity struct {
	Email       string
	DisplayName string
}

// PasswordPolicyError reports every unmet requirement at once, so a client can show the whole
// list instead of making the user discover the rules one submission at a time.
//
// It is safe to return verbatim to the caller: the endpoint that produces it is authenticated and
// the user is changing THEIR OWN password, so the messages describe rules the user is entitled to
// know. It never echoes the candidate password.
type PasswordPolicyError struct {
	Reasons []string
}

func (e *PasswordPolicyError) Error() string {
	return "password does not meet policy: " + strings.Join(e.Reasons, "; ")
}

// minLocalPartMatchLen is the shortest email local-part / display-name token that the
// "must not contain your identity" rule bothers with. Below this the token is short enough that
// a ban would reject unrelated strong passwords for containing, say, "jo".
const minLocalPartMatchLen = 4

// commonPasswords is a deliberately SMALL blocklist of the values that top every published
// credential-stuffing corpus, normalised to lowercase. It is compared against the whole password
// only (never as a substring), because a substring ban on strings this common rejects good
// passphrases. See the module comment on why this is not a breach-corpus check.
var commonPasswords = map[string]struct{}{
	"password":        {},
	"password1":       {},
	"password123":     {},
	"password1234":    {},
	"passw0rd":        {},
	"p@ssw0rd":        {},
	"p@ssword123":     {},
	"qwertyuiop":      {},
	"qwerty123456":    {},
	"1234567890":      {},
	"123456789012":    {},
	"administrator":   {},
	"welcome123456":   {},
	"letmein123456":   {},
	"iloveyou1234":    {},
	"screenconnect":   {},
	"changeme123":     {},
	"changeme1234":    {},
	"trustno1234":     {},
	"monkey123456":    {},
	"dragon123456":    {},
	"abcd1234abcd":    {},
	"aaaaaaaaaaaa":    {},
	"remotesupport":   {},
	"remotedesktop":   {},
	"controlplane123": {},
}

// commonPasswordsByLengthDesc is commonPasswords ordered longest-first, so mostlyCommonPassword's
// stripping is DETERMINISTIC (Go randomises map iteration) and an entry that contains another
// ("password1" ⊃ "password") is removed as the longer match first.
var commonPasswordsByLengthDesc = sortedCommonPasswords()

func sortedCommonPasswords() []string {
	out := make([]string, 0, len(commonPasswords))
	for w := range commonPasswords {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j] // stable tiebreak
	})
	return out
}

// ValidatePassword reports whether a candidate password satisfies the policy, given the account's
// identity. A nil return means acceptable; otherwise the error is a *PasswordPolicyError listing
// every failed rule.
//
// The checks, in order, and why each exists:
//
//	length (bytes)   DoS bound on an intentionally expensive path — checked FIRST so an oversized
//	                 body is rejected before anything walks it.
//	control chars    An ASCII control character in a password is a paste/encoding accident far
//	                 more often than a choice, and it survives into a hash the user can then never
//	                 reproduce from a different client. Rejected rather than silently accepted.
//	length (runes)   The load-bearing strength rule.
//	classes          3 of 4, waived for a long passphrase.
//	identity echo    A password that IS (or embeds) the account's own email/name is public data.
//	blocklist        The handful of values that dominate credential stuffing.
func ValidatePassword(password string, id PasswordIdentity, p PasswordPolicy) error {
	var reasons []string

	if p.MaxLen > 0 && len(password) > p.MaxLen {
		// Return immediately: every rule below walks the string, and the point of this bound is
		// to not do unbounded work for an unauthenticated-sized input.
		return &PasswordPolicyError{Reasons: []string{
			fmt.Sprintf("must be at most %d bytes", p.MaxLen),
		}}
	}
	if !utf8.ValidString(password) {
		return &PasswordPolicyError{Reasons: []string{"must be valid UTF-8"}}
	}

	runes := []rune(password)
	if hasControlRune(runes) {
		reasons = append(reasons, "must not contain control characters")
	}
	if p.MinLen > 0 && len(runes) < p.MinLen {
		reasons = append(reasons, fmt.Sprintf("must be at least %d characters", p.MinLen))
	}

	exempt := p.PassphraseExemptLen > 0 && len(runes) >= p.PassphraseExemptLen
	if p.MinClasses > 0 && !exempt {
		// Deliberately does NOT say "…or be at least N characters". Naming the exemption in the
		// rejection is what steers a user who just failed the class rule into padding a weak
		// password to the exemption length, which is the exact behaviour the rules below exist to
		// stop. The requirement is stated; the escape hatch is not advertised.
		reasons = append(reasons, ensureClasses(runes, p.MinClasses)...)
	}

	lower := strings.ToLower(password)
	if echoesIdentity(lower, id) {
		reasons = append(reasons, "must not contain your email address or name")
	}
	reasons = append(reasons, checkLowEntropy(lower, runes, p)...)

	if len(reasons) > 0 {
		return &PasswordPolicyError{Reasons: reasons}
	}
	return nil
}

// ensureClasses reports the character-class rule's failure, if any.
func ensureClasses(runes []rune, minClasses int) []string {
	if countClasses(runes) >= minClasses {
		return nil
	}
	return []string{"must use at least " + fmt.Sprint(minClasses) +
		" of: lowercase, uppercase, digit, symbol"}
}

// minDistinctRunes is the floor on how many DIFFERENT characters a password must contain,
// enforced at every length — the passphrase exemption does not waive it.
//
// This exists because length alone was launderable. Without it the policy contradicted itself:
// "aaaaaaaaaaaa" (12) was rejected by the blocklist while "aaaaaaaaaaaaaaaaaaaa" (20) was
// ACCEPTED, because reaching PassphraseExemptLen waived the class rule and the blocklist only ever
// compared the whole string. A long string built from two or three distinct characters carries no
// more entropy than the short version already refused, so length must not buy an exemption from
// that. NIST SP 800-63B §5.1.1.2 — the same section this module cites for relaxing composition
// rules — requires exactly this compensating check ("repetitive or sequential characters").
const minDistinctRunes = 5

// checkLowEntropy applies the three checks that keep the passphrase exemption from becoming a
// bypass: the distinct-character floor, the blocklist (including a self-repeated blocklist entry),
// and the "mostly a blocklisted word" test.
func checkLowEntropy(lower string, runes []rune, p PasswordPolicy) []string {
	var reasons []string

	// A password that is some shorter UNIT repeated is only as strong as that unit — repetition
	// adds length, not entropy. So the length floor is applied to the unit rather than to the
	// padded result, which is what stops "12345" (refused: too short) from being laundered into
	// "12345123451234512345" (20 runes, 5 distinct characters, matching no blocklist entry).
	unit := smallestRepeatUnit(lower)
	repeated := unit != lower
	shortUnit := repeated && p.MinLen > 0 && len([]rune(unit)) < p.MinLen

	if shortUnit || (len(runes) > 0 && countDistinctRunes(runes) < minDistinctRunes) {
		reasons = append(reasons,
			"must not be a single character or a short sequence repeated to reach the length requirement")
	}

	switch word, dominates := mostlyCommonPassword(lower, p); {
	case isCommonPassword(lower):
		reasons = append(reasons, "is among the most commonly used passwords")
	case repeated && isCommonPassword(unit):
		// "qwertyuiop" is refused, so "qwertyuiopqwertyuiop" must be too — concatenating a banned
		// value with itself is the most obvious way around an exact-match blocklist.
		reasons = append(reasons, "is a commonly used password, repeated")
	case dominates:
		// Name the offending word and say what would fix it. "is mostly a commonly used password"
		// was true but unactionable: the user cannot see which of the substrings they typed is on a
		// list they have never read, so their only move is to guess.
		//
		// This is safe because the word is echoed back out of the CALLER'S OWN SUBMISSION and comes
		// from OUR public blocklist — it is never derived from anything stored. That is the whole
		// justification, and it deliberately no longer rests on the reader being authenticated: this
		// function's reasons are now also returned by the PUBLIC POST /auth/password/redeem, where
		// the caller holds a reset link rather than a session. The one rule that CONSULTS stored
		// values, the identity-echo check above, is careful for the same reason: its reason is the
		// fixed string "must not contain your email address or name", which reveals neither value
		// nor even which of the two matched.
		reasons = append(reasons, fmt.Sprintf(
			"is mostly the commonly used password %q — the rest must be at least %d characters",
			word, minOwnRunesBesideBlocklist(p)))
	}

	return reasons
}

// countDistinctRunes counts how many different runes appear.
func countDistinctRunes(runes []rune) int {
	seen := make(map[rune]struct{}, len(runes))
	for _, r := range runes {
		seen[r] = struct{}{}
	}
	return len(seen)
}

func isCommonPassword(lower string) bool {
	_, banned := commonPasswords[lower]
	return banned
}

// smallestRepeatUnit returns the shortest prefix u such that s is u repeated a whole number of
// times ("abcabcabc" → "abc"). Returns s itself when s is not a repetition. Operates on runes so a
// multi-byte password is not split mid-character.
func smallestRepeatUnit(s string) string {
	runes := []rune(s)
	n := len(runes)
	for unit := 1; unit < n; unit++ {
		if n%unit != 0 {
			continue
		}
		repeats := true
		for i := unit; i < n && repeats; i++ {
			if runes[i] != runes[i-unit] {
				repeats = false
			}
		}
		if repeats {
			return string(runes[:unit])
		}
	}
	return s
}

// blocklistDominanceDenominator sets how much of a password may be blocklisted content before it is
// refused: what REMAINS after stripping every blocklist word must be more than 1/3 of the original.
//
// The threshold is a deliberate calibration, not a round number. It has to catch the case this rule
// exists for — a banned word concatenated with itself, e.g. "passwordpassword1234" (20% remains) or
// "password1password1pa" (10%) — without rejecting a real password that merely STARTS with a common
// word. At the more aggressive "at least half" setting, "screenconnect-Rocks-2026!" (48% remains)
// was refused by a single character, which is exactly the false positive the module comment warns
// about: a substring ban on words this common rejects good passwords and pushes users toward worse
// ones. At 1/3 the doubled-word cases still fail by a wide margin and that password passes.
const blocklistDominanceDenominator = 3

// minOwnRunesBesideBlocklist is the length floor the user's OWN material must clear beside any
// amount of blocklisted padding: the policy's own MinLen.
func minOwnRunesBesideBlocklist(p PasswordPolicy) int {
	if p.MinLen > 0 {
		return p.MinLen
	}
	return DefaultPasswordPolicy.MinLen
}

// remainderStandsAlone reports whether what is left after stripping every blocklisted word would
// itself be an acceptable password's worth of material.
//
// This is the SECOND condition on the dominance rule, and it is what makes the rule defensible.
// Dominance alone is a ratio, so it tightens as the password gets LONGER — which inverts the
// policy's central claim that length is the load-bearing strength rule, and produced exactly the
// false positives the module comment warns about: a good password carrying one long common word
// ("administrator", "remotedesktop") refused on proportions while a shorter, weaker one passed.
//
// But "long enough" ALONE is not the right second condition, and a probe of the first version of
// this rule proved it by execution rather than by argument:
// `remotedesktop×3 + "123456123456"` was ACCEPTED while its own contributed material,
// "123456123456", is REFUSED on its own (a short unit repeated). Blocklist padding must not be able
// to launder a remainder that is not a password. So the remainder must clear the length floor AND
// the same low-entropy checks any password faces.
//
// The recursion terminates: the remainder has had every blocklist word stripped out of it, so
// mostlyCommonPassword finds no match on it and returns immediately.
func remainderStandsAlone(remainder string, p PasswordPolicy) bool {
	runes := []rune(remainder)
	if len(runes) < minOwnRunesBesideBlocklist(p) {
		return false
	}
	return len(checkLowEntropy(remainder, runes, p)) == 0
}

// mostlyCommonPassword reports whether blocklisted words dominate the password — so a banned value
// cannot slip through merely because the concatenation is not itself a list entry — AND the
// remainder is too short to stand as a password on its own (see minOwnRunesBesideBlocklist).
//
// It returns the LONGEST blocklist entry that actually appeared, so the rejection can name it
// instead of leaving the user to guess which of their substrings is on a list they cannot read.
func mostlyCommonPassword(lower string, p PasswordPolicy) (string, bool) {
	total := len([]rune(lower))
	if total == 0 {
		return "", false
	}
	stripped := lower
	longest := ""
	// Longest-first and from a SORTED slice: map iteration order is randomised in Go, and
	// overlapping entries ("password" ⊂ "password1") would otherwise make the verdict — and the
	// word named in the message — differ between runs on the same input.
	for _, w := range commonPasswordsByLengthDesc {
		if !strings.Contains(stripped, w) {
			continue
		}
		if longest == "" {
			longest = w // the slice is longest-first, so the first hit is the longest
		}
		stripped = strings.ReplaceAll(stripped, w, "")
	}
	if longest == "" {
		return "", false
	}
	dominates := len([]rune(stripped))*blocklistDominanceDenominator < total &&
		!remainderStandsAlone(stripped, p)
	return longest, dominates
}

// hasControlRune reports whether any rune is an ASCII/Unicode control character.
func hasControlRune(runes []rune) bool {
	for _, r := range runes {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// countClasses counts how many of {lower, upper, digit, other} appear. "other" covers punctuation,
// symbols, spaces, and any non-cased letter (CJK, for instance), so a non-Latin password is not
// silently held to an impossible standard.
func countClasses(runes []rune) int {
	var lower, upper, digit, other bool
	for _, r := range runes {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, present := range []bool{lower, upper, digit, other} {
		if present {
			n++
		}
	}
	return n
}

// echoesIdentity reports whether the (already lowercased) password contains the account's email,
// its local part, or a display-name token — each only when long enough to be distinctive.
func echoesIdentity(lowerPassword string, id PasswordIdentity) bool {
	for _, cand := range identityTokens(id) {
		if len(cand) >= minLocalPartMatchLen && strings.Contains(lowerPassword, cand) {
			return true
		}
	}
	return false
}

// identityTokens returns the lowercased strings a password must not embed: the full email, its
// local part, its domain label, and each whitespace-separated display-name token.
func identityTokens(id PasswordIdentity) []string {
	var out []string
	if email := strings.ToLower(strings.TrimSpace(id.Email)); email != "" {
		out = append(out, email)
		local, domain, found := strings.Cut(email, "@")
		if found {
			if local != "" {
				out = append(out, local)
			}
			// The registrable label only ("acme" from "acme.test"): banning the whole domain
			// would also ban the TLD, and "test"/"com" are too generic to forbid.
			if label, _, _ := strings.Cut(domain, "."); label != "" {
				out = append(out, label)
			}
		}
	}
	for _, tok := range strings.Fields(strings.ToLower(id.DisplayName)) {
		out = append(out, tok)
	}
	return out
}

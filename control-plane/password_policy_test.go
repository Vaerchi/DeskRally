package controlplane

import (
	"errors"
	"strings"
	"testing"
)

// acceptable passwords under DefaultPasswordPolicy, with the account identity they are used with.
func TestValidatePasswordAccepts(t *testing.T) {
	id := PasswordIdentity{Email: "tech@acme.test", DisplayName: "Dana Tech"}
	for _, pw := range []string{
		"Tr0ub4dor&3xyz",             // 14 runes, 4 classes
		"correct-Horse-9",            // lower + upper + digit + symbol
		"aB3xY9mK2pQ7",               // exactly MinLen (12), 3 classes, 12 distinct runes
		"the quick brown fox jumped", // 26 runes, only 2 classes → passphrase exemption
		"日本語のパスワードはとても長いのでこれで大丈夫です", // 23 runes, 1 class → passphrase exemption
		"Ünïcödé-Pässwörd-9", // accented, 4 classes
	} {
		if err := ValidatePassword(pw, id, DefaultPasswordPolicy); err != nil {
			t.Errorf("ValidatePassword(%q) = %v, want nil", pw, err)
		}
	}
}

// Each rejection case names the rule it is proving, and asserts on the REASON so a rule that
// silently stops firing (while some other rule still rejects the input) is caught.
func TestValidatePasswordRejects(t *testing.T) {
	id := PasswordIdentity{Email: "dana.tech@acme.test", DisplayName: "Dana Tech"}
	cases := []struct {
		name       string
		password   string
		wantReason string
	}{
		{"too short", "Ab3-short", "at least 12 characters"},
		{"empty", "", "at least 12 characters"},
		{"only two classes", "abcdefghijkl", "at least 3 of"},
		{"lower+digit only", "abcdefgh1234", "at least 3 of"},
		{"equals email", "dana.tech@acme.test", "email address or name"},
		{"contains email local part", "Xx-dana.tech-99", "email address or name"},
		{"contains domain label", "Bright-acme-2026", "email address or name"},
		{"contains display-name token", "quiet-Dana-1234", "email address or name"},
		{"common password", "password1234", "commonly used"},
		{"common password, mixed case", "Password1234", "commonly used"},
		{"control character", "Abc3\ndefghijk", "control characters"},
		{"tab", "Abc3\tdefghijk", "control characters"},
		{"over the byte cap", strings.Repeat("aA1!", 100), "at most 256 bytes"},
		{"invalid utf-8", "Abc123!\xff\xfe" + strings.Repeat("x", 8), "valid UTF-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.password, id, DefaultPasswordPolicy)
			if err == nil {
				t.Fatalf("ValidatePassword(%q) = nil, want rejection (%s)", tc.password, tc.wantReason)
			}
			var pe *PasswordPolicyError
			if !errors.As(err, &pe) {
				t.Fatalf("error type = %T, want *PasswordPolicyError", err)
			}
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Fatalf("reasons %v do not mention %q", pe.Reasons, tc.wantReason)
			}
			// The rejection must never quote the candidate back — these strings end up in logs
			// and client-side error toasts.
			if tc.password != "" && strings.Contains(err.Error(), tc.password) {
				t.Fatalf("error echoed the password: %q", err.Error())
			}
		})
	}
}

// REGRESSION (adversarial review, 2026-08-01). The passphrase exemption used to waive the class
// rule with nothing left to catch a long, zero-entropy string, and the blocklist only ever matched
// the WHOLE password. The policy therefore contradicted itself: it refused "aaaaaaaaaaaa" (a
// blocklist entry) and accepted "aaaaaaaaaaaaaaaaaaaa" — the same value, padded past the exemption
// length — and the class-rule message actively told users to pad. Every string below was CONFIRMED
// accepted by the pre-fix code.
func TestValidatePasswordRejectsPaddedLowEntropyStrings(t *testing.T) {
	id := PasswordIdentity{Email: "dana@acme.test", DisplayName: "Dana Scully"}
	cases := map[string]string{
		"repeated single character":  "aaaaaaaaaaaaaaaaaaaa",
		"two-character alternation":  "abababababababababab",
		"digit run repeated":         "12345678901234567890",
		"keyboard walk repeated":     "qwertyuiopqwertyuiop",
		"blocklisted word doubled":   "passwordpassword1234",
		"blocklisted word dominates": "password1password1pa",
		// Found by a review agent's probe: a SHORT unit repeated to reach the exemption length.
		// None of these is a blocklist entry and all clear the distinct-rune floor, so only the
		// "judge the repeating unit, not the padded result" rule catches them.
		"5-digit run repeated":       "12345123451234512345",
		"5-char mixed unit repeated": "aA1!baA1!baA1!baA1!b",
		"alphabet run doubled":       "abcdefghijabcdefghij",
	}
	for name, pw := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePassword(pw, id, DefaultPasswordPolicy); err == nil {
				t.Fatalf("ValidatePassword(%q) = nil; a padded low-entropy string must be rejected", pw)
			}
		})
	}

	// The self-contradiction itself: if the 12-rune form is refused, the padded form must be too.
	for _, short := range []string{"aaaaaaaaaaaa", "qwertyuiop", "1234567890"} {
		if err := ValidatePassword(short, id, DefaultPasswordPolicy); err == nil {
			t.Fatalf("test premise: %q should already be rejected", short)
		}
		padded := short + short
		if err := ValidatePassword(padded, id, DefaultPasswordPolicy); err == nil {
			t.Fatalf("%q is rejected but %q (itself, doubled) is accepted — the blocklist must not be "+
				"bypassable by self-concatenation", short, padded)
		}
	}

	// And the rejection message must not advertise the exemption as an escape hatch, or it steers
	// users straight into the region these rules exist to close.
	err := ValidatePassword("abcdefghijkl", id, DefaultPasswordPolicy) // 12 runes, 1 class
	if err == nil {
		t.Fatal("class-rule case should be rejected")
	}
	if strings.Contains(err.Error(), "at least 20 characters") {
		t.Fatalf("the class-rule message advertises the passphrase exemption: %q", err.Error())
	}
}

// The compensating checks must not swallow genuine passphrases — that would be the failure mode
// the module comment warns about (a substring ban rejecting good passwords).
func TestValidatePasswordStillAcceptsGenuinePassphrases(t *testing.T) {
	id := PasswordIdentity{Email: "dana@acme.test", DisplayName: "Dana Scully"}
	for _, pw := range []string{
		"the quick brown fox jumped", // long, low class count, high distinct-rune count
		"my password is a giraffe!",  // CONTAINS a blocklisted word but is not mostly one
		"Original-Passw0rd!",         // ditto, shorter
		"correct horse battery staple",
		// False positives a review agent's probe surfaced at the stricter "at least half"
		// blocklist-dominance threshold. Each merely STARTS with a common word and is otherwise a
		// fine password; refusing them would push users toward weaker choices.
		"screenconnect-Rocks-2026!",
		"MyScreenConnectAdmin1!",
		"Qwertyuiop-Zebra-42",
		"Tulips-1234567890!",
	} {
		if err := ValidatePassword(pw, id, DefaultPasswordPolicy); err != nil {
			t.Errorf("ValidatePassword(%q) = %v, want nil", pw, err)
		}
	}
}

// The dominance rule is a RATIO, so it tightens as a password gets longer — which inverts this
// policy's own central claim that length is the load-bearing strength rule. The property that
// fixes it: if a password is acceptable on its own, PREPENDING blocklisted padding to it cannot
// make it unacceptable. Nothing is lost, because the remainder alone already clears every rule the
// policy asks of a password with no padding at all.
func TestBlocklistPaddingCannotRejectAnAlreadyAcceptablePassword(t *testing.T) {
	id := PasswordIdentity{Email: "dana@acme.test", DisplayName: "Dana Scully"}
	// Each of these passes on its own (asserted below), and is long enough that heaping three
	// blocklisted words in front of it pushes the blocklist past 2/3 of the total.
	for _, own := range []string{"Kite9Zebra!!", "Tulip-Fjord-7", "correct horse battery staple"} {
		if err := ValidatePassword(own, id, DefaultPasswordPolicy); err != nil {
			t.Fatalf("test premise: ValidatePassword(%q) = %v, want nil", own, err)
		}
		padded := "remotesupport" + "remotedesktop" + "screenconnect" + own
		if err := ValidatePassword(padded, id, DefaultPasswordPolicy); err != nil {
			t.Errorf("ValidatePassword(%q) = %v — padding an acceptable password with common words "+
				"must not make it unacceptable", padded, err)
		}
	}
}

// The dominance rule keeps catching padded blocklist entries, and now says WHICH word it saw —
// "is mostly a commonly used password" was true but unactionable, since the user cannot read the
// blocklist and so could only guess at which substring offended.
func TestMostlyCommonPasswordNamesTheWordAndKeepsCatchingPadding(t *testing.T) {
	id := PasswordIdentity{Email: "dana@acme.test", DisplayName: "Dana Scully"}

	// Still refused: the user's own contribution is below the length floor, so what is left after
	// the blocklisted content would not be a password on its own.
	for _, pw := range []string{
		"passwordpassword1234",         // 4 own runes
		"password1password1pa",         // 2
		"administratoradministrator1!", // 2
		"screenconnectscreenconnect9!", // 2
		// Long enough own material, but the material is not a PASSWORD: "123456123456" is a short
		// unit repeated and is refused on its own. Blocklist padding must not launder it. Found by
		// probing the first version of this rule, which accepted exactly this string.
		"remotedesktopremotedesktopremotedesktop123456123456",
		"remotesupportremotesupportremotesupportaaaaaaaaaaaa",
	} {
		err := ValidatePassword(pw, id, DefaultPasswordPolicy)
		if err == nil {
			t.Fatalf("ValidatePassword(%q) = nil — padded blocklist content must still be refused", pw)
		}
	}

	// …and the message names the blocklisted word plus the amount of own material that would fix it.
	err := ValidatePassword("passwordpassword1234", id, DefaultPasswordPolicy)
	var pe *PasswordPolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v (%T), want *PasswordPolicyError", err, err)
	}
	joined := strings.Join(pe.Reasons, "; ")
	// The named word must be a real blocklist entry that really occurs in the password — the
	// longest one, which for "passwordpassword1234" is the 12-char "password1234", not "password".
	if !strings.Contains(joined, `"password1234"`) {
		t.Fatalf("the rejection does not name the longest blocklisted word it saw: %q", joined)
	}
	if !strings.Contains(joined, "12") {
		t.Fatalf("the rejection does not say how much own material is required: %q", joined)
	}

	// The named word is the LONGEST match and is stable across runs (Go randomises map order).
	for i := 0; i < 20; i++ {
		w, dominates := mostlyCommonPassword("password123password123", DefaultPasswordPolicy)
		if !dominates || w != "password123" {
			t.Fatalf("mostlyCommonPassword = (%q, %v), want (\"password123\", true) on every run", w, dominates)
		}
	}
}

func TestSmallestRepeatUnit(t *testing.T) {
	for in, want := range map[string]string{
		"abcabcabc": "abc",
		"aaaa":      "a",
		"abab":      "ab",
		"abcd":      "abcd", // not a repetition
		"abcabca":   "abcabca",
		"":          "",
		"日本日本":      "日本", // rune-aware, never splits a multi-byte character
	} {
		if got := smallestRepeatUnit(in); got != want {
			t.Errorf("smallestRepeatUnit(%q) = %q, want %q", in, got, want)
		}
	}
}

// A single submission reports EVERY unmet rule, so a client can show the whole list at once
// instead of making the user rediscover the policy one attempt at a time.
func TestValidatePasswordReportsAllReasons(t *testing.T) {
	err := ValidatePassword("dana", PasswordIdentity{Email: "dana@acme.test"}, DefaultPasswordPolicy)
	var pe *PasswordPolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v (%T), want *PasswordPolicyError", err, err)
	}
	if len(pe.Reasons) < 3 {
		t.Fatalf("reasons = %v, want at least 3 (length, classes, identity echo)", pe.Reasons)
	}
}

// The byte cap short-circuits: an oversized input returns exactly one reason and does not walk the
// string for the other rules. This is the DoS bound, so it must not itself do the expensive work.
func TestValidatePasswordByteCapShortCircuits(t *testing.T) {
	huge := strings.Repeat("a", DefaultPasswordPolicy.MaxLen+1) // also too-few-classes, also lowercase-only
	err := ValidatePassword(huge, PasswordIdentity{Email: "a@b.test"}, DefaultPasswordPolicy)
	var pe *PasswordPolicyError
	if !errors.As(err, &pe) || len(pe.Reasons) != 1 {
		t.Fatalf("err = %v, want exactly one (byte-cap) reason", err)
	}
	if !strings.Contains(pe.Reasons[0], "at most") {
		t.Fatalf("reason = %q, want the byte cap", pe.Reasons[0])
	}
	// Exactly at the cap is fine (the bound is inclusive). The repeating unit is 16 runes — at or
	// above MinLen — so it clears the "short unit repeated" rule; a shorter unit would (correctly)
	// trip it.
	atCap := strings.Repeat("aA1!bB2@cC3#dD4$", DefaultPasswordPolicy.MaxLen/16)
	if len(atCap) != DefaultPasswordPolicy.MaxLen {
		t.Fatalf("test setup: len = %d, want %d", len(atCap), DefaultPasswordPolicy.MaxLen)
	}
	if err := ValidatePassword(atCap, PasswordIdentity{Email: "a@b.test"}, DefaultPasswordPolicy); err != nil {
		t.Fatalf("password exactly at the cap rejected: %v", err)
	}
}

// MinLen counts RUNES, MaxLen counts BYTES — a multi-byte password must not be judged short by
// its rune count nor long by its byte count on the wrong axis.
func TestValidatePasswordLengthUnits(t *testing.T) {
	// 12 runes, 24 bytes: passes MinLen (runes) even though a byte count would also pass.
	twelveRunes := "ÄÖÜäöüßñçÉÈÀ"
	if n := len([]rune(twelveRunes)); n != 12 {
		t.Fatalf("test setup: %d runes, want 12", n)
	}
	if len(twelveRunes) == 12 {
		t.Fatal("test setup: expected a multi-byte string")
	}
	if err := ValidatePassword(twelveRunes+"1", PasswordIdentity{}, DefaultPasswordPolicy); err != nil {
		t.Fatalf("13-rune multibyte password rejected: %v", err)
	}
	// 100 runes of a 3-byte character = 300 bytes: over the BYTE cap even though the rune count
	// is comfortable. This is the bound that matters for the work the server does.
	if err := ValidatePassword(strings.Repeat("日", 100), PasswordIdentity{}, DefaultPasswordPolicy); err == nil {
		t.Fatal("300-byte password accepted; the byte cap must apply")
	}
}

// The identity rules must not fire on tokens too short to be distinctive, or the policy would
// reject unrelated strong passwords.
func TestValidatePasswordShortIdentityTokensIgnored(t *testing.T) {
	id := PasswordIdentity{Email: "jo@x.test", DisplayName: "Jo X"}
	// "jo", "x" are all below minLocalPartMatchLen — none may trigger the identity rule.
	if err := ValidatePassword("Enjoyable-Xylo-7", id, DefaultPasswordPolicy); err != nil {
		t.Fatalf("short identity tokens rejected a good password: %v", err)
	}
}

// The passphrase exemption waives the character-class rule, and only that rule.
func TestValidatePasswordPassphraseExemption(t *testing.T) {
	p := DefaultPasswordPolicy
	long := "many words all lowercase here" // 29 runes, 2 classes (lower + space)
	if len([]rune(long)) < p.PassphraseExemptLen {
		t.Fatalf("test setup: %d runes, want >= %d", len([]rune(long)), p.PassphraseExemptLen)
	}
	if err := ValidatePassword(long, PasswordIdentity{}, p); err != nil {
		t.Fatalf("long passphrase rejected: %v", err)
	}
	// The exemption does NOT waive the identity rule.
	if err := ValidatePassword(long+" dana.tech", PasswordIdentity{Email: "dana.tech@acme.test"}, p); err == nil {
		t.Fatal("passphrase exemption also waived the identity rule")
	}
	// With the exemption disabled, the same passphrase fails the class rule.
	noExempt := p
	noExempt.PassphraseExemptLen = 0
	if err := ValidatePassword(long, PasswordIdentity{}, noExempt); err == nil {
		t.Fatal("class rule not enforced when the exemption is disabled")
	}
}

// A single-script, non-cased password (CJK) can only ever reach ONE character class, so between
// MinLen and PassphraseExemptLen the class rule is unsatisfiable without mixing in Latin/digits —
// the passphrase exemption is its only route. This pins that documented trade-off so it is a
// deliberate property rather than something discovered by a user.
func TestValidatePasswordSingleScriptNeedsPassphraseLength(t *testing.T) {
	short := "日本語のパスワードです" // 11 runes: fails MinLen too
	if err := ValidatePassword(short, PasswordIdentity{}, DefaultPasswordPolicy); err == nil {
		t.Fatal("11-rune single-script password accepted")
	}
	mid := "日本語のパスワードはとても長いです" // 17 runes: long enough, but 1 class and below the exemption
	if n := len([]rune(mid)); n < DefaultPasswordPolicy.MinLen || n >= DefaultPasswordPolicy.PassphraseExemptLen {
		t.Fatalf("test setup: %d runes, want between %d and %d",
			n, DefaultPasswordPolicy.MinLen, DefaultPasswordPolicy.PassphraseExemptLen)
	}
	err := ValidatePassword(mid, PasswordIdentity{}, DefaultPasswordPolicy)
	if err == nil || !strings.Contains(err.Error(), "at least 3 of") {
		t.Fatalf("mid-length single-script password = %v, want the class rule to reject it", err)
	}
	// At the exemption length it is accepted.
	long := mid + "ね本当に長いです"
	if n := len([]rune(long)); n < DefaultPasswordPolicy.PassphraseExemptLen {
		t.Fatalf("test setup: %d runes, want >= %d", n, DefaultPasswordPolicy.PassphraseExemptLen)
	}
	if err := ValidatePassword(long, PasswordIdentity{}, DefaultPasswordPolicy); err != nil {
		t.Fatalf("single-script passphrase at the exemption length rejected: %v", err)
	}
}

// countClasses must treat non-cased scripts as the "other" class rather than as nothing, so a
// CJK password is not held to a standard its script cannot meet.
func TestCountClassesNonCasedScript(t *testing.T) {
	if n := countClasses([]rune("パスワード")); n != 1 {
		t.Fatalf("countClasses(katakana) = %d, want 1 (the 'other' class)", n)
	}
	if n := countClasses([]rune("パスワードAb3")); n != 4 {
		t.Fatalf("countClasses = %d, want 4", n)
	}
}

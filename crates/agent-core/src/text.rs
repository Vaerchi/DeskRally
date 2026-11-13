//! Making attacker-controlled text safe to **draw on the guest's screen**.
//!
//! # Why this is in agent-core and not in the Windows crate
//!
//! This rule started life in `rmt_agent_windows::uri` as `sanitize_reason`, guarding the one place
//! a remote party's text reached the guest's eyes: the consent dialog. The guest window
//! ([`crate::guest_ui`]) adds a second, larger such place — it renders the session banner AND every
//! chat line the technician sends, live, in a window on the guest's desktop.
//!
//! A second implementation over there would be exactly the drift this repo keeps re-finding, and
//! `agent-windows` depends on `agent-core` (never the reverse), so the shared rule has to live
//! **down here**. `uri::sanitize_reason` now delegates to [`sanitize_display`]: one implementation,
//! several call sites.
//!
//! # What "hostile" means
//!
//! Not "malicious content" — this is not a filter for rude words or shell metacharacters. It is
//! narrowly about characters that break the *rendering* of a line, so that what the guest reads is
//! not what was sent:
//!
//! * **Controls** — a newline inside a one-line banner pushes the rest out of view; a `\r` overwrites.
//! * **Bidi overrides** — `U+202E` RIGHT-TO-LEFT OVERRIDE reverses everything after it, which is how
//!   you make `support.evil.com` render as `moc.live.troppus`. On a banner whose entire job is to
//!   name the party that has control of the machine, that is the whole attack.
//! * **Zero-width and BOM** — text that is present, counted, and invisible.
//! * **Arabic letter mark** — `U+061C` is a bidi control that reorders neighbouring text.
//! * **Invisible operators and joiners** — `U+2060..=U+2064` (word joiner, function application,
//!   invisible times/separator/plus), `U+180E` Mongolian vowel separator and `U+034F` combining
//!   grapheme joiner: zero-width, so they hide inside a name without changing how it looks.
//! * **Deprecated format controls** — `U+2065..=U+206F` (reserved slot, bidi isolates, and the
//!   deprecated symmetric-swapping, Arabic-shaping and digit-shape controls), `U+180B..=U+180D`
//!   Mongolian free variation selectors, `U+1D173..=U+1D17A` musical beam/tie/slur/phrase and
//!   `U+1BCA0..=U+1BCA3` shorthand format controls: default-ignorable, no glyph, not whitespace.
//! * **Interlinear annotation anchors** — `U+FFF9..=U+FFFB`.
//! * **Unicode tag block** — `U+E0000..=U+E007F`, invisible characters that can smuggle hidden text.
//! * **Blank fillers** — `U+115F`/`U+1160`/`U+3164`/`U+FFA0` Hangul fillers, `U+17B4`/`U+17B5` Khmer
//!   inherent vowels and `U+2800` Braille blank: they draw as empty cells but are not Unicode
//!   whitespace, so `trim()` keeps them and a name made of them looks blank yet is non-empty.

/// True for characters that must never reach a surface the guest reads.
///
/// C0/C1 controls, the Unicode line/paragraph separators, the bidi controls and isolates (including
/// `U+061C`), the zero-width/BOM characters, the invisible joiners and operators (`U+2060..=U+2064`,
/// `U+180E`, `U+034F`), the interlinear annotation anchors (`U+FFF9..=U+FFFB`) and the Unicode tag
/// block (`U+E0000..=U+E007F`), and the blank-filler class: characters that render as empty space
/// but are not whitespace, so `trim()` would keep them (`U+115F`, `U+1160`, `U+3164`, `U+FFA0`,
/// `U+17B4`, `U+17B5`, `U+2800`). Also the deprecated format controls and reserved slot
/// (`U+2065..=U+206F`), the Mongolian free variation selectors (`U+180B..=U+180D`), the musical
/// format characters (`U+1D173..=U+1D17A`) and the shorthand format controls
/// (`U+1BCA0..=U+1BCA3`). Variation selectors (`U+FE00..=U+FE0F`) are deliberately NOT
/// included: emoji presentation needs them. See the module doc for why each one is here.
pub fn is_display_hostile(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{2028}' | '\u{2029}'                 // line / paragraph separator
            | '\u{200B}'..='\u{200F}'               // zero-width + LRM/RLM
            | '\u{202A}'..='\u{202E}'               // bidi embedding / override
            | '\u{2065}'..='\u{206F}'               // reserved slot, bidi isolates, deprecated format controls
            | '\u{FEFF}'                            // BOM / zero-width no-break space
            | '\u{061C}'                            // Arabic letter mark (bidi control)
            | '\u{2060}'..='\u{2064}'               // word joiner + invisible operators
            | '\u{180B}'..='\u{180E}'               // Mongolian free variation selectors + vowel separator
            | '\u{1D173}'..='\u{1D17A}'             // musical beam/tie/slur/phrase format characters
            | '\u{1BCA0}'..='\u{1BCA3}'             // shorthand format controls
            | '\u{FFF9}'..='\u{FFFB}'               // interlinear annotation anchors
            | '\u{034F}'                            // combining grapheme joiner
            | '\u{E0000}'..='\u{E007F}'             // tag characters
            | '\u{115F}' | '\u{1160}'               // Hangul choseong / jungseong filler
            | '\u{3164}' | '\u{FFA0}'               // Hangul filler / halfwidth Hangul filler
            | '\u{17B4}' | '\u{17B5}'               // Khmer inherent vowels (invisible)
            | '\u{2800}'                            // Braille pattern blank
        )
}

/// Make an arbitrary string safe to render: drop the display-hostile characters, trim, and cap the
/// result at `max_chars` **characters** (never bytes — a byte cap splits a codepoint).
///
/// **Idempotent by construction.** Sanitizing an already-sanitized string returns it unchanged,
/// which is what lets the same function be applied at a parsing boundary *and* again at the point
/// of rendering without the text creeping shorter on every pass. The truncation marker is included
/// in the cap for exactly that reason: the result is at most `max_chars`, so a second pass finds
/// nothing left to do.
///
/// `max_chars == 0` yields the empty string rather than panicking — a caller that computes a cap
/// from a window width can legitimately arrive at zero, and a panic drawn from a layout calculation
/// would take the agent down over a cosmetic bound.
pub fn sanitize_display(raw: &str, max_chars: usize) -> String {
    let cleaned: String = raw.chars().filter(|c| !is_display_hostile(*c)).collect();
    let trimmed = cleaned.trim();
    if max_chars == 0 {
        return String::new();
    }
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    // Truncate to max-1 and mark it, so the result is exactly `max_chars` characters and a second
    // pass through this function is a no-op.
    let head: String = trimmed.chars().take(max_chars - 1).collect();
    let mut out = head.trim_end().to_string();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_characters_that_rewrite_what_the_guest_reads() {
        // The bidi override is the load-bearing one: without it the host name in a banner can be
        // made to render backwards, so the banner names a different party than the one in control.
        assert_eq!(sanitize_display("support\u{202E}moc.live", 120), "supportmoc.live");
        assert_eq!(sanitize_display("a\nb\rc", 120), "abc", "a newline scrolls a banner");
        assert_eq!(sanitize_display("a\u{200B}b\u{FEFF}c", 120), "abc", "invisible but counted");
        assert_eq!(sanitize_display("a\u{2066}b\u{2069}c", 120), "abc", "bidi isolates");
        assert_eq!(sanitize_display("  padded  ", 120), "padded");
    }

    const NEWLY_HOSTILE: [char; 15] = [
        '\u{061C}',
        '\u{2060}', '\u{2064}',
        '\u{180E}',
        '\u{FFF9}', '\u{FFFB}',
        '\u{034F}',
        '\u{E0000}', '\u{E007F}',
        // interior points, so a range typo that only covers its ends still fails
        '\u{2061}', '\u{2062}', '\u{2063}', '\u{FFFA}', '\u{E0041}', '\u{E0020}',
    ];

    #[test]
    fn invisible_format_characters_are_hostile_and_stripped() {
        for c in NEWLY_HOSTILE {
            assert!(is_display_hostile(c), "U+{:04X} must be hostile", c as u32);
            let raw = format!("a{c}b");
            assert_eq!(sanitize_display(&raw, 120), "ab", "U+{:04X} must be stripped", c as u32);
        }
    }

    #[test]
    fn hidden_tag_and_word_joiner_text_cannot_ride_inside_a_banner() {
        assert_eq!(
            sanitize_display("support\u{2060}.evil\u{E0041}.com", 120),
            "support.evil.com"
        );
    }

    #[test]
    fn ordinary_text_and_neighbouring_code_points_are_not_newly_rejected() {
        for s in ["Zo\u{00eb}", "\u{65e5}\u{672c}\u{8a9e}", "\u{05e9}\u{05dc}\u{05d5}\u{05dd}",
                  "\u{0645}\u{0631}\u{062d}\u{0628}\u{0627}", "\u{1F600}", "a\u{00AD}b"] {
            assert_eq!(sanitize_display(s, 120), s, "legitimate text must survive: {s:?}");
        }
        // Specification conflict, resolved explicitly: this test previously asserted that U+2065
        // and U+180D were NOT flagged. The task classifies both as hostile (reserved default-ignorable
        // slot; Mongolian free variation selector), so those two negative expectations are replaced
        // here by the opposite, positive assertions rather than silently dropped.
        for c in ['\u{2065}', '\u{180D}'] {
            assert!(is_display_hostile(c), "U+{:04X} is now deliberately hostile", c as u32);
            assert_eq!(sanitize_display(&format!("a{c}b"), 120), "ab");
        }
        for c in ['\u{205F}', '\u{E0080}', '\u{2005}', '\u{061B}', '\u{061D}',
                  '\u{180F}', '\u{034E}', '\u{0350}', '\u{FFF8}', '\u{FFFC}'] {
            assert!(!is_display_hostile(c), "U+{:04X} must not be flagged", c as u32);
        }
        assert!(!is_display_hostile('\u{00AD}'));
    }

    #[test]
    fn sanitizing_is_idempotent_over_the_new_characters() {
        let table = [
            "support\u{2060}.evil\u{E0041}.com",
            "\u{061C}abc\u{034F}\u{180E}",
            "\u{FFF9}x\u{FFFA}y\u{FFFB}",
            "\u{E0000}\u{E007F}",
            "ok text \u{2061}\u{2062}\u{2063}\u{2064}",
        ];
        for s in table {
            let once = sanitize_display(s, 120);
            assert_eq!(sanitize_display(&once, 120), once, "not idempotent for {s:?}");
        }
        let long = format!("{}\u{2060}", "y".repeat(300));
        let once = sanitize_display(&long, 50);
        assert_eq!(sanitize_display(&once, 50), once);
    }

    const DEPRECATED_FORMAT: [char; 20] = [
        '\u{2065}', '\u{206A}', '\u{206F}',
        '\u{180B}', '\u{180C}', '\u{180D}',
        '\u{1D173}', '\u{1D17A}',
        '\u{1BCA0}', '\u{1BCA3}',
        // interior points, so a range typo that only covers its ends still fails
        '\u{206B}', '\u{206C}', '\u{206D}', '\u{206E}',
        '\u{1D174}', '\u{1D175}', '\u{1D178}', '\u{1D179}',
        '\u{1BCA1}', '\u{1BCA2}',
    ];

    #[test]
    fn deprecated_format_and_mongolian_selectors_are_hostile_and_stripped() {
        for c in DEPRECATED_FORMAT {
            assert!(is_display_hostile(c), "U+{:04X} must be hostile", c as u32);
            let raw = format!("a{c}b");
            assert_eq!(sanitize_display(&raw, 120), "ab", "U+{:04X} must be stripped", c as u32);
        }
    }

    #[test]
    fn a_string_of_only_deprecated_format_controls_is_empty() {
        let raw: String = ('\u{206A}'..='\u{206F}').collect();
        assert_eq!(sanitize_display(&raw, 120), "");
    }

    #[test]
    fn deprecated_format_controls_cannot_hide_inside_a_name() {
        assert_eq!(sanitize_display("Alice\u{206E}Support", 120), "AliceSupport");
    }

    #[test]
    fn neighbours_of_the_deprecated_format_ranges_are_not_flagged() {
        for c in ['\u{205F}', '\u{2070}', '\u{180A}', '\u{180F}', '\u{1D15E}', '\u{1D172}',
                  '\u{1D17B}', '\u{1BC9F}', '\u{1BCA4}', '\u{FE00}', '\u{FE0F}', '\u{00AD}'] {
            assert!(!is_display_hostile(c), "U+{:04X} must not be flagged", c as u32);
            let raw = format!("a{c}b");
            assert_eq!(sanitize_display(&raw, 120), raw, "U+{:04X} must survive", c as u32);
        }
    }

    #[test]
    fn sanitizing_is_idempotent_over_the_deprecated_format_characters() {
        let table = [
            "Alice\u{206E}Support",
            "\u{206A}\u{206B}\u{206C}\u{206D}\u{206E}\u{206F}",
            "\u{180B}x\u{180C}y\u{180D}",
            "a\u{1D173}b\u{1D17A}c\u{1BCA0}d\u{1BCA3}",
            "\u{2065}ok\u{2070}",
        ];
        for s in table {
            let once = sanitize_display(s, 120);
            assert_eq!(sanitize_display(&once, 120), once, "not idempotent for {s:?}");
        }
    }

    const BLANK_FILLERS: [char; 7] = [
        '\u{115F}', '\u{1160}', '\u{3164}', '\u{FFA0}', '\u{17B4}', '\u{17B5}', '\u{2800}',
    ];

    #[test]
    fn blank_filler_characters_are_hostile_and_stripped() {
        for c in BLANK_FILLERS {
            assert!(is_display_hostile(c), "U+{:04X} must be hostile", c as u32);
            let raw = format!("a{c}b");
            assert_eq!(sanitize_display(&raw, 120), "ab", "U+{:04X} must be stripped", c as u32);
        }
    }

    #[test]
    fn a_name_made_only_of_blank_fillers_is_empty() {
        for c in ['\u{3164}', '\u{2800}', '\u{FFA0}'] {
            let raw = c.to_string().repeat(5);
            assert_eq!(sanitize_display(&raw, 120), "", "U+{:04X} only", c as u32);
        }
        assert_eq!(sanitize_display(" \u{3164} \u{2800} ", 120), "");
    }

    #[test]
    fn blank_fillers_cannot_pad_gaps_inside_a_name() {
        assert_eq!(
            sanitize_display("Alice\u{3164}\u{3164}\u{3164}Support", 120),
            "AliceSupport"
        );
    }

    #[test]
    fn real_hangul_braille_emoji_and_neighbours_are_not_flagged() {
        for c in ['\u{AC00}', '\u{1100}', '\u{1161}', '\u{2801}', '\u{FE0F}', '\u{17B6}',
                  '\u{115E}', '\u{3165}', '\u{FF9F}', '\u{FFA1}'] {
            assert!(!is_display_hostile(c), "U+{:04X} must not be flagged", c as u32);
        }
        let emoji = "\u{2764}\u{FE0F}";
        assert_eq!(sanitize_display(emoji, 120), emoji, "emoji presentation selector survives");
        for s in ["\u{AC00}\u{1100}\u{1161}", "\u{2801}", "\u{17B6}"] {
            assert_eq!(sanitize_display(s, 120), s);
        }
    }

    #[test]
    fn sanitizing_is_idempotent_over_the_blank_fillers() {
        let table = [
            "\u{3164}",
            "Alice\u{3164}\u{3164}Support",
            "\u{115F}\u{1160}x\u{FFA0}",
            "\u{17B4}a\u{17B5}\u{2800}b",
            "\u{2800}\u{2801}\u{2800}",
        ];
        for s in table {
            let once = sanitize_display(s, 120);
            assert_eq!(sanitize_display(&once, 120), once, "not idempotent for {s:?}");
        }
    }

    #[test]
    fn leaves_ordinary_text_including_non_latin_alone() {
        for s in ["Alice from IT", "ヘルプデスク", "Служба поддержки", "café ☕", "a-b_c.d:1234"] {
            assert_eq!(sanitize_display(s, 120), s, "sanitizing must not mangle legitimate text");
        }
    }

    #[test]
    fn truncation_is_idempotent_and_respects_the_cap_exactly() {
        let long = "x".repeat(500);
        let once = sanitize_display(&long, 120);
        assert_eq!(once.chars().count(), 120, "the marker is inside the cap, not added to it");
        assert!(once.ends_with('…'));
        let twice = sanitize_display(&once, 120);
        assert_eq!(once, twice, "a second pass must be a no-op, or text creeps shorter every render");
    }

    #[test]
    fn truncation_counts_characters_so_it_never_splits_a_codepoint() {
        // Every char here is 4 bytes; a byte-based cap would slice one in half and produce a string
        // that cannot be rendered at all.
        let emoji = "🙂".repeat(50);
        let out = sanitize_display(&emoji, 10);
        assert_eq!(out.chars().count(), 10);
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn a_zero_cap_is_empty_rather_than_a_panic() {
        // A cap computed from a window width can legitimately be zero; `max_chars - 1` would
        // underflow and panic in debug, taking the agent down over a layout calculation.
        assert_eq!(sanitize_display("anything at all", 0), "");
    }

    #[test]
    fn a_string_that_is_entirely_hostile_becomes_empty_not_a_marker() {
        // Truncation must not manufacture visible output from input that had none.
        assert_eq!(sanitize_display("\u{202E}\u{200B}\u{FEFF}", 120), "");
    }

    #[test]
    fn trim_end_removes_trailing_space_before_ellipsis() {
        // Arrange a string where the (max_chars-1)th character taken for the head is a space, so
        // trim_end() on the head has real work to do.
        //
        // With max=10, take(9) reads indices 0..=8.  We place a space at index 8 and extend the
        // string to 11 chars so truncation is triggered.
        //
        //   indices:  0 1 2 3 4 5 6 7  8   9 10
        //   chars:    x x x x x x x x ' ' x  x
        //
        // Without trim_end() the head is "xxxxxxxx " and the output would be "xxxxxxxx …",
        // which contains " …" (space immediately before the marker).
        let max = 10usize;
        let raw = format!("{} xx", "x".repeat(max - 2)); // 8 x's + ' ' + "xx" = 11 chars
        let out = sanitize_display(&raw, max);
        assert!(
            out.ends_with('…'),
            "truncated output must end with the ellipsis marker; got: {:?}",
            out
        );
        assert!(
            !out.contains(" \u{2026}"),
            "the ellipsis marker must never follow a space; got: {:?}",
            out
        );
    }
}

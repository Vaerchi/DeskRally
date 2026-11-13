package controlplane

// Strict JSON decoding for bodies whose bytes are stored and hashed exactly as submitted (the toolbox
// script body). encoding/json REPLACES malformed UTF-8 and unpaired \uD800-\uDFFF escapes with U+FFFD
// while decoding, so a check on the decoded string can never see them: what was submitted would be
// silently changed, stored, hashed and audited as something else. These checks run on the RAW bytes
// first, and refuse.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"unicode/utf8"
)

var errStrictJSONText = errors.New("the request contains invalid UTF-8 or an unpaired surrogate escape")

// jsonTextIsStrict reports whether raw is valid UTF-8 and every \uXXXX escape that encodes a UTF-16
// surrogate is part of a correctly ordered high+low pair. It does not validate JSON syntax (the
// decoder does that); it only rejects what the decoder would otherwise replace.
func jsonTextIsStrict(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	hex4 := func(b []byte) (rune, bool) {
		if len(b) < 4 {
			return 0, false
		}
		var r rune
		for _, c := range b[:4] {
			r <<= 4
			switch {
			case c >= '0' && c <= '9':
				r |= rune(c - '0')
			case c >= 'a' && c <= 'f':
				r |= rune(c-'a') + 10
			case c >= 'A' && c <= 'F':
				r |= rune(c-'A') + 10
			default:
				return 0, false
			}
		}
		return r, true
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			return true // malformed JSON; the decoder reports it
		}
		if raw[i+1] != 'u' {
			i++ // a two-character escape such as \\ or \"; skip it whole
			continue
		}
		r, ok := hex4(raw[i+2:])
		if !ok {
			return true // malformed escape; the decoder reports it
		}
		switch {
		case r >= 0xD800 && r <= 0xDBFF: // high surrogate: must be followed by \u + low surrogate
			if i+12 > len(raw) { // a pair is exactly 12 bytes: 😀
				return false
			}
			if raw[i+6] != '\\' || raw[i+7] != 'u' {
				return false
			}
			lo, ok := hex4(raw[i+8:])
			if !ok || lo < 0xDC00 || lo > 0xDFFF {
				return false
			}
			i += 11
		case r >= 0xDC00 && r <= 0xDFFF: // a low surrogate on its own
			return false
		default:
			i += 5
		}
	}
	return true
}

// decodeStrictJSONBody is decodeJSONBodyDetailed with the raw-text check above: 413 over maxBytes,
// 400 for text the decoder would have altered, 400 with the decoder's detail for malformed JSON.
func decodeStrictJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any, badRequestPrefix string) error {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		if !writeIfBodyTooLarge(w, err) {
			writeError(w, http.StatusBadRequest, badRequestPrefix+": "+err.Error())
		}
		return err
	}
	if !jsonTextIsStrict(raw) {
		writeError(w, http.StatusBadRequest, errStrictJSONText.Error())
		return errStrictJSONText
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		writeError(w, http.StatusBadRequest, badRequestPrefix+": "+err.Error())
		return err
	}
	return nil
}

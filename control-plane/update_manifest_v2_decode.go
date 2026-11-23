package controlplane

// The strict wire decoder for the format-2 update manifest. Its Rust twin is serde_json into
// `SignedUpdateManifestV2` (`#[serde(deny_unknown_fields)]` at every level, plus `from_json`'s
// format check). encoding/json cannot be made to agree with that: it matches field names
// case-insensitively, keeps the last of a duplicated key, and turns a missing or null field into a
// zero value, so a file the agent refuses could print OK in the offline verifier. This decoder
// accepts exactly one shape and refuses everything else, so "the verifier said OK" can stand for
// "an agent will read this".
//
// It is a deliberately tiny parser for a closed grammar (objects of known keys, strings, integers),
// not a general JSON reader, so every rule below is visible rather than inherited:
//   - keys match byte-for-byte; an unknown key, a case variant, or a repeated key is an error;
//   - every key is required, at every level, and no value may be null (or of any other type);
//   - integers are plain JSON integers (no fraction, no exponent) that fit their Go type;
//   - strings are valid UTF-8 with JSON escapes only; a lone surrogate escape is refused (as
//     serde_json does) rather than replaced with U+FFFD, which would change the signed bytes;
//   - `format` must be 2, and nothing but whitespace may follow the top-level value.

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// DecodeSignedUpdateManifestV2 decodes the wire JSON of a format-2 manifest, strictly. It does not
// verify anything: signature, window and field shapes are VerifyUpdateManifestV2's job.
func DecodeSignedUpdateManifestV2(raw []byte) (SignedUpdateManifestV2, error) {
	var m SignedUpdateManifestV2
	if !utf8.Valid(raw) {
		return m, errors.New("manifest is not valid UTF-8")
	}
	p := &strictJSON{b: raw}
	var format int64
	err := p.object([]string{"format", "claims", "sig"}, func(key string) error {
		var err error
		switch key {
		case "format":
			format, err = p.integer()
		case "claims":
			err = p.object([]string{"release", "issued_at_ms", "expires_at_ms"}, func(key string) error {
				var err error
				switch key {
				case "release":
					err = p.release(&m.Claims.Release)
				case "issued_at_ms":
					m.Claims.IssuedAtMs, err = p.integer()
				case "expires_at_ms":
					m.Claims.ExpiresAtMs, err = p.integer()
				}
				return err
			})
		case "sig":
			m.Sig, err = p.str()
		}
		return err
	})
	if err != nil {
		return SignedUpdateManifestV2{}, err
	}
	p.skipSpace()
	if p.i != len(p.b) {
		return SignedUpdateManifestV2{}, p.errf("trailing data after the manifest")
	}
	if format != UpdateManifestFormatV2 {
		return SignedUpdateManifestV2{}, fmt.Errorf("format %d is not supported here (expected %d)", format, UpdateManifestFormatV2)
	}
	m.Format = UpdateManifestFormatV2
	return m, nil
}

type strictJSON struct {
	b []byte
	i int
	// what names the document in error messages; empty means "manifest". The deployment-pass
	// decoder (deployment_pass.go) reuses this grammar for its envelope and bodies.
	what string
}

func (p *strictJSON) name() string {
	if p.what == "" {
		return "manifest"
	}
	return p.what
}

func (p *strictJSON) errf(format string, a ...any) error {
	return fmt.Errorf("%s JSON at byte %d: %s", p.name(), p.i, fmt.Sprintf(format, a...))
}

func (p *strictJSON) skipSpace() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

// release decodes the eight string fields of ReleaseBodyV2.
func (p *strictJSON) release(r *ReleaseBodyV2) error {
	dst := map[string]*string{
		"ring": &r.Ring, "version": &r.Version, "msi_sha256": &r.MSISHA256, "msi_url": &r.MSIURL,
		"product_version": &r.ProductVersion, "product_code": &r.ProductCode,
		"upgrade_code": &r.UpgradeCode, "min_upgradable_from": &r.MinUpgradableFrom,
	}
	keys := []string{"ring", "version", "msi_sha256", "msi_url", "product_version", "product_code", "upgrade_code", "min_upgradable_from"}
	return p.object(keys, func(key string) (err error) {
		*dst[key], err = p.str()
		return err
	})
}

// object parses `{...}`, calling field(key) positioned at each value. Each key in `required` must
// appear exactly once and nothing else may appear.
func (p *strictJSON) object(required []string, field func(key string) error) error {
	p.skipSpace()
	if p.i >= len(p.b) || p.b[p.i] != '{' {
		return p.errf("expected an object")
	}
	p.i++
	seen := make(map[string]bool, len(required))
	for first := true; ; first = false {
		p.skipSpace()
		if p.i >= len(p.b) {
			return p.errf("unexpected end of input")
		}
		if p.b[p.i] == '}' && first {
			p.i++
			break
		}
		if !first {
			if p.b[p.i] == '}' {
				p.i++
				break
			}
			if p.b[p.i] != ',' {
				return p.errf("expected ',' or '}'")
			}
			p.i++
			p.skipSpace()
		}
		key, err := p.str()
		if err != nil {
			return err
		}
		known := false
		for _, k := range required {
			if k == key {
				known = true
			}
		}
		if !known {
			return p.errf("unknown field %q", key)
		}
		if seen[key] {
			return p.errf("duplicate field %q", key)
		}
		seen[key] = true
		p.skipSpace()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return p.errf("expected ':' after %q", key)
		}
		p.i++
		p.skipSpace()
		if err := field(key); err != nil {
			return err
		}
	}
	for _, k := range required {
		if !seen[k] {
			return fmt.Errorf("%s JSON: missing field %q", p.name(), k)
		}
	}
	return nil
}

// integer parses a JSON integer: -?(0|[1-9][0-9]*), no fraction or exponent, fitting int64.
func (p *strictJSON) integer() (int64, error) {
	start := p.i
	if p.i < len(p.b) && p.b[p.i] == '-' {
		p.i++
	}
	digits := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	n := p.i - digits
	if n == 0 || (n > 1 && p.b[digits] == '0') {
		p.i = start
		return 0, p.errf("expected an integer")
	}
	// serde_json reads -0 as a FLOAT and refuses it for an i64 field, so the agent would reject
	// the manifest; accepting it here would let the offline verifier pass what agents refuse.
	if digits > start && n == 1 && p.b[digits] == '0' {
		p.i = start
		return 0, p.errf("negative zero is not an integer")
	}
	if p.i < len(p.b) {
		switch p.b[p.i] {
		case '.', 'e', 'E':
			p.i = start
			return 0, p.errf("expected an integer, not a fraction or exponent")
		}
	}
	v, err := strconv.ParseInt(string(p.b[start:p.i]), 10, 64)
	if err != nil {
		p.i = start
		return 0, p.errf("integer out of range")
	}
	return v, nil
}

// str parses a JSON string literal.
func (p *strictJSON) str() (string, error) {
	if p.i >= len(p.b) || p.b[p.i] != '"' {
		return "", p.errf("expected a string")
	}
	p.i++
	var out []byte
	for {
		if p.i >= len(p.b) {
			return "", p.errf("unterminated string")
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), nil
		case c < 0x20:
			return "", p.errf("control character in string")
		case c != '\\':
			out = append(out, c)
			p.i++
			continue
		}
		p.i++
		if p.i >= len(p.b) {
			return "", p.errf("unterminated string")
		}
		e := p.b[p.i]
		p.i++
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, err := p.hex4()
			if err != nil {
				return "", err
			}
			if utf16.IsSurrogate(r) {
				// Only a high surrogate immediately followed by a \u low surrogate is a character.
				if r >= 0xDC00 || p.i+1 >= len(p.b) || p.b[p.i] != '\\' || p.b[p.i+1] != 'u' {
					return "", p.errf("lone surrogate escape")
				}
				p.i += 2
				lo, err := p.hex4()
				if err != nil {
					return "", err
				}
				r = utf16.DecodeRune(r, lo)
				if r == utf8.RuneError {
					return "", p.errf("lone surrogate escape")
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return "", p.errf("invalid escape")
		}
	}
}

func (p *strictJSON) hex4() (rune, error) {
	if p.i+4 > len(p.b) {
		return 0, p.errf("short \\u escape")
	}
	var r rune
	for _, c := range p.b[p.i : p.i+4] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, p.errf("bad \\u escape")
		}
	}
	p.i += 4
	return r, nil
}

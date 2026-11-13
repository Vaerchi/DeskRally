/**
 * The Owner editor's inline validation of the PUBLIC join-page fields: a port of control-plane/brandtext.go
 * (docs/66 2.2, 2a.7, 2h). It exists so a typo is caught while typing; the SERVER stays the authority and the editor
 * shows the server's own refusal text when the two disagree (a Unicode table can differ between Go and the browser, for
 * one). `brand_text.test.ts` runs the shared vectors in `control-plane/testdata/brand_text_vectors.json` through both.
 *
 * Every normaliser returns the canonical string the server would store, or the refusal sentence (the server's words).
 */

import { BRAND_NAME_MAX, BRAND_NAME_MIN, BRAND_TEXT_MAX, BRAND_TEXT_MAX_LINES, BRAND_CONTACT_MAX, type BrandContactKind } from "./host_branding";
import { checkAccentContrast } from "./brand_contrast";

export type Normalized = { ok: true; value: string } | { ok: false; error: string };

const ok = (value: string): Normalized => ({ ok: true, value });
const refuse = (error: string): Normalized => ({ ok: false, error });

const NAME_MAX_CELLS = 120;
const TEXT_MAX_CELLS = 400;
const MAX_MARKS_IN_A_ROW = 3;
const NAME_MAX_MARKS = 8;
const TEXT_MAX_MARKS = 24;
const MAX_IDENTICAL_RUN = 4;

const CATEGORY_C = /^\p{C}$/u; // Cc, Cf, Cs, Co and Cn (unassigned)
const MARK = /^\p{M}$/u;
const SPACE_SEPARATOR = /^\p{Zs}$/u;
const LETTER_OR_NUMBER = /^[\p{L}\p{N}]$/u;

/** East Asian wide and emoji count double, combining marks nothing (brandtext.go `cellWidth`). */
function cellWidth(ch: string): number {
  if (MARK.test(ch)) return 0;
  const r = ch.codePointAt(0)!;
  if (
    (r >= 0x1100 && r <= 0x115f) || (r >= 0x2e80 && r <= 0xa4cf) || (r >= 0xac00 && r <= 0xd7a3) ||
    (r >= 0xf900 && r <= 0xfaff) || (r >= 0xfe30 && r <= 0xfe6f) || (r >= 0xff00 && r <= 0xff60) ||
    (r >= 0xffe0 && r <= 0xffe6) || (r >= 0x1f300 && r <= 0x1faff) || (r >= 0x20000 && r <= 0x3fffd)
  ) {
    return 2;
  }
  return 1;
}

function estimateCells(s: string): number {
  let n = 0;
  for (const ch of s) n += cellWidth(ch);
  return n;
}

const hex4 = (r: number) => r.toString(16).toUpperCase().padStart(4, "0");

interface TextRules {
  multiline: boolean;
  minRunes: number;
  maxRunes: number;
  maxLines: number;
  maxCells: number;
  maxMarks: number;
  needAlnum: boolean;
  allowNone: boolean;
}

/** Trim like Go's strings.TrimSpace on what survives the loop below (only ASCII space and newline are left). */
const trim = (s: string) => s.replace(/^[ \n]+|[ \n]+$/g, "");

function normalizeText(input: string, o: TextRules): Normalized {
  if (/\p{Cs}/u.test(input)) return refuse("must be valid UTF-8 text"); // a lone surrogate has no UTF-8 form
  let s = input.normalize("NFC");
  if (o.multiline) s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  let out = "";
  let prevSpace = false;
  let run = 0;
  let marksRow = 0;
  let marks = 0;
  let prev = "";
  let alnum = false;
  for (const ch of s) {
    const r = ch.codePointAt(0)!;
    if (ch === "\n" && o.multiline) {
      out += ch;
      prevSpace = false;
      run = 0;
      marksRow = 0;
      prev = "";
      continue;
    }
    if (r === 0xfffd || CATEGORY_C.test(ch) || r === 0x2028 || r === 0x2029) {
      return refuse(`contains a control, formatting (bidirectional or zero-width), private-use or unassigned character (U+${hex4(r)})`);
    }
    if (SPACE_SEPARATOR.test(ch)) {
      if (!prevSpace) out += " ";
      prevSpace = true;
      prev = " ";
      run = 0;
      marksRow = 0;
      continue;
    }
    prevSpace = false;
    if (ch === prev) {
      run++;
      if (run >= MAX_IDENTICAL_RUN + 1) return refuse(`repeats one character more than ${MAX_IDENTICAL_RUN} times in a row`);
    } else {
      prev = ch;
      run = 1;
    }
    if (MARK.test(ch)) {
      marksRow++;
      marks++;
      if (marksRow > MAX_MARKS_IN_A_ROW || marks > o.maxMarks) {
        return refuse(`has too many combining marks (at most ${MAX_MARKS_IN_A_ROW} in a row, ${o.maxMarks} in all)`);
      }
    } else {
      marksRow = 0;
    }
    if (LETTER_OR_NUMBER.test(ch)) alnum = true;
    out += ch;
  }
  let lines = 1;
  if (o.multiline) {
    out = trim(out.split("\n").map(trim).join("\n"));
    lines = out === "" ? 0 : out.split("\n").length;
  } else {
    out = trim(out);
  }
  if (out === "" && o.allowNone) return ok("");
  const runes = [...out].length;
  if (runes < o.minRunes || runes > o.maxRunes) return refuse(`must be ${o.minRunes} to ${o.maxRunes} characters`);
  if (o.multiline && lines > o.maxLines) return refuse(`must be at most ${o.maxLines} lines`);
  if (o.needAlnum && !alnum) return refuse("must contain a letter or digit");
  const cells = estimateCells(out);
  if (cells > o.maxCells) return refuse(`is too wide to display (estimated ${cells} cells, at most ${o.maxCells})`);
  return ok(out);
}

/** 3 to 100 characters, a letter or digit, one line. */
export function normalizeBrandName(s: string): Normalized {
  return normalizeText(s, { multiline: false, minRunes: BRAND_NAME_MIN, maxRunes: BRAND_NAME_MAX, maxLines: 1, maxCells: NAME_MAX_CELLS, maxMarks: NAME_MAX_MARKS, needAlnum: true, allowNone: false });
}

/** Empty, or up to 280 characters over at most 4 lines. */
export function normalizeBrandSupportText(s: string): Normalized {
  return normalizeText(s, { multiline: true, minRunes: 0, maxRunes: BRAND_TEXT_MAX, maxLines: BRAND_TEXT_MAX_LINES, maxCells: TEXT_MAX_CELLS, maxMarks: TEXT_MAX_MARKS, needAlnum: false, allowNone: true });
}

/** What the live counter shows: code points of the text as typed, with CRLF counted as one line break. */
export function supportTextCounts(s: string): { runes: number; lines: number } {
  const t = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return { runes: [...t].length, lines: t === "" ? 0 : t.split("\n").length };
}

/** Empty (the theme's own colour) or `#rrggbb`, lowercased, passing both contrast gates. */
export function normalizeBrandAccent(s: string): Normalized {
  const a = s.trim().toLowerCase();
  if (a === "") return ok("");
  if (!/^#[0-9a-f]{6}$/.test(a)) return refuse("must be empty or a #rrggbb hex colour");
  const c = checkAccentContrast(a);
  return c.failure !== null ? refuse(c.failure) : ok(a);
}

// ---- support contact -------------------------------------------------------------------------------------

export interface ContactInput {
  kind: BrandContactKind | "";
  value: string;
}

export type NormalizedContact = { ok: true; value: { kind: BrandContactKind | ""; value: string } } | { ok: false; error: string };

const EMAIL_LOCAL = /^[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_{|}~-]+)*$/;
const HOSTNAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** hostpolicy.go `NormalizeAuthority` (a contact host never carries a port; the caller refuses ":" first). */
function normalizeAuthority(raw: string): string | null {
  if (raw === "" || raw.length > 260) return null;
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c <= 0x20 || c >= 0x7f || "/\\@[]?#%".includes(raw[i]!)) return null;
  }
  let host = raw;
  const colon = raw.indexOf(":");
  if (colon >= 0) {
    if (raw.split(":").length !== 2 || raw.slice(colon + 1) !== "443") return null;
    host = raw.slice(0, colon);
  }
  if (host.endsWith(".")) {
    host = host.slice(0, -1);
    if (host.endsWith(".")) return null;
  }
  host = host.toLowerCase();
  if (host.length === 0 || host.length > 253 || !HOSTNAME.test(host)) return null;
  if (/^[0-9]+$/.test(host.slice(host.lastIndexOf(".") + 1))) return null; // a numeric last label: an IP spelling
  return host;
}

/** brandtext.go `canonicalPhone`: 5 to 15 digits; spaces, dashes, dots, a leading + and ONE balanced pair of parentheses are dropped. */
function canonicalPhone(input: string): string | null {
  if (input.length > 40) return null;
  let digits = "";
  let open = false;
  let closed = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    if (ch >= "0" && ch <= "9") digits += ch;
    else if (ch === " " || ch === "-" || ch === ".") continue;
    else if (ch === "+" && i === 0) continue;
    else if (ch === "(" && !open && !closed) open = true;
    else if (ch === ")" && open && !closed) closed = true;
    else return null;
  }
  if (open !== closed || digits.length < 5 || digits.length > 15) return null;
  return digits;
}

// ---- Go's url.Parse / URL.String for an https contact (net/url, Go 1.26) --------------------------------------
// brandtext.go parses the contact with url.Parse and stores u.String(). A string Go refuses must be refused here with the
// same sentence, and an accepted one must serialise the same way (paths re-encoded, a query kept byte for byte). Only what
// the earlier checks leave possible is mirrored: printable ASCII, no space or backslash, an https:// prefix.

const URL_PLAIN_REFUSAL = "must be a plain https URL on a public host (no user-info, no fragment)";
const URL_HOST_REFUSAL = "must name a public DNS host (no port, no IP literal)";

type EscapeMode = "path" | "host" | "zone";

/** net/url shouldEscape for the three modes used here (a zone is escaped like a host). */
function goShouldEscape(c: number, mode: EscapeMode): boolean {
  const ch = String.fromCharCode(c);
  if (/^[A-Za-z0-9]$/.test(ch)) return false;
  if (mode !== "path" && "!$&'()*+,;=:[]<>\"".includes(ch)) return false;
  if ("-_.~".includes(ch)) return false;
  if ("$&+,/:;=?@".includes(ch)) return mode === "path" ? ch === "?" : true;
  return true;
}

const HEX_DIGIT = /^[0-9a-fA-F]$/;

/** net/url unescape: the decoded bytes, or null where Go returns an error (bad escape, or a character a host may not hold). */
function goUnescape(s: string, mode: EscapeMode): number[] | null {
  const out: number[] = [];
  for (let i = 0; i < s.length; ) {
    const c = s.charCodeAt(i);
    if (c === 0x25) {
      if (i + 2 >= s.length || !HEX_DIGIT.test(s[i + 1]!) || !HEX_DIGIT.test(s[i + 2]!)) return null;
      const v = parseInt(s.slice(i + 1, i + 3), 16);
      const is25 = s.slice(i, i + 3) === "%25";
      if (mode === "host" && v >> 4 < 8 && !is25) return null;
      if (mode === "zone" && !is25 && v !== 0x20 && goShouldEscape(v, "host")) return null;
      out.push(v);
      i += 3;
    } else {
      if (mode !== "path" && c < 0x80 && goShouldEscape(c, mode)) return null;
      out.push(c);
      i++;
    }
  }
  return out;
}

const bytesToString = (b: number[]) => String.fromCharCode(...b);

/** URL.EscapedPath for a path Go accepted: the raw text when it is a valid encoding, else the decoded bytes re-escaped. */
function goEscapedPath(raw: string, decoded: number[]): string {
  let valid = true;
  for (const ch of raw) {
    if ("!$&'()*+,;=:@[]%".includes(ch)) continue;
    if (goShouldEscape(ch.charCodeAt(0), "path")) valid = false;
  }
  if (valid) return raw;
  return decoded.map((c) => (goShouldEscape(c, "path") ? "%" + c.toString(16).toUpperCase().padStart(2, "0") : String.fromCharCode(c))).join("");
}

function ipv4FieldsOk(s: string): boolean {
  let val = 0;
  let pos = 0;
  let digits = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c >= "0" && c <= "9") {
      if (digits === 1 && val === 0) return false;
      val = val * 10 + (c.charCodeAt(0) - 48);
      digits++;
      if (val > 255) return false;
    } else if (c === ".") {
      if (i === 0 || i === s.length - 1 || s[i - 1] === ".") return false;
      if (pos === 3) return false;
      pos++;
      val = 0;
      digits = 0;
    } else {
      return false;
    }
  }
  return pos >= 3;
}

/** netip.ParseAddr accepting an IPv6 address (net/url refuses anything else inside brackets): port of netip.parseIPv6. */
function goParsesAsIPv6(input: string): boolean {
  for (const c of input) {
    if (c === ":") break;
    if (c === "." || c === "%") return false; // an IPv4 address, or a zone with no address
  }
  if (!input.includes(":")) return false;
  let s = input;
  const pct = s.indexOf("%");
  if (pct !== -1) {
    if (s.slice(pct + 1) === "") return false;
    s = s.slice(0, pct);
  }
  let ellipsis = -1;
  if (s.length >= 2 && s[0] === ":" && s[1] === ":") {
    ellipsis = 0;
    s = s.slice(2);
    if (s.length === 0) return true;
  }
  let i = 0;
  while (i < 16) {
    let off = 0;
    let acc = 0;
    for (; off < s.length; off++) {
      const c = s[off]!;
      if (!HEX_DIGIT.test(c)) break;
      acc = acc * 16 + parseInt(c, 16);
      if (off > 3 || acc > 0xffff) return false;
    }
    if (off === 0) return false;
    if (off < s.length && s[off] === ".") {
      if (ellipsis < 0 && i !== 12) return false;
      if (i + 4 > 16) return false;
      if (!ipv4FieldsOk(s)) return false;
      s = "";
      i += 4;
      break;
    }
    i += 2;
    s = s.slice(off);
    if (s.length === 0) break;
    if (s[0] !== ":" || s.length === 1) return false;
    s = s.slice(1);
    if (s[0] === ":") {
      if (ellipsis >= 0) return false;
      ellipsis = i;
      s = s.slice(1);
      if (s.length === 0) break;
    }
  }
  if (s.length !== 0) return false;
  return i < 16 ? ellipsis >= 0 : ellipsis < 0;
}

const validOptionalPort = (p: string) => p === "" || (p[0] === ":" && /^[0-9]*$/.test(p.slice(1)));

/** net/url parseHost (https: strict colons); null where Go returns an error. */
function goParseHost(host: string): string | null {
  const open = host.lastIndexOf("[");
  if (open > 0) return null;
  if (open === 0) {
    const close = host.lastIndexOf("]");
    if (close < 0) return null;
    const colonPort = host.slice(close + 1);
    if (!validOptionalPort(colonPort)) return null;
    const name = host.slice(1, close);
    const zone = name.indexOf("%25");
    let decoded: number[] | null;
    if (zone >= 0) {
      const a = goUnescape(name.slice(0, zone), "host");
      const z = goUnescape(name.slice(zone), "zone");
      decoded = a === null || z === null ? null : [...a, ...z];
    } else {
      decoded = goUnescape(name, "host");
    }
    if (decoded === null || !goParsesAsIPv6(bytesToString(decoded))) return null;
    return `[${bytesToString(decoded)}]${colonPort}`;
  }
  const colon = host.indexOf(":");
  if (colon !== -1 && !validOptionalPort(host.slice(colon))) return null;
  const decoded = goUnescape(host, "host");
  return decoded === null ? null : bytesToString(decoded);
}

/**
 * brandtext.go's url branch: url.Parse, its refusals, the host policy, then u.String(). `value` has already passed the
 * https:// prefix and no-space-or-backslash checks. Every url.Parse failure, a non-empty fragment, user-info and an empty
 * host share the "plain https URL" sentence; a parsed host that fails the DNS policy gets the other one.
 */
function canonicalHttpsUrl(value: string): Normalized {
  const hash = value.indexOf("#");
  if (hash >= 0 && value.length > hash + 1) return refuse(URL_PLAIN_REFUSAL); // a fragment, or one Go cannot unescape
  const noFragment = hash >= 0 ? value.slice(0, hash) : value; // an empty fragment is dropped
  const afterScheme = noFragment.slice("https://".length);
  const q = afterScheme.indexOf("?");
  const query = q >= 0 ? afterScheme.slice(q) : ""; // kept byte for byte: url.Parse never unescapes it
  const beforeQuery = q >= 0 ? afterScheme.slice(0, q) : afterScheme;
  const slash = beforeQuery.indexOf("/");
  const authority = slash >= 0 ? beforeQuery.slice(0, slash) : beforeQuery;
  const rawPath = slash >= 0 ? beforeQuery.slice(slash) : "";
  if (authority.includes("@")) return refuse(URL_PLAIN_REFUSAL);
  const host = goParseHost(authority);
  const path = goUnescape(rawPath, "path");
  if (host === null || path === null || host === "") return refuse(URL_PLAIN_REFUSAL);
  const normalized = normalizeAuthority(host);
  if (normalized === null || host.includes(":") || normalized !== host.toLowerCase()) return refuse(URL_HOST_REFUSAL);
  return ok(`https://${normalized}${goEscapedPath(rawPath, path)}${query}`);
}

const contactErr = (error: string): NormalizedContact => ({ ok: false, error });

/** An empty kind with an empty value is "no contact". The value is ASCII only and shown literally. */
export function normalizeBrandContact(input: ContactInput): NormalizedContact {
  const kind = input.kind.trim().toLowerCase();
  const value = input.value.trim();
  if (kind === "" && value === "") return { ok: true, value: { kind: "", value: "" } };
  if (kind === "" || value === "") return contactErr("needs both a kind and a value");
  if (value.length > BRAND_CONTACT_MAX) return contactErr(`is at most ${BRAND_CONTACT_MAX} characters`);
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 0x20 || c >= 0x7f) return contactErr("must be plain ASCII without control characters (use punycode for a domain)");
  }
  switch (kind) {
    case "phone": {
      const d = canonicalPhone(value);
      if (d === null) {
        return contactErr("a phone number is 5 to 15 digits; spaces, dashes, dots, one balanced pair of parentheses and a leading + are accepted and removed");
      }
      return { ok: true, value: { kind, value: d } };
    }
    case "email": {
      const at = value.lastIndexOf("@");
      if (at < 1 || at > 64) return contactErr("is not a valid email address");
      const local = value.slice(0, at);
      const rawDomain = value.slice(at + 1);
      const domain = rawDomain.toLowerCase();
      if (!EMAIL_LOCAL.test(local)) return contactErr("is not a valid email address");
      if (normalizeAuthority(domain) !== domain || rawDomain.includes(":")) return contactErr("is not a valid email address");
      return { ok: true, value: { kind, value: `${local}@${domain}` } };
    }
    case "url": {
      if (!value.toLowerCase().startsWith("https://")) return contactErr("a URL must start with https://");
      if (/[ \\]/.test(value)) return contactErr("is not a valid URL");
      const r = canonicalHttpsUrl(value);
      if (!r.ok) return contactErr(r.error);
      if (r.value.length > BRAND_CONTACT_MAX) return contactErr(`is at most ${BRAND_CONTACT_MAX} characters`);
      return { ok: true, value: { kind, value: r.value } };
    }
  }
  return contactErr("kind must be phone, email or url");
}

// ---- the whole form --------------------------------------------------------------------------------------

export interface BrandFormValues {
  productName: string;
  accent: string;
  supportText: string;
  contactKind: BrandContactKind | "";
  contactValue: string;
}

export interface BrandFormCheck {
  /** One message per field that would be refused; absent = fine. */
  errors: { productName?: string; accent?: string; supportText?: string; contact?: string };
  /** The canonical value of every field that passed (absent for a refused one). */
  normalized: { productName?: string; accent?: string; supportText?: string; contact?: { kind: BrandContactKind | ""; value: string } };
  /** True when every field passed. */
  valid: boolean;
}

/** Validates every field (the server stops at the first refusal; the form shows them all). */
export function checkBrandForm(v: BrandFormValues): BrandFormCheck {
  const errors: BrandFormCheck["errors"] = {};
  const normalized: BrandFormCheck["normalized"] = {};
  const name = normalizeBrandName(v.productName);
  if (name.ok) normalized.productName = name.value;
  else errors.productName = name.error;
  const accent = normalizeBrandAccent(v.accent);
  if (accent.ok) normalized.accent = accent.value;
  else errors.accent = accent.error;
  const text = normalizeBrandSupportText(v.supportText);
  if (text.ok) normalized.supportText = text.value;
  else errors.supportText = text.error;
  const contact = normalizeBrandContact({ kind: v.contactKind, value: v.contactValue });
  if (contact.ok) normalized.contact = contact.value;
  else errors.contact = contact.error;
  return { errors, normalized, valid: Object.keys(errors).length === 0 };
}

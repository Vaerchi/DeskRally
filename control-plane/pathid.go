package controlplane

// Caller-supplied ids that land in a `uuid` column — the shared parse that keeps a typo'd id from
// reading as a server fault.
//
// Most ids this service routes on (`/machines/{id}`, `/sessions/{id}/end`,
// `/attended-sessions/{id}/…`, `/users/{id}/password-reset`) are database primary keys, and in the
// PostgreSQL schema every one of those columns is a `uuid` (0001, 0013). PostgreSQL rejects a
// malformed literal at cast time with SQLSTATE 22P02 (invalid_text_representation), which reaches
// the handler as an opaque driver error — indistinguishable there from "the database is
// unreachable" — so each handler fell through to its `writeError(500, "could not resolve …")`
// branch. Measured before this existed: all six `{id}` routes answered 500 for `not-a-uuid`.
//
// Three things were wrong with that, and only the first is cosmetic:
//   - GET /machines/not-a-uuid asks for a machine that cannot exist. That is what 404 means; 500
//     asserts the server broke, which is a different claim and a false one.
//   - It is unactionable noise exactly where operators watch. A crawler or a stale console link
//     raises the 5xx rate and pages somebody, and the trail says "could not resolve machine"
//     without a hint that the caller merely mistyped an id.
//   - It is a free oracle for how far a request got: malformed 500s while well-formed-unknown 404s,
//     which separates "reached the database" from "did not" without owning anything.
//
// WHY THIS LIVES IN THE PG STORE, not in the handlers. The first cut of this gated `r.PathValue`
// in each handler and broke 18 existing tests, which was the right answer to a wrong design: ids
// are NOT uuids everywhere. The in-memory stores compare Go strings, and DEV mode plus most of this
// package's tests use symbolic ids ("target", "tenant-1") that a uuid gate rejects —
// canonicalUUIDish already documents the same fact for the audit preimage. A uuid is a constraint of
// the PostgreSQL SCHEMA, so only the pg stores may assume it. Placing the check there also makes it
// total: it applies to every caller of these methods, not only the handler call sites someone
// remembered to guard, and it holds no matter which route reaches them.
//
// WHICH PARSER, and why not the strict one. This uses parsePgUUID — which accepts exactly the
// spellings PostgreSQL's own uuid_in accepts (dashless, brace-wrapped, uppercase, hyphens optional
// at each group boundary) — rather than the canonical-only isUUID in http_backstage_audit.go. The
// asymmetry is the whole argument: accepting a spelling Postgres would reject costs nothing (the
// value reaches the cast and errors exactly as before), while REJECTING a spelling Postgres accepts
// would turn a lookup that resolves a real row today into a not-found — a regression introduced by
// a fix, invisible to every other test here because the console only ever handles canonical ids.
// This check can therefore only convert a 500 into a 404; it can never change an answer that was
// already correct. TestPgMalformedPathIDStillResolvesEveryFormPostgresAccepts pins that direction
// against a live server.
//
// Each caller returns its own not-found sentinel, so handlers need no change: they already map that
// sentinel to 404, and a malformed id is reported identically to a well-formed one naming no row.
// The caller learns nothing about which of the two it was — matching how these handlers already
// refuse to distinguish "does not exist" from "outside your scope".

// namesNoUUIDRow reports whether id CANNOT name a row in a `uuid` column — i.e. PostgreSQL would
// reject it at the cast rather than simply not matching. Callers turn true into their own
// not-found error, which is what the miss would have meant had the value been well-formed.
//
// It is deliberately about the ID PARAMETER ONLY. The alternative — running the query and
// translating SQLSTATE 22P02 in the error path — would also swallow a 22P02 raised by any OTHER
// parameter in the same statement (a malformed tenant id pinned by withTenant, say), turning a real
// server-side misconfiguration into a silent, plausible-looking 404. Checking the one value that is
// attacker-supplied keeps that distinction intact, and costs a round trip less.
func namesNoUUIDRow(id string) bool {
	_, ok := parsePgUUID(id)
	return !ok
}

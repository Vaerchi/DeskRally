module rmt/controlplane

// The control plane is the multi-tenant management API (docs/02-architecture.md ADR-003):
// tenants, users, RBAC scoped to machine/session groups, machines, enrollment, audit.
//
// Routing uses the Go 1.22 net/http ServeMux method+path patterns, so there is no chi/mux
// dependency to vendor. External dependencies:
//   - golang.org/x/crypto — argon2id password hashing for local login (password.go).
//   - github.com/jackc/pgx/v5 — the Postgres driver behind the pgx-backed UserStore /
//     SessionStore / TenantResolver (pgstore.go). The in-memory fakes remain the default
//     test path; the DB seams (TenantBinder, UserStore, SessionStore, TenantResolver) stay
//     interfaces so tests need no live database.
// TOTP and session tokens use the standard library only. The OIDC/Zitadel client is added
// when that integration lands (see the TODO(auth) in http.go).
go 1.26.9

require (
	github.com/coreos/go-oidc/v3 v3.11.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/jackc/pgx/v5 v5.10.0
	golang.org/x/crypto v0.54.0
	golang.org/x/oauth2 v0.23.0
	golang.org/x/sys v0.47.0
	golang.org/x/text v0.41.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
)
